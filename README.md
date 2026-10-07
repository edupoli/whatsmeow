# whatsmeow
[![Go Reference](https://pkg.go.dev/badge/go.mau.fi/whatsmeow.svg)](https://pkg.go.dev/go.mau.fi/whatsmeow)

whatsmeow is a Go library for the WhatsApp web multidevice API.

## Discussion
Matrix room: [#whatsmeow:maunium.net](https://matrix.to/#/#whatsmeow:maunium.net)

For questions about the WhatsApp protocol (like how to send a specific type of
message), you can also use the [WhatsApp protocol Q&A] section on GitHub
discussions.

[WhatsApp protocol Q&A]: https://github.com/tulir/whatsmeow/discussions/categories/whatsapp-protocol-q-a

## Usage
The [godoc](https://pkg.go.dev/go.mau.fi/whatsmeow) includes docs for all methods and event types.
There's also a [simple example](https://pkg.go.dev/go.mau.fi/whatsmeow#example-package) at the top.

### Experimental iOS primary-device registration (SMS)

This is separate from `PairPhone`, which links a Web companion. Register a fresh
`sqlstore.Container` device as a primary device in two steps. First request the
verification code (the channel is chosen automatically from `/exist` — `wa_old`
for numbers that already have a WhatsApp account):

```go
container, err := sqlstore.New(ctx, "sqlite3", "file:yoursqlitefile.db?_foreign_keys=on", nil)
if err != nil { return err }
device := container.NewDevice()
client := whatsmeow.NewClient(device, nil)

// phone is the full international number including the country code,
// without "+" (e.g. "5543991665228"). The country code is detected automatically.
sent, err := client.RequestMobileCode(ctx, phone, "")
if err != nil { return err }
// The code is now dispatched out-of-band via sent.Method (sms, wa_old, ...).
```

The code arrives out-of-band (SMS, voice, wa_old, or email_otp). Once you have
it, complete the registration:

```go
verified, err := client.RegisterMobile(ctx, code)
if err != nil { return err }
_ = verified
return client.Connect()
```

`RequestMobileCode` emits a `*events.MobileCodeRequested` event with the delivery
details, and `RegisterMobile` emits `*events.MobileRegistered` on success.
`RegisterMobile` validates the code via `/register`. A server response of
`blocked` is returned as a `*MobileRegistrationError` without an automatic
retry. No live registration request is made by the library without an explicit
call.

To ask which channels a number has before spending an attempt, use
`ProbeRegistration`. It reads `/exist` only: no code is requested, no attempt is
spent, and no pending registration is left behind, so it is safe to call as often
as you like.

```go
elig, err := client.ProbeRegistration(ctx, phone)
if err != nil { return err }
// elig.Suggestion is a default to try first, or "" when nothing is usable now.
for _, m := range elig.Methods {
    log.Printf("%s supported=%v offered=%v wait=%ds", m.Method, m.Supported, m.Offered, m.WaitSeconds)
}
```

It deliberately does not answer "which channel works", because `/exist` cannot.
Measured against WhatsApp, a number that had never had an account and a number
that already had one returned nearly identical replies: same `reason`, no `type`,
every eligibility flag `0` and every wait `0`. What the reply does carry is
therefore reported as separate facts per channel rather than collapsed into one
available/unavailable flag:

- `Supported` — whether this build can request the channel at all. `flash`,
  `send_sms`, `passkey`, `password`, `acc_tr`, `silent_auth` and
  `silent_auth_ts_43` are reported here as unsupported; the ones the server named
  are also listed in `Unsupported`.
- `Offered` — the server named it in `fallback_methods`/`recommended_method`, or
  its eligibility flag is `1`. This is **not** evidence that it works: a number
  the server listed as `sms`-eligible was answered `no_routes`.
- `WaitSeconds` — a real cooldown. Zero means *unknown*, not ready; the waits only
  turn non-zero once an attempt has been made.
- `HasAccount` — true only when the server made an explicit offer that requires an
  existing account (`wa_old`, `password`, `acc_tr`). `reason=incorrect` and `type`
  are **not** used for this, because both came back the same way for a fresh
  number. When it is true, the carrier channels (`sms`, `voice`) are reported as
  not offered.

A refusal is returned as data, not as an error: `Reason` carries `blocked`,
`temporarily_unavailable` and the rest. An error is returned only when no reply
arrived at all.

To run the attempt itself, `RegisterWithMethod` drives the whole sequence over the
channel you chose. The server answers `/register` with continuations rather than a
final verdict — a code can be accepted and still need a PIN or an age signal — and
this follows them, asking you for each value only when it is actually needed:

```go
verified, err := client.RegisterWithMethod(ctx, phone, "sms", whatsmeow.MobileRegistrationCallbacks{
    Code: func(ctx context.Context, method string) (string, error) {
        return askUser(fmt.Sprintf("enter the %s code", method))
    },
    TwoFactorPIN: func(ctx context.Context) (string, error) {
        return askUser("enter your existing WhatsApp PIN")
    },
    AgeConsent: func(ctx context.Context) (whatsmeow.MobileAgeConsent, error) {
        return whatsmeow.MobileAgeConsent{DOB: "1980-04-12"}, nil
    },
})
```

`Code` is the only callback that is required. Each one is asked at most once, which
is what bounds the loop: a server that keeps asking for a value already supplied is
returned as an error rather than retried. A continuation this build cannot answer
stops the attempt too — a captcha challenge returns `ErrMobileCaptcha`, wrapping the
`*MobileRegistrationError` so the challenge image is still reachable.

If a callback fails, the attempt stays resumable: the code is already on its way, so
`ResumeMobileRegistration(ctx, phone)` picks it up without spending another one.

A `reason=consent` response is returned as an error with the saved attempt
intact, so nothing is spent on a number the caller has no age signal for. The
`pending` field of the server's answer is included in the error text, because it
distinguishes a fresh number awaiting age verification (`pending=app_store_age`)
from other consent states.

To answer that gate, call `RegisterMobileWithConsent` with the account holder's
date of birth. It posts the signal to `/consent` and completes the registration
from that reply — there is no second `/register`, because a successful `/consent`
is itself the registration completing. `MobileAgeConsent` also carries a Google
Play Age Signals verdict (`AgeStatus`, `AgeLowerBound`, `AgeUpperBound`) for a
caller that has a real one; that shape only means something when it came from a
real app-store install.

This has nothing to do with `MOBILE_OS=android`. The extra fields the Android
request adds (`tos_version`, `education_screen_displayed`, `clicked_education_link`)
belong to `/code` and do not clear an age gate.

To reuse the saved attempt after restarting, call `ResumeMobileRegistration(ctx, phone)`
before `RegisterMobile`, without requesting a new code. For an existing 2FA PIN,
use `RegisterMobileTwoFactor`. `DiscardMobileRegistration` explicitly discards a
pending attempt. Lower-level HTTPS operations are available via
`MobileRegistrationClient` and `MobileRegistrationState`.

## Features
Most core features are already present:

* Sending messages to private chats and groups (both text and media)
* Receiving all messages
* Managing groups and receiving group change events
* Joining via invite messages, using and creating invite links
* Sending and receiving typing notifications
* Sending and receiving delivery and read receipts
* Reading and writing app state (contact list, chat pin/mute status, etc)
* Sending and handling retry receipts if message decryption fails
* Sending status messages (experimental, may not work for large contact lists)

Things that are not yet implemented:

* Sending broadcast list messages (this is not supported on WhatsApp web either)
* Calls
