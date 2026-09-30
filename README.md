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
sent, err := client.RequestMobileCode(ctx, phone)
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
`RegisterMobile` validates the code via `/register` and automatically confirms
the consent step required for fresh numbers via `/consent`. A server response of
`blocked` is returned as a `*MobileRegistrationError` without an automatic
retry. No live registration request is made by the library without an explicit
call.

For lower-level control (persisting a pending registration across process
restarts, choosing the method manually, answering CAPTCHA or 2FA challenges),
see `MobileRegistration`, `NewMobileRegistration`, `Snapshot`,
`RestoreMobileRegistration`, `CheckExists`, `RequestCode`, `VerifyCode`,
`ConfirmConsent`, `ConfirmChallenge` and `ConfirmTwoFactorPIN`.

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
