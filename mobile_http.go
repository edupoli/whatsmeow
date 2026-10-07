// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// BlockScreen is the custom_block_screen field.
//
// The server answers it either as a bare bool or as an object carrying the block
// text, and both spellings mean the same thing: this registration is not going
// to be delivered. Decoding it as a bool turned an object into a hard parse
// error, which threw away the whole diagnostic — including the block text that
// says why.
type BlockScreen struct {
	Blocked bool
	Body    string
}

func (b *BlockScreen) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	switch trimmed[0] {
	case '{':
		var obj struct {
			Body string `json:"body"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return err
		}
		b.Blocked, b.Body = true, obj.Body
		return nil
	case '"':
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return err
		}
		b.Blocked, b.Body = text != "", text
		return nil
	default:
		var flag bool
		if err := json.Unmarshal(trimmed, &flag); err != nil {
			return err
		}
		b.Blocked = flag
		return nil
	}
}

// MarshalJSON keeps the bool spelling, so a response built locally to feed a
// test server round-trips back as "not blocked".
func (b BlockScreen) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.Blocked)
}

// MobileRegistrationResponse represents the parsed response from WhatsApp registration endpoints.
type MobileRegistrationResponse struct {
	Status            string      `json:"status"`
	Reason            string      `json:"reason"`
	Param             string      `json:"param"`
	FailureReason     string      `json:"failure_reason"`
	Login             string      `json:"login"`
	Method            string      `json:"method"`
	Length            int         `json:"length"`
	ImageBlob         string      `json:"image_blob"`
	AudioBlob         string      `json:"audio_blob"`
	SMSWait           int         `json:"sms_wait"`
	VoiceWait         int         `json:"voice_wait"`
	WaOldWait         int         `json:"wa_old_wait"`
	EmailOTPWait      int         `json:"email_otp_wait"`
	RetryAfter        int         `json:"retry_after"`
	CustomBlockScreen BlockScreen `json:"custom_block_screen"`

	// Undecodable names the fields this build could not read, because the server
	// answered them in a shape this struct does not model. Their JSON is still on
	// MobileRegistrationError.Raw.
	Undecodable []string `json:"-"`

	// /exist eligibility
	//
	// Only some methods carry a flag. sms, voice, flash and passkey do not: they
	// are advertised by appearing in fallback_methods (or recommended_method), and
	// the absence of a flag means the server does not model them that way — not
	// that they are unavailable. send_sms_eligible gates send_sms, which is a
	// distinct method from sms, not another way of spelling it.
	SendSMSEligible        int      `json:"send_sms_eligible"`
	WaOldEligible          int      `json:"wa_old_eligible"`
	EmailOTPEligible       int      `json:"email_otp_eligible"`
	PasswordEligible       int      `json:"password_eligible"`
	AccTrEligible          int      `json:"acc_tr_eligible"`
	SilentAuthEligible     int      `json:"silent_auth_eligible"`
	SilentAuthTs43Eligible int      `json:"silent_auth_ts_43_eligible"`
	RecommendedMethod      []string `json:"recommended_method"`
	FallbackMethods        []string `json:"fallback_methods"`

	// /exist returns the canonical number in "val"
	Val string `json:"val"`

	// /code and /exist timing
	SMSSendWait   int `json:"send_sms_wait"`
	NotifyAfter   int `json:"notify_after"`
	FlashType     int `json:"flash_type"`
	FlashWait     int `json:"flash_wait"`
	NumVisibleDBs int `json:"num_visible_dbs_methods"`

	// /register / /consent fields
	Pending           string `json:"pending"`
	CC                string `json:"cc"`
	ISO               string `json:"iso"`
	LID               string `json:"lid"`
	EntAccessToken    string `json:"ent_access_token"`
	EntCanonicalFBID  string `json:"ent_canonical_fbid"`
	PasskeyCredential string `json:"passkey_credential"`
	SecurityCodeSet   bool   `json:"security_code_set"`
	// Type is "new" or "existing": whether the server found a WhatsApp account on
	// this number. It is the only reliable signal about which delivery channel can
	// work, and the official client reads it as the primary/existing enum
	// (X/C8R.A01, via registration/core/http/KotlinRegistrationBridge.A00).
	Type                    string `json:"type"`
	NeedChatRestorePNVerify int    `json:"need_chat_restore_pn_verify"`
}

// IsBlocked reports whether the server refused to deliver a code.
func (r *MobileRegistrationResponse) IsBlocked() bool {
	return r != nil && r.CustomBlockScreen.Blocked
}

// IsChallenge reports whether the server is asking for a captcha to be solved.
// Only the reasons named in the protocol are checked; this build has never seen
// the server put a challenge in pending, so guessing a value there would risk
// treating an ordinary hold as one.
func (r *MobileRegistrationResponse) IsChallenge() bool {
	if r == nil {
		return false
	}
	switch r.Reason {
	case "challenge", "challenge_email_start":
		return true
	}
	return false
}

// MobileRegistrationError preserves the full server diagnostic.
type MobileRegistrationError struct {
	Path       string
	HTTPStatus int
	Response   MobileRegistrationResponse
	// Raw is the response body exactly as the server sent it.
	Raw string
}

func (e *MobileRegistrationError) Error() string {
	msg := fmt.Sprintf("mobile registration %s: HTTP %d, status=%s, reason=%s", e.Path, e.HTTPStatus, e.Response.Status, e.Response.Reason)
	if e.Response.Param != "" {
		msg += fmt.Sprintf(", param=%s", e.Response.Param)
	}
	if e.Response.Pending != "" {
		msg += fmt.Sprintf(", pending=%s", e.Response.Pending)
	}
	if e.Response.FailureReason != "" {
		msg += fmt.Sprintf(", failure_reason=%s", e.Response.FailureReason)
	}
	if e.Response.RetryAfter > 0 {
		msg += fmt.Sprintf(", retry_after=%ds", e.Response.RetryAfter)
	}
	if e.Response.IsBlocked() {
		msg += ", custom_block_screen"
		if e.Response.CustomBlockScreen.Body != "" {
			msg += fmt.Sprintf("=%q", e.Response.CustomBlockScreen.Body)
		}
	}
	if len(e.Response.Undecodable) > 0 {
		msg += fmt.Sprintf(", undecodable fields: %s", strings.Join(e.Response.Undecodable, ", "))
	}
	return msg
}

// MobileProfileConfig is the device identity presented during registration.
type MobileProfileConfig struct {
	// OS is "ios" or "android". It decides the User-Agent, the form field set,
	// the registration token and the User-Agent extra headers, because the
	// registration server reads the platform out of the User-Agent alone: there
	// is no form field naming it.
	OS string

	Version      string
	OSVersion    string
	Model        string
	Manufacturer string

	// Locale and SIM. Empty means "resolve from the country code"; set them when
	// the SIM in the phone is known, because the country table can only guess one
	// operator per calling code.
	LocaleLanguage string
	LocaleCountry  string
	SIMMCC         string
	SIMMNC         string

	// AndroidTokenMaterial is the key, signing certificates and classes.dex digest
	// read out of a real WhatsApp APK. Required for OS "android"; nil is not a
	// usable default, because the Android token cannot be derived — see
	// AndroidTokenMaterial.
	AndroidTokenMaterial *AndroidTokenMaterial
}

// AndroidTokenMaterial is the token material the Android client signs with.
//
// Unlike iOS, whose token is an MD5 over a published string, the Android token is
// an HMAC over material that only exists inside the APK: a key derived from
// packageName||about_logo.png by PBKDF2-HMAC-SHA1, the v1 signing certificates
// in order, and MD5(classes.dex). Substituting a constant produces a
// well-formed token belonging to nobody, and the server answers bad_token.
type AndroidTokenMaterial struct {
	SecretKey     []byte
	Certificates  [][]byte
	ClassesDexMD5 []byte
}

// AndroidToken computes the Android registration token for a national number.
func (m *AndroidTokenMaterial) AndroidToken(nationalNumber string) (string, error) {
	if m == nil || len(m.SecretKey) == 0 || len(m.Certificates) == 0 || len(m.ClassesDexMD5) != md5.Size {
		return "", errors.New("android token material is missing or incomplete")
	}
	mac := hmac.New(sha1.New, m.SecretKey)
	for _, cert := range m.Certificates {
		mac.Write(cert)
	}
	mac.Write(m.ClassesDexMD5)
	mac.Write([]byte(nationalNumber))
	// Java's URLEncoder over base64 escapes exactly these three, same as
	// encodeURIComponent.
	return url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil))), nil
}

// ParseAndroidTokenMaterial reads the material an APK dump produces.
//
// The three byte fields are base64, not hex. Read as hex they decode to nothing, and
// an empty key produces a well-formed token belonging to nobody — which the server
// answers with bad_token, looking like a refusal from WhatsApp rather than a decoding
// bug.
func ParseAndroidTokenMaterial(data []byte) (*AndroidTokenMaterial, string, error) {
	var file struct {
		SecretKey     string   `json:"secretKey"`
		ClassesDexMD5 string   `json:"classesDexMd5"`
		Certificates  []string `json:"certificates"`
		ApkVersion    string   `json:"apkVersion"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, "", fmt.Errorf("parse: %w", err)
	}
	decode := func(value string) ([]byte, error) {
		return base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	}
	secret, err := decode(file.SecretKey)
	if err != nil {
		return nil, "", fmt.Errorf("secretKey não é base64: %w", err)
	}
	classes, err := decode(file.ClassesDexMD5)
	if err != nil {
		return nil, "", fmt.Errorf("classesDexMd5 não é base64: %w", err)
	}
	material := &AndroidTokenMaterial{SecretKey: secret, ClassesDexMD5: classes}
	for _, cert := range file.Certificates {
		decoded, err := decode(cert)
		if err != nil {
			return nil, "", fmt.Errorf("certificado não é base64: %w", err)
		}
		material.Certificates = append(material.Certificates, decoded)
	}
	// Fail here rather than at the first /code, which would cost an attempt.
	if _, err := material.AndroidToken("0"); err != nil {
		return nil, "", err
	}
	return material, file.ApkVersion, nil
}

// DefaultMobileProfile returns the profile used when none is set.
// This is the iOS profile: it is the only one whose token is derivable, because
// it is an MD5 over a published string rather than material read out of an APK.
//
// Model is the marketing name the client announces in its User-Agent, not the
// model identifier. "Device/iPhone14,3" puts a build code where a handset name
// belongs, and the reference sends "Device/iPhone 15 Pro".
func DefaultMobileProfile() MobileProfileConfig {
	return MobileProfileConfig{
		OS:           "ios",
		Version:      DefaultMobileVersion,
		OSVersion:    "17.4.1",
		Model:        "iPhone 15 Pro",
		Manufacturer: "Apple",
	}
}

// AndroidMobileProfile returns the Android profile. The registration token needs
// AndroidTokenMaterial read out of a real APK; there is no constant that works.
//
// The Android request carries the app-store fields (tos_version,
// education_screen_displayed, clicked_education_link) on /code. None of them is
// what clears an age gate: reason=consent is answered by a separate POST to
// /consent carrying the account holder's date of birth. See MobileAgeConsent.
func AndroidMobileProfile(material *AndroidTokenMaterial) MobileProfileConfig {
	return MobileProfileConfig{
		OS:                   "android",
		Version:              DefaultMobileVersion,
		OSVersion:            "14",
		Model:                "sdk_gphone64_x86_64",
		Manufacturer:         "Google",
		AndroidTokenMaterial: material,
	}
}

// LookupMobileVersion fetches the current public WhatsApp iOS release version and
// normalises it to the four-part form the token expects (26.38.74 -> 2.26.38.74).
func LookupMobileVersion(ctx context.Context, httpClient *http.Client) (string, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://itunes.apple.com/lookup?bundleId=net.whatsapp.WhatsApp", nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("app store: HTTP %d", resp.StatusCode)
	}
	var result struct {
		Results []struct {
			Version string `json:"version"`
		} `json:"results"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Results) == 0 || result.Results[0].Version == "" {
		return "", errors.New("app store returned no version")
	}
	version := result.Results[0].Version
	if !strings.HasPrefix(version, "2.") {
		version = "2." + version
	}
	return version, nil
}

// MobileRegistrationClient handles the HTTPS registration flow.
type MobileRegistrationClient struct {
	State          *MobileRegistrationState
	HTTPClient     *http.Client
	Endpoint       string
	P256PrivateKey *ecdsa.PrivateKey // for signing H
	SignH          bool              // the Android path signs; the measured iOS path does not
	DebugWriter    io.Writer

	// RequestTimeout bounds one registration HTTP call. Zero means no bound.
	//
	// It is applied per request rather than on HTTPClient because the real call
	// sites assign HTTPClient to the Client's preLoginHTTP — the same pointer, so
	// that SetProxyAddress keeps working whether it runs before or after the
	// registration starts — and preLoginHTTP carries no Timeout of its own. A
	// client with no timeout waits forever, so a server that accepts the
	// connection and then goes quiet would wedge the caller indefinitely.
	RequestTimeout time.Duration
}

// DefaultRegistrationRequestTimeout bounds one registration HTTP call.
const DefaultRegistrationRequestTimeout = 45 * time.Second

// NewMobileRegistrationClient creates a client for the registration flow.
func NewMobileRegistrationClient(state *MobileRegistrationState, p256Priv *ecdsa.PrivateKey) *MobileRegistrationClient {
	return &MobileRegistrationClient{
		State:          state,
		HTTPClient:     &http.Client{Timeout: 45 * time.Second},
		Endpoint:       mobileRegistrationURL,
		P256PrivateKey: p256Priv,
		RequestTimeout: DefaultRegistrationRequestTimeout,
	}
}

// SetRequestTimeout overrides the per-request bound, so a caller that knows it
// wants to wait longer can, and a test does not have to sit through 45 seconds.
func (c *MobileRegistrationClient) SetRequestTimeout(d time.Duration) {
	c.RequestTimeout = d
}

// SetEndpoint overrides the registration endpoint (for testing).
func (c *MobileRegistrationClient) SetEndpoint(endpoint string) {
	c.Endpoint = endpoint
}

// SetSignH enables the H signature header. The measured iOS path does not send it;
// only the Android Keystore path does.
func (c *MobileRegistrationClient) SetSignH(v bool) {
	c.SignH = v
}

// SetDebugWriter logs every request path and the raw response body, which is the
// only reliable way to diff our envelope against a captured official-app one.
func (c *MobileRegistrationClient) SetDebugWriter(w io.Writer) {
	c.DebugWriter = w
}

// Request makes a single registration request to the given path.
func (c *MobileRegistrationClient) Request(ctx context.Context, path string, fields []string) (*MobileRegistrationResponse, error) {
	if len(fields)%2 != 0 {
		return nil, errors.New("unpaired fields")
	}
	var plain strings.Builder
	for i := 0; i < len(fields); i += 2 {
		if i > 0 {
			plain.WriteByte('&')
		}
		plain.WriteString(fields[i])
		plain.WriteByte('=')
		plain.WriteString(fields[i+1])
	}

	enc, err := MobileEncrypt([]byte(plain.String()), nil)
	if err != nil {
		return nil, err
	}

	body := "ENC=" + enc
	// The measured iOS flow posts ENC only. H= carries the Android Keystore
	// signature and is not part of the path that returned status=sent.
	if c.SignH {
		h, err := SignENC(enc, c.P256PrivateKey)
		if err != nil {
			return nil, err
		}
		body += "&H=" + h
	}
	return c.rawRequest(ctx, path, body)
}

// rawRequest posts an already-built body to path and decodes the response.
func (c *MobileRegistrationClient) rawRequest(ctx context.Context, path, body string) (*MobileRegistrationResponse, error) {
	// Bound the call without touching HTTPClient, which is shared with the rest of
	// the client and carries no timeout of its own. An earlier deadline on ctx wins.
	if c.RequestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.RequestTimeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.Endpoint, "/")+path,
		bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.State.UserAgent())
	req.Header.Set("request_token", uuid.NewString())
	if c.State.isAndroid() {
		// Observed on a live native Android registration; the native iOS client
		// omits all three.
		req.Header.Set("Accept", "text/json")
		req.Header.Set("WaMsysRequest", "1")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var raw json.RawMessage
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&raw); err != nil {
		return nil, fmt.Errorf("%s: invalid response: %w", path, err)
	}
	if c.DebugWriter != nil {
		fmt.Fprintf(c.DebugWriter, "mobile %s -> HTTP %d %s\n", path, resp.StatusCode, raw)
	}

	result, err := parseRegistrationResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	if resp.StatusCode != http.StatusOK || result.Reason != "" ||
		(result.Status != "ok" && result.Status != "sent" && result.Status != "verified") {
		return result, &MobileRegistrationError{
			Path: path, HTTPStatus: resp.StatusCode, Response: *result, Raw: string(raw),
		}
	}
	return result, nil
}

// parseRegistrationResponse handles both response shapes: /exist answers with a
// one-element JSON array, the other endpoints answer with a bare object.
func parseRegistrationResponse(raw []byte) (*MobileRegistrationResponse, error) {
	body := raw
	if len(raw) > 0 && raw[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, err
		}
		if len(arr) == 0 {
			return nil, errors.New("empty response array")
		}
		body = arr[0]
	}
	result := &MobileRegistrationResponse{}
	if err := decodeTolerant(body, result); err != nil {
		return nil, err
	}
	return result, nil
}

// decodeTolerant decodes raw into out one field at a time.
//
// A field whose JSON shape this build does not model is recorded in
// Undecodable instead of failing the whole decode. One unrecognised field used
// to cost the caller the entire diagnostic — a block screen arrived as an
// opaque "cannot unmarshal" error, with the block text that explains it lost.
func decodeTolerant(raw []byte, out *MobileRegistrationResponse) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	value := reflect.ValueOf(out).Elem()
	structType := value.Type()
	byName := make(map[string]int, structType.NumField())
	for i := 0; i < structType.NumField(); i++ {
		name, _, _ := strings.Cut(structType.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			byName[name] = i
		}
	}
	var skipped []string
	for name, encoded := range fields {
		field, ok := byName[name]
		if !ok {
			continue // not modelled here; the raw body on the error keeps it
		}
		if err := json.Unmarshal(encoded, value.Field(field).Addr().Interface()); err != nil {
			skipped = append(skipped, name)
		}
	}
	sort.Strings(skipped)
	out.Undecodable = skipped
	return nil
}

// UserAgent returns the client user agent for registration.
//
// The server reads the platform out of this string: there is no form field naming
// it, so a User-Agent that names no known platform is refused with
// bad_param param=platform on every endpoint.
func (s *MobileRegistrationState) UserAgent() string {
	if s.isAndroid() {
		return fmt.Sprintf("WhatsApp/%s Android/%s Device/%s-%s", s.Version, s.OSVersion, s.Manufacturer, s.Model)
	}
	return fmt.Sprintf("WhatsApp/%s iOS/%s Device/%s", s.Version, s.OSVersion, s.Model)
}

// SendFunnel posts one of the onboarding funnel requests the official app makes
// before /exist: pre_pn_client_log → reg_onboard_abprop → client_log.
// These carry no H= signature and no attestation, and they are what the server
// expects to have seen before a registration is considered.
func (c *MobileRegistrationClient) SendFunnel(ctx context.Context, path string, fields []string) (*MobileRegistrationResponse, error) {
	if len(fields)%2 != 0 {
		return nil, errors.New("unpaired fields")
	}
	var plain strings.Builder
	for i := 0; i < len(fields); i += 2 {
		if i > 0 {
			plain.WriteByte('&')
		}
		plain.WriteString(fields[i])
		plain.WriteByte('=')
		plain.WriteString(fields[i+1])
	}
	enc, err := MobileEncrypt([]byte(plain.String()), nil)
	if err != nil {
		return nil, err
	}
	return c.rawRequest(ctx, path, "ENC="+enc)
}

// RunOnboardingFunnel replays the funnel in the order the official app uses it.
func (c *MobileRegistrationClient) RunOnboardingFunnel(ctx context.Context) error {
	phone := c.State.CountryCode + c.State.NationalNumber
	steps := []struct {
		path   string
		fields []string
	}{
		{"/pre_pn_client_log", []string{
			"cc", c.State.CountryCode, "in", c.State.NationalNumber,
			"rc", "0", "lg", "en", "lc", "US", "login", phone,
		}},
		{"/reg_onboard_abprop", []string{
			"cc", c.State.CountryCode, "in", c.State.NationalNumber,
			"rc", "0", "lg", "en", "lc", "US", "login", phone,
			"vname", c.State.Version,
		}},
		{"/client_log", []string{
			"cc", c.State.CountryCode, "in", c.State.NationalNumber,
			"rc", "0", "lg", "en", "lc", "US", "login", phone,
			"vname", c.State.Version, "os_version", c.State.OSVersion,
			"manufacture", c.State.Manufacturer, "model", c.State.Model,
			"network_radio_type", "4", "simnum", "0", "fdid", strings.ToUpper(c.State.PhoneID),
		}},
	}
	for _, step := range steps {
		if _, err := c.SendFunnel(ctx, step.path, step.fields); err != nil {
			var regErr *MobileRegistrationError
			if errors.As(err, &regErr) {
				continue // the funnel is best-effort; a rejection must not abort registration
			}
			return fmt.Errorf("%s: %w", step.path, err)
		}
	}
	return nil
}

// CheckExists calls /exist and returns the full response.
// The endpoint answers status=fail reason=incorrect for an identity the server has
// not seen before, which is the normal response for a first-time registration. It
// still carries the eligibility flags that PickMethod reads.
func (c *MobileRegistrationClient) CheckExists(ctx context.Context) (*MobileRegistrationResponse, error) {
	fields, err := c.State.BuildForm(c.State.existOrder(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Request(ctx, "/exist", fields)
	if err != nil {
		var regErr *MobileRegistrationError
		if errors.As(err, &regErr) && regErr.HTTPStatus == http.StatusOK && resp.Status == "fail" && resp.Reason == "incorrect" {
			return resp, nil // expected for new keys
		}
		return resp, err
	}
	return resp, nil
}

// serverMethods is every delivery method the server names, including the ones
// this build cannot request. Kept separate from supportedRegistrationMethods
// because "the server offered a route" and "we can use it" are different
// questions, and the answer to the first must not be mistaken for the second.
var serverMethods = []string{
	"sms", "voice", "wa_old", "email_otp", "flash", "send_sms",
	"passkey", "password", "acc_tr", "silent_auth", "silent_auth_ts_43",
}

// supportedRegistrationMethods are the methods RequestCode can actually send, in
// the order the official client prefers them.
//
// The order is the official client's — flash, sms, voice, wa_old, acc_tr,
// send_sms, email_otp — with the entries this build cannot request removed. flash
// goes on that list first and is dropped here for two reasons: the route exists
// on Android only, and the code is the tail of the calling number rather than
// something the caller types.
var supportedRegistrationMethods = []string{"sms", "voice", "wa_old", "email_otp"}

// hasAccount reports whether the server offered something that only makes sense
// on a number that already has an account: wa_old delivers the code into the
// WhatsApp app on it, and the rest re-authenticate that account.
//
// Only an explicit offer counts. Two things that look like signals are not, both
// measured against WhatsApp:
//
//   - reason. It came back "incorrect" for a number that had never had WhatsApp,
//     identical to one that had. It means the identity check found no new account,
//     not that an account exists. Gating sms on it would have hidden the primary
//     channel from every fresh number.
//   - type. It is documented as new/existing, but it was absent from the reply
//     entirely, for both kinds of number.
//
// So for a number with no explicit offer the carrier channels stay on. If it turns
// out to have an account, /code says no_routes and that attempt is recorded; the
// reply cannot be trusted to have predicted it.
func (r *MobileRegistrationResponse) hasAccount() bool {
	return r.WaOldEligible == 1 || r.PasswordEligible == 1 ||
		r.AccTrEligible == 1 || r.SecurityCodeSet
}

// advertises reports whether the server named this method at all, in either list.
// The server sends fallback_methods; recommended_method is kept because older
// builds answered with that name and a client that stops reading it loses the
// offer entirely.
func (r *MobileRegistrationResponse) advertises(method string) bool {
	for _, m := range r.FallbackMethods {
		if m == method {
			return true
		}
	}
	for _, m := range r.RecommendedMethod {
		if m == method {
			return true
		}
	}
	return false
}

// eligibilityFlag returns the server's own eligibility flag for a method, or 0.
// Zero is ambiguous on purpose: it is both "the server said no" and "the server
// does not model this method with a flag", since sms, voice, flash and passkey
// carry none at all.
func (r *MobileRegistrationResponse) eligibilityFlag(method string) int {
	switch method {
	case "wa_old":
		return r.WaOldEligible
	case "email_otp":
		return r.EmailOTPEligible
	case "send_sms":
		return r.SendSMSEligible
	case "password":
		return r.PasswordEligible
	case "acc_tr":
		return r.AccTrEligible
	case "silent_auth":
		return r.SilentAuthEligible
	case "silent_auth_ts_43":
		return r.SilentAuthTs43Eligible
	}
	return 0
}

// methodState reports whether the server offered this method and how long it has
// to wait.
//
// Two signals that used to be conflated into one:
//
//   - Some methods carry no *_eligible flag. sms, voice, flash and passkey are
//     advertised only by appearing in a method list. Treating a missing flag as
//     "ineligible" made this return "" for numbers that do have a route.
//   - The rest carry a flag, where 1 is an offer. send_sms_eligible gates
//     send_sms, a different method from sms — it is not another spelling of it,
//     and reading it as sms requested a channel the server had not offered.
//
// The cooldown is the matching *_wait. A method with a positive wait is not
// pickable: asking for it spends an attempt and is answered with too_recent.
func (r *MobileRegistrationResponse) methodState(method string) (advertised bool, cooldownSeconds int) {
	return r.advertises(method) || r.eligibilityFlag(method) == 1, r.cooldownSeconds(method)
}

// cooldownSeconds returns the server-reported cooldown for a method, in seconds.
// Zero means unknown rather than ready: the waits only turn non-zero once an
// attempt has been made, so /exist cannot report one that is already cooling down.
func (r *MobileRegistrationResponse) cooldownSeconds(method string) int {
	switch method {
	case "sms":
		return r.SMSWait
	case "voice":
		return r.VoiceWait
	case "flash":
		return r.FlashWait
	case "send_sms":
		return r.SMSSendWait
	case "wa_old":
		return r.WaOldWait
	case "email_otp":
		return r.EmailOTPWait
	}
	return 0
}

// MethodEligibility is what is actually known about one delivery channel.
//
// The fields are deliberately not collapsed into one available/unavailable flag.
// /exist cannot answer that question: a number with no account and a number that
// already has one came back nearly identical when measured, so any availability
// claim for a fresh number would be a guess. These are the raw signals plus what
// this build can do about them.
type MethodEligibility struct {
	Method string
	// Supported is whether this build can request the channel at all.
	Supported bool
	// Offered is what the server said, uninterpreted: the channel is named in
	// fallback_methods or recommended_method, or its eligibility flag is 1. It does
	// not mean the channel works. A number the server listed as sms-eligible was
	// answered no_routes.
	Offered bool
	// Eligibility is the server's flag. Zero covers both "no" and "not modelled";
	// sms, voice, flash and passkey carry none.
	Eligibility int
	// WaitSeconds is the server-reported cooldown. Zero means unknown, not ready:
	// only an attempt produces a non-zero wait.
	WaitSeconds int
}

// RegistrationEligibility is the answer to "can this number register, and how",
// read from /exist without asking for a code. It costs no attempt and leaves no
// pending registration behind.
type RegistrationEligibility struct {
	Login  string
	Status string
	// Reason is the server's verdict on the identity check. "incorrect" is the
	// normal answer for a number with no account, and is not a failure.
	Reason string
	// Type is documented as new/existing, but it came back absent from the reply
	// for both numbers measured, so it is reported and not acted on.
	Type string

	// HasAccount is the one thing the reply can settle, and only through an
	// explicit offer: wa_old has a WhatsApp app to deliver the code into. False
	// means no offer was made, not that there is no account.
	HasAccount bool

	// Methods covers every channel the server knows, in the official client's
	// preference order, including the ones this build cannot request.
	Methods []MethodEligibility
	// Unsupported lists the channels the server named that this build cannot send.
	Unsupported []string
	// Suggestion is the channel to try first, or "" when none is usable right now.
	// It is a default, not a decision: /exist cannot rule a channel in or out, so
	// the choice belongs to whoever asked.
	Suggestion string

	// Response is the parsed reply, kept so a caller can log the evidence behind
	// the summary above without having to re-read it.
	Response *MobileRegistrationResponse
}

// Eligibility summarises a reply for a caller that wants one row per channel.
func (r *MobileRegistrationResponse) Eligibility() *RegistrationEligibility {
	if r == nil {
		return nil
	}
	out := &RegistrationEligibility{
		Login:       r.Login,
		Status:      r.Status,
		Reason:      r.Reason,
		Type:        r.Type,
		HasAccount:  r.hasAccount(),
		Unsupported: r.UnsupportedMethods(),
		Suggestion:  r.PickMethod(),
		Response:    r,
	}
	for _, m := range serverMethods {
		advertised, cooldown := r.methodState(m)
		out.Methods = append(out.Methods, MethodEligibility{
			Method:      m,
			Supported:   SupportedMethod(m),
			Offered:     advertised,
			Eligibility: r.eligibilityFlag(m),
			WaitSeconds: cooldown,
		})
	}
	return out
}

// HasDeliveryMethod reports whether there is at least one channel worth offering.
//
// It answers that question the same way PickMethod does: a channel the server named
// and this build can send, or — when the server named nothing and no account was
// proven — sms, which is where the official flow starts for a number it has not seen.
// Silence from /exist is not evidence against a channel.
func (r *MobileRegistrationResponse) HasDeliveryMethod() bool {
	if r == nil {
		return false
	}
	if r.PickMethod() != "" {
		return true
	}
	// A channel named but not implemented still means the server offered a route,
	// which is what a caller asking this needs to know.
	for _, m := range serverMethods {
		if advertised, _ := r.methodState(m); advertised {
			return true
		}
	}
	return false
}

// PickMethod returns the delivery channel worth trying first, or "" when nothing
// qualifies. It is a suggestion, not a decision: /exist cannot rule a channel in or
// out, so the caller is free to pick any supported channel.
//
// Preference is the official client's — sms, voice, wa_old, email_otp — restricted to
// channels the server actually named and that are not cooling down. An explicit
// wa_old offer outranks that order, since the server volunteered it for a number that
// already has an account.
//
// With nothing named and no proven account, it returns sms: that is the channel the
// official flow starts on for a number the server has not seen, and /exist staying
// silent is not evidence against it.
//
// A wait of zero means unknown, not available. The waits only turn non-zero after an
// attempt, so /exist cannot report a channel that is already cooling down. Only /code
// settles that, and it costs an attempt.
func (r *MobileRegistrationResponse) PickMethod() string {
	if r == nil {
		return ""
	}
	// A refusal carries no channel information at all.
	if r.Reason != "" && r.Reason != "incorrect" {
		return ""
	}
	if r.WaOldEligible == 1 && r.WaOldWait <= 0 {
		return "wa_old"
	}
	for _, m := range supportedRegistrationMethods {
		advertised, cooldown := r.methodState(m)
		if advertised && cooldown <= 0 {
			return m
		}
	}
	// Nothing named: fall back to the official first channel rather than refusing,
	// unless an account was proven, in which case the carrier routes are likely
	// closed and wa_old is the only sensible default.
	if !r.hasAccount() && r.SMSWait <= 0 {
		return "sms"
	}
	return ""
}

// SupportedMethod reports whether this build can request the named method.
func SupportedMethod(method string) bool {
	for _, m := range supportedRegistrationMethods {
		if m == method {
			return true
		}
	}
	return false
}

// UnsupportedMethods returns the methods the server named that this build cannot
// request, in the server's own order. Reported separately from the ineligible
// ones so a caller can tell "this number cannot use it" from "we cannot do it".
func (r *MobileRegistrationResponse) UnsupportedMethods() []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, m := range serverMethods {
		if SupportedMethod(m) {
			continue
		}
		if advertised, _ := r.methodState(m); advertised {
			out = append(out, m)
		}
	}
	return out
}

// RequestCode calls /code exactly once with the given method.
// Returns the full server response (including retry_after, waits).
func (c *MobileRegistrationClient) RequestCode(ctx context.Context, method string) (*MobileRegistrationResponse, error) {
	if method != "sms" && method != "voice" && method != "email_otp" && method != "wa_old" {
		return nil, errors.New("method must be sms, voice, email_otp, or wa_old")
	}
	fields, err := c.State.BuildForm(c.State.codeOrder(), map[string]string{"method": method})
	if err != nil {
		return nil, err
	}
	return c.Request(ctx, "/code", fields)
}

// VerifyCode calls /register with the OTP.
func (c *MobileRegistrationClient) VerifyCode(ctx context.Context, code string) (*MobileRegistrationResponse, error) {
	code = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", "")
	if !digits(code) || len(code) < 4 || len(code) > 10 {
		return nil, errors.New("invalid registration code")
	}
	fields, err := c.State.BuildForm(c.State.registerOrder(), map[string]string{"code": code})
	if err != nil {
		return nil, err
	}
	return c.Request(ctx, "/register", fields)
}

// MobileAgeConsent is the age signal /v2/consent carries.
//
// When /register answers reason=consent the code was accepted and the account was
// found, but the server will not complete the registration until it sees an age
// signal. That signal goes to a *separate* endpoint, /v2/consent — it is not a
// field on /register and it is not something the Android profile carries instead.
//
// There are two shapes, told apart by the context value, and they are not
// interchangeable:
//
//	DOB    context=dob — the account holder's own date of birth. This is the
//	       designed self-declaration: the official app's age screen collects exactly
//	       this, and it is the one a server-side client can actually answer.
//	Play   context=app_store_age — the verdict from Google Play's Age Signals API
//	       for a real app-store install. It only means something if it came from
//	       one; there is nothing here to synthesise.
//
// Fields read out of the official Android build (com.whatsapp 2.26.38.72):
// X/C28754Cis.A0g builds the request, KotlinRegistrationBridge.A06 puts context
// and dob on it and merges the rest as additional params,
// WaConsentRepository$sendAppStoreAgeSignal$2 names the app_store_age fields, and
// X/C245415l.A00 formats the date.
type MobileAgeConsent struct {
	// DOB is the account holder's date of birth. YYYY-MM-DD, DD/MM/YYYY, YYYYMMDD
	// or a bare YYYY; normalised to YYYY-MM-DD, or to the year alone when only the
	// year is known — the official formatter leaves a partial date partial.
	DOB string

	// The Play Age Signals verdict, for a caller that has a real one. Setting any
	// of these selects context=app_store_age in place of the DOB.
	AgeLowerBound    int
	AgeUpperBound    int
	AgeStatus        string
	InstallID        string
	LastApprovalDate string
}

// context is the value that tells the server which of the two shapes this is.
func (a MobileAgeConsent) context() string {
	if a.DOB == "" && (a.AgeStatus != "" || a.AgeLowerBound > 0 || a.AgeUpperBound > 0) {
		return "app_store_age"
	}
	return "dob"
}

// pctEncodeString mirrors X/C6C.A00, the encoder every additional-params value
// passes through on its way to the form. Unreserved characters go untouched and
// everything else becomes %XX — which is why "NOT SHARED" would not survive raw.
func pctEncodeString(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			out.WriteByte(c)
			continue
		}
		fmt.Fprintf(&out, "%%%02X", c)
	}
	return out.String()
}

// normalizeMobileDOB accepts the spellings a person is likely to type and returns
// the one the endpoint takes. An unreadable date is an error rather than a guess:
// a wrong date here is a wrong claim about the account holder.
func normalizeMobileDOB(dob string) (string, error) {
	s := strings.TrimSpace(dob)
	if s == "" {
		return "", nil
	}
	digitsOnly := func(s string) bool {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == '/' })
	if len(parts) == 3 {
		switch {
		case len(parts[0]) == 4 && len(parts[1]) <= 2 && len(parts[2]) <= 2:
			// YYYY-MM-DD
			return fmt.Sprintf("%04s-%02s-%02s", parts[0], parts[1], parts[2]), nil
		case len(parts[2]) == 4 && len(parts[0]) <= 2 && len(parts[1]) <= 2:
			// DD/MM/YYYY, as written in Brazil and most of Europe
			return fmt.Sprintf("%04s-%02s-%02s", parts[2], parts[1], parts[0]), nil
		}
	}
	if len(s) == 8 && digitsOnly(s) {
		return s[0:4] + "-" + s[4:6] + "-" + s[6:8], nil
	}
	if len(s) == 4 && digitsOnly(s) {
		return s, nil
	}
	return "", fmt.Errorf("date of birth not understood: %s — use YYYY-MM-DD, DD/MM/YYYY, YYYYMMDD or YYYY", s)
}

// isMobileConsentGate reports the "held for an age signal" answer, in every
// spelling the server uses. Reasons come from X/C8R, the pending values from
// X/C28017CNd and X/CV1.
func isMobileConsentGate(resp *MobileRegistrationResponse) bool {
	if resp == nil {
		return false
	}
	switch resp.Reason {
	case "consent", "consent_minor", "consent_parent_linking_ineligible",
		"consent_parent_linking_already_registered":
		return true
	}
	switch resp.Pending {
	case "dob", "app_store_age", "youth_consent", "parent_verification":
		return true
	}
	return false
}

// form renders the consent signal. dob and context go on directly; everything
// else travels as an additional param, which is percent-encoded on the way out.
func (a MobileAgeConsent) form() (map[string]string, error) {
	out := map[string]string{"context": a.context()}

	dob, err := normalizeMobileDOB(a.DOB)
	if err != nil {
		return nil, err
	}
	if dob != "" {
		out["dob"] = dob
	}

	if a.context() == "app_store_age" {
		if a.AgeLowerBound > 0 {
			out["age_lower_bound"] = pctEncodeString(fmt.Sprintf("%d", a.AgeLowerBound))
		}
		if a.AgeUpperBound > 0 {
			out["age_upper_bound"] = pctEncodeString(fmt.Sprintf("%d", a.AgeUpperBound))
		}
		if a.AgeStatus != "" {
			out["android_age_status"] = pctEncodeString(a.AgeStatus)
		} else {
			// No verdict: the official client sends age_error rather than an empty
			// android_age_status, defaulting to "unknown_error".
			out["age_error"] = pctEncodeString("unknown_error")
		}
		if a.InstallID != "" {
			out["android_install_id"] = pctEncodeString(a.InstallID)
		}
		if a.LastApprovalDate != "" {
			out["android_last_approval_date"] = pctEncodeString(a.LastApprovalDate)
		}
	}
	return out, nil
}

// ConfirmConsent calls /consent with the given age signal.
//
// context is the field the server validates first: a form without it is refused
// with bad_param param=context. That is why this takes an age signal rather than
// posting the bare registration form.
func (c *MobileRegistrationClient) ConfirmConsent(ctx context.Context, consent MobileAgeConsent) (*MobileRegistrationResponse, error) {
	extra, err := consent.form()
	if err != nil {
		return nil, err
	}
	if c.DebugWriter != nil {
		// The age signal, and nothing else: the rest of the form is the device
		// identity and does not belong in a log. Worth printing because the shape
		// of this request is what the server answers with bad_param param=context,
		// and an attempt on a real number is not a cheap way to find out.
		keys := make([]string, 0, len(extra))
		for k := range extra {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var shown strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&shown, "%s=%s ", k, extra[k])
		}
		fmt.Fprintf(c.DebugWriter, "mobile /consent age signal: %s\n", strings.TrimSpace(shown.String()))
	}
	// includeToken stays true: the official client puts no token on this request,
	// but a form carrying one has been accepted as far as the server's own
	// param=context complaint, so this is the smaller delta for a real number.
	fields := c.State.BuildRegistrationForm(true, extra)
	resp, err := c.Request(ctx, "/consent", fields)
	if err == nil && resp.Status != "ok" {
		return resp, &MobileRegistrationError{Path: "/consent", HTTPStatus: http.StatusOK, Response: *resp}
	}
	return resp, err
}

// ConfirmTwoFactorPIN calls /register with the PIN (security_code stage).
func (c *MobileRegistrationClient) ConfirmTwoFactorPIN(ctx context.Context, pin string) (*MobileRegistrationResponse, error) {
	if !digits(pin) || len(pin) < 4 || len(pin) > 10 {
		return nil, errors.New("invalid two-factor PIN")
	}
	fields := c.State.BuildRegistrationForm(true, map[string]string{
		"code":          "",
		"security_code": pin,
		"method":        "twofac_pin",
		"context":       "twofac_dynamic",
	})
	return c.Request(ctx, "/register", fields)
}
