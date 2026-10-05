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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	SendSMSEligible   int      `json:"send_sms_eligible"`
	WaOldEligible     int      `json:"wa_old_eligible"`
	EmailOTPEligible  int      `json:"email_otp_eligible"`
	PasswordEligible  int      `json:"password_eligible"`
	RecommendedMethod []string `json:"recommended_method"`
	FallbackMethods   []string `json:"fallback_methods"`

	// /exist returns the canonical number in "val"
	Val string `json:"val"`

	// /code and /exist timing
	SMSSendWait   int `json:"send_sms_wait"`
	NotifyAfter   int `json:"notify_after"`
	FlashType     int `json:"flash_type"`
	FlashWait     int `json:"flash_wait"`
	NumVisibleDBs int `json:"num_visible_dbs_methods"`

	// /register / /consent fields
	Pending                 string `json:"pending"`
	CC                      string `json:"cc"`
	ISO                     string `json:"iso"`
	LID                     string `json:"lid"`
	EntAccessToken          string `json:"ent_access_token"`
	EntCanonicalFBID        string `json:"ent_canonical_fbid"`
	PasskeyCredential       string `json:"passkey_credential"`
	SecurityCodeSet         bool   `json:"security_code_set"`
	Type                    string `json:"type"`
	NeedChatRestorePNVerify int    `json:"need_chat_restore_pn_verify"`
}

// IsBlocked reports whether the server refused to deliver a code.
func (r *MobileRegistrationResponse) IsBlocked() bool {
	return r != nil && r.CustomBlockScreen.Blocked
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
}

// DefaultMobileProfile returns the profile used when none is set.
// This is the iOS profile: it is the only one with a measured /code -> status=sent
// and a delivered SMS (docs/mobile/STUDY.md sections 1 and 3). The Android form
// answers no_routes.
//
// Model is the marketing name the client announces in its User-Agent, not the
// model identifier. "Device/iPhone14,3" puts a build code where a handset name
// belongs, and the reference sends "Device/iPhone 15 Pro".
func DefaultMobileProfile() MobileProfileConfig {
	return MobileProfileConfig{
		Version:      DefaultMobileVersion,
		OSVersion:    "17.4.1",
		Model:        "iPhone 15 Pro",
		Manufacturer: "Apple",
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
}

// NewMobileRegistrationClient creates a client for the registration flow.
func NewMobileRegistrationClient(state *MobileRegistrationState, p256Priv *ecdsa.PrivateKey) *MobileRegistrationClient {
	return &MobileRegistrationClient{
		State:          state,
		HTTPClient:     &http.Client{Timeout: 45 * time.Second},
		Endpoint:       mobileRegistrationURL,
		P256PrivateKey: p256Priv,
	}
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.Endpoint, "/")+path,
		bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.State.UserAgent())
	req.Header.Set("request_token", uuid.NewString())

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
func (s *MobileRegistrationState) UserAgent() string {
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
	fields := c.State.BuildForm(iosFormOrder, nil)
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

// HasDeliveryMethod reports whether /exist offered at least one way to deliver a code.
func (r *MobileRegistrationResponse) HasDeliveryMethod() bool {
	return r != nil && (r.SendSMSEligible == 1 || r.WaOldEligible == 1 ||
		r.EmailOTPEligible == 1 || r.PasswordEligible == 1 || r.PickMethod() != "")
}

// PickMethod returns the delivery method to use, based on /exist.
// The eligibility flags are authoritative: a number that already has an account
// gets wa_old=1 and send_sms_eligible=0, and asking for sms there is answered
// with no_routes. The recommended_method list is only a fallback because its
// order is not a priority order.
func (r *MobileRegistrationResponse) PickMethod() string {
	if r == nil {
		return ""
	}
	if r.WaOldEligible == 1 {
		return "wa_old"
	}
	if r.SendSMSEligible == 1 {
		return "sms"
	}
	if r.EmailOTPEligible == 1 {
		return "email_otp"
	}
	for _, m := range r.RecommendedMethod {
		if m == "wa_old" || m == "sms" || m == "voice" || m == "email_otp" {
			return m
		}
	}
	return ""
}

// RequestCode calls /code exactly once with the given method.
// Returns the full server response (including retry_after, waits).
func (c *MobileRegistrationClient) RequestCode(ctx context.Context, method string) (*MobileRegistrationResponse, error) {
	if method != "sms" && method != "voice" && method != "email_otp" && method != "wa_old" {
		return nil, errors.New("method must be sms, voice, email_otp, or wa_old")
	}
	fields := c.State.BuildForm(iosCodeFormOrder, map[string]string{"method": method})
	return c.Request(ctx, "/code", fields)
}

// VerifyCode calls /register with the OTP.
func (c *MobileRegistrationClient) VerifyCode(ctx context.Context, code string) (*MobileRegistrationResponse, error) {
	code = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", "")
	if !digits(code) || len(code) < 4 || len(code) > 10 {
		return nil, errors.New("invalid registration code")
	}
	fields := c.State.BuildForm(iosRegisterFormOrder, map[string]string{"code": code})
	return c.Request(ctx, "/register", fields)
}

// ConfirmConsent calls /consent for new accounts requiring age verification.
func (c *MobileRegistrationClient) ConfirmConsent(ctx context.Context) (*MobileRegistrationResponse, error) {
	fields := c.State.BuildRegistrationForm(true, nil)
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
