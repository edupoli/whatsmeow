// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
)

const mobileRegistrationURL = "https://v.whatsapp.net/v2"
const iosRegistrationSecret = "0a1mLfGUIBVrMKF1RdvLI5lkRBvof6vn0fD2QRSM"

var mobileRegistrationPublicKey = [32]byte{0x8e, 0x8c, 0x0f, 0x74, 0xc3, 0xeb, 0xc5, 0xd7, 0xa6, 0x86, 0x5c, 0x6c, 0x3c, 0x84, 0x38, 0x56, 0xb0, 0x61, 0x21, 0xcc, 0xe8, 0xea, 0x77, 0x4d, 0x22, 0xfb, 0x6f, 0x12, 0x25, 0x12, 0x30, 0x2d}

// MobileRegistration contains the stable identifiers and Signal keys used across
// /code, /register, and the subsequent primary-device connection. Keep it across restarts.
type MobileRegistration struct {
	Device          *store.Device
	CountryCode     string
	NationalNumber  string
	Version         string
	OSVersion       string
	Model           string
	PhoneID         string
	DeviceID        [16]byte
	IdentityID      [20]byte
	AccessSessionID [16]byte
	HTTPClient      *http.Client
	Endpoint        string
}

type MobileRegistrationResponse struct {
	Status            string    `json:"status"`
	Reason            string    `json:"reason"`
	Param             string    `json:"param"`
	FailureReason     string    `json:"failure_reason"`
	Login             string    `json:"login"`
	Method            string    `json:"method"`
	Length            int       `json:"length"`
	ImageBlob         string    `json:"image_blob"`
	AudioBlob         string    `json:"audio_blob"`
	SMSWait           int       `json:"sms_wait"`
	VoiceWait         int       `json:"voice_wait"`
	WaOldWait         int       `json:"wa_old_wait"`
	EmailOTPWait      int       `json:"email_otp_wait"`
	RetryAfter        int       `json:"retry_after"`
	CustomBlockScreen *struct{} `json:"custom_block_screen"`
	// Eligibility reported by /exist. The official app selects the delivery
	// method from these instead of always asking for SMS.
	SendSMSEligible   int      `json:"send_sms_eligible"`
	WaOldEligible     int      `json:"wa_old_eligible"`
	EmailOTPEligible  int      `json:"email_otp_eligible"`
	PasswordEligible  int      `json:"password_eligible"`
	RecommendedMethod []string `json:"recommended_method"`
	FallbackMethods   []string `json:"fallback_methods"`
	// Fields from /register and /consent: a fresh number is left pending
	// (reason=consent) until /consent confirms the account.
	Pending              string `json:"pending"`
	CC                   string `json:"cc"`
	ISO                  string `json:"iso"`
	LID                  string `json:"lid"`
	EntAccessToken       string `json:"ent_access_token"`
	EntCanonicalFBID     string `json:"ent_canonical_fbid"`
	PasskeyCredential    string `json:"passkey_credential"`
	SecurityCodeSet      bool   `json:"security_code_set"`
	Type                 string `json:"type"`
	NeedChatRestorePNVerify int `json:"need_chat_restore_pn_verify"`
}

// MobileRegistrationState contains private keys. Persist it as carefully as a
// normal device session, before requesting a code.
type MobileRegistrationState struct {
	CountryCode, NationalNumber, Version, OSVersion, Model, PhoneID string
	DeviceID, AccessSessionID                                       [16]byte
	IdentityID                                                      [20]byte
	NoisePrivate, IdentityPrivate, SignedPreKeyPrivate              [32]byte
	SignedPreKeySignature                                           [64]byte
	SignedPreKeyID, RegistrationID                                  uint32
}

func (r *MobileRegistration) Snapshot() ([]byte, error) {
	if r == nil || r.Device == nil || r.Device.NoiseKey == nil || r.Device.IdentityKey == nil || r.Device.SignedPreKey == nil || r.Device.SignedPreKey.Signature == nil {
		return nil, errors.New("incomplete mobile registration keys")
	}
	return json.Marshal(MobileRegistrationState{
		CountryCode: r.CountryCode, NationalNumber: r.NationalNumber, Version: r.Version,
		OSVersion: r.OSVersion, Model: r.Model, PhoneID: r.PhoneID, DeviceID: r.DeviceID,
		IdentityID: r.IdentityID, AccessSessionID: r.AccessSessionID,
		NoisePrivate: *r.Device.NoiseKey.Priv, IdentityPrivate: *r.Device.IdentityKey.Priv,
		SignedPreKeyPrivate: *r.Device.SignedPreKey.Priv, SignedPreKeyID: r.Device.SignedPreKey.KeyID,
		SignedPreKeySignature: *r.Device.SignedPreKey.Signature, RegistrationID: r.Device.RegistrationID,
	})
}

// RestoreMobileRegistration reuses the exact identity that requested the OTP.
func RestoreMobileRegistration(device *store.Device, snapshot []byte) (*MobileRegistration, error) {
	if device == nil || device.ID != nil {
		return nil, errors.New("expected an unregistered device")
	}
	var state MobileRegistrationState
	if err := json.Unmarshal(snapshot, &state); err != nil {
		return nil, err
	}
	if !digits(state.CountryCode) || len(state.CountryCode) > 3 || !digits(state.NationalNumber) || len(state.CountryCode)+len(state.NationalNumber) < 8 || len(state.CountryCode)+len(state.NationalNumber) > 15 || !validIOSVersion(state.Version) || state.PhoneID == "" {
		return nil, errors.New("invalid mobile registration snapshot")
	}
	device.NoiseKey = keys.NewKeyPairFromPrivateKey(state.NoisePrivate)
	device.IdentityKey = keys.NewKeyPairFromPrivateKey(state.IdentityPrivate)
	device.SignedPreKey = &keys.PreKey{KeyPair: *keys.NewKeyPairFromPrivateKey(state.SignedPreKeyPrivate), KeyID: state.SignedPreKeyID, Signature: &state.SignedPreKeySignature}
	device.RegistrationID = state.RegistrationID
	device.Mobile = true
	return &MobileRegistration{
		Device: device, CountryCode: state.CountryCode, NationalNumber: state.NationalNumber,
		Version: state.Version, OSVersion: state.OSVersion, Model: state.Model, PhoneID: state.PhoneID,
		DeviceID: state.DeviceID, IdentityID: state.IdentityID, AccessSessionID: state.AccessSessionID,
	}, nil
}

type MobileRegistrationError struct {
	Path       string
	HTTPStatus int
	Response   MobileRegistrationResponse
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
	return msg
}

// LookupIOSVersion fetches the public WhatsApp iOS release version, which is
// independent of the WhatsApp Web version used by store.GetWAVersion.
func LookupIOSVersion(ctx context.Context, client *http.Client) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://itunes.apple.com/lookup?bundleId=net.whatsapp.WhatsApp", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("App Store: HTTP %d", resp.StatusCode)
	}
	var result struct {
		Results []struct {
			Version string `json:"version"`
		} `json:"results"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Results) == 0 {
		return "", errors.New("App Store returned no iOS version")
	}
	version := result.Results[0].Version
	if !strings.HasPrefix(version, "2.") {
		version = "2." + version
	}
	if !validIOSVersion(version) {
		return "", fmt.Errorf("invalid iOS version %q", version)
	}
	return version, nil
}

func validIOSVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 4 || parts[0] != "2" {
		return false
	}
	for _, part := range parts {
		if !digits(part) {
			return false
		}
	}
	return true
}

func digits(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// phoneCountryCodes is the exact set of valid ITU country calling codes
// (1-3 digits). Only codes that exist at exactly this length are listed, so a
// number splits unambiguously by longest matching prefix.
var phoneCountryCodes = map[string]struct{}{
	// 1 digit
	"1": {}, "7": {},
	// 2 digits
	"20": {}, "27": {}, "30": {}, "31": {}, "32": {}, "33": {}, "34": {},
	"36": {}, "39": {}, "40": {}, "41": {}, "43": {}, "44": {}, "45": {},
	"46": {}, "47": {}, "48": {}, "49": {}, "51": {}, "52": {}, "53": {},
	"54": {}, "55": {}, "56": {}, "57": {}, "58": {}, "60": {}, "61": {},
	"62": {}, "63": {}, "64": {}, "65": {}, "66": {}, "81": {}, "82": {},
	"84": {}, "86": {}, "90": {}, "91": {}, "92": {}, "93": {}, "94": {},
	"95": {}, "98": {},
	// 3 digits
	"211": {}, "212": {}, "213": {}, "216": {}, "218": {},
	"220": {}, "221": {}, "222": {}, "223": {}, "224": {}, "225": {}, "226": {}, "227": {}, "228": {}, "229": {},
	"230": {}, "231": {}, "232": {}, "233": {}, "234": {}, "235": {}, "236": {}, "237": {}, "238": {}, "239": {},
	"240": {}, "241": {}, "242": {}, "243": {}, "244": {}, "245": {}, "246": {}, "247": {}, "248": {}, "249": {},
	"250": {}, "251": {}, "252": {}, "253": {}, "254": {}, "255": {}, "256": {}, "257": {}, "258": {}, "259": {},
	"260": {}, "261": {}, "262": {}, "263": {}, "264": {}, "265": {}, "266": {}, "267": {}, "268": {}, "269": {},
	"290": {}, "291": {}, "297": {}, "298": {}, "299": {},
	"350": {}, "351": {}, "352": {}, "353": {}, "354": {}, "355": {}, "356": {}, "357": {}, "358": {}, "359": {},
	"370": {}, "371": {}, "372": {}, "373": {}, "374": {}, "375": {}, "376": {}, "377": {}, "378": {}, "379": {},
	"380": {}, "381": {}, "382": {}, "383": {}, "385": {}, "386": {}, "387": {}, "389": {},
	"420": {}, "421": {}, "423": {},
	"500": {}, "501": {}, "502": {}, "503": {}, "504": {}, "505": {}, "506": {}, "507": {}, "508": {}, "509": {},
	"590": {}, "591": {}, "592": {}, "593": {}, "594": {}, "595": {}, "596": {}, "597": {}, "598": {}, "599": {},
	"670": {}, "672": {}, "673": {}, "674": {}, "675": {}, "676": {}, "677": {}, "678": {}, "679": {},
	"680": {}, "681": {}, "682": {}, "683": {}, "685": {}, "686": {}, "687": {}, "688": {}, "689": {},
	"690": {}, "691": {}, "692": {},
	"850": {}, "852": {}, "853": {}, "855": {}, "856": {}, "858": {},
	"870": {}, "880": {}, "881": {}, "886": {}, "888": {},
	"960": {}, "961": {}, "962": {}, "963": {}, "964": {}, "965": {}, "966": {}, "967": {}, "968": {},
	"970": {}, "971": {}, "972": {}, "973": {}, "974": {}, "975": {}, "976": {}, "977": {},
	"992": {}, "993": {}, "994": {}, "995": {}, "996": {}, "998": {},
}

func splitMobileNumber(phone string) (countryCode, nationalNumber string, err error) {
	phone = strings.TrimSpace(phone)
	phone = strings.TrimPrefix(phone, "+")
	phone = notNumbers.ReplaceAllString(phone, "")
	if phone == "" {
		return "", "", errors.New("phone number is required")
	}
	if strings.HasPrefix(phone, "00") {
		phone = phone[2:]
	}
	if len(phone) < 8 || len(phone) > 15 {
		return "", "", fmt.Errorf("invalid phone number length: %q", phone)
	}
	// Try the longest country code first: a 13-digit Brazilian number
	// "5543991665228" splits as cc=55 in=43991665228, not cc=5 in=543991665228.
	for l := 3; l >= 1; l-- {
		cc := phone[:l]
		if _, ok := phoneCountryCodes[cc]; !ok {
			continue
		}
		national := phone[l:]
		if len(national) < 6 || len(national) > 12 {
			continue
		}
		return cc, national, nil
	}
	return "", "", fmt.Errorf("unable to determine country code for %q", phone)
}

// RequestMobileCode starts mobile primary-device registration: it checks the
// number's eligibility via /exist, chooses the best delivery channel
// (wa_old for numbers that already have a WhatsApp account, otherwise sms), and
// requests the verification code via /code. The code is delivered out-of-band
// (SMS, voice, wa_old, or email_otp); the returned response describes the
// delivery method and wait times. The client keeps the session state, so
// RegisterMobile must be called later with the received code.
//
// phone must be the full international number without a leading "+" or "00",
// including the country code (e.g. "5543991665228"). The country code is
// detected automatically from the leading digits.
//
// If /code answers no_routes (the channel has no route for this number, which
// is common for sms on numbers with an existing account), the request is
// retried once with wa_old.
func (cli *Client) RequestMobileCode(ctx context.Context, phone string) (*MobileRegistrationResponse, error) {
	if cli == nil {
		return nil, ErrClientIsNil
	}
	if cli.Store.ID != nil {
		return nil, ErrMobileAlreadyRegistered
	}
	if cli.mobileRegistration != nil {
		return nil, errors.New("mobile registration already started; call RegisterMobile first")
	}
	countryCode, nationalNumber, err := splitMobileNumber(phone)
	if err != nil {
		return nil, err
	}
	version, err := LookupIOSVersion(ctx, cli.preLoginHTTP)
	if err != nil {
		return nil, err
	}
	registration, err := NewMobileRegistration(cli.Store, countryCode, nationalNumber, version)
	if err != nil {
		return nil, err
	}
	registration.HTTPClient = cli.preLoginHTTP
	method := "sms"
	if exist, err := registration.CheckExists(ctx); err == nil {
		if picked := exist.PickMethod(); picked != "" {
			method = picked
		}
	}
	sent, err := registration.RequestCode(ctx, method)
	if err != nil {
		// no_routes means the requested channel has no route for this number.
		// For numbers that already have a WhatsApp account, SMS is usually not
		// eligible while wa_old is; retry once with wa_old when /exist said so.
		var regErr *MobileRegistrationError
		if errors.As(err, &regErr) && regErr.Response.Reason == "no_routes" && method != "wa_old" {
			if sent, err = registration.RequestCode(ctx, "wa_old"); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	cli.mobileRegistration = registration
	cli.dispatchEvent(&events.MobileCodeRequested{
		Phone:      countryCode + nationalNumber,
		Method:     sent.Method,
		Length:     sent.Length,
		RetryAfter: sent.RetryAfter,
	})
	return sent, nil
}

// RegisterMobile completes mobile primary-device registration: it validates the
// code received out-of-band via /register, and automatically confirms the
// consent step required for fresh numbers via /consent. On success the device is
// persisted and the client is ready for Connect(). It must be called after
// RequestMobileCode.
func (cli *Client) RegisterMobile(ctx context.Context, code string) (*MobileRegistrationResponse, error) {
	if cli == nil {
		return nil, ErrClientIsNil
	}
	if cli.mobileRegistration == nil {
		return nil, errors.New("no mobile registration started; call RequestMobileCode first")
	}
	registration := cli.mobileRegistration
	verified, err := registration.VerifyCode(ctx, code)
	if err != nil {
		var regErr *MobileRegistrationError
		if errors.As(err, &regErr) && regErr.Response.Reason == "consent" {
			var consentErr error
			verified, consentErr = registration.ConfirmConsent(ctx)
			if consentErr != nil {
				return nil, consentErr
			}
		} else {
			return nil, err
		}
	}
	cli.mobileRegistration = nil
	cli.dispatchEvent(&events.MobileRegistered{
		Phone: registration.CountryCode + registration.NationalNumber,
		LID:   verified.LID,
	})
	return verified, nil
}

// NewMobileRegistration initializes an iOS primary-device registration using
// existing device keys. The caller must persist this state before requesting SMS.
func NewMobileRegistration(device *store.Device, countryCode, nationalNumber, version string) (*MobileRegistration, error) {
	if device == nil || device.NoiseKey == nil || device.IdentityKey == nil || device.SignedPreKey == nil || device.ID != nil {
		return nil, errors.New("expected an unregistered device with Noise and Signal keys")
	}
	if !digits(countryCode) || len(countryCode) > 3 || !digits(nationalNumber) || len(countryCode)+len(nationalNumber) < 8 || len(countryCode)+len(nationalNumber) > 15 || !validIOSVersion(version) {
		return nil, errors.New("invalid country code, national number, or iOS version")
	}
	r := &MobileRegistration{
		Device: device, CountryCode: countryCode, NationalNumber: nationalNumber,
		Version: version, OSVersion: "17.5.1", Model: "Apple-iPhone_13",
		PhoneID: strings.ToUpper(uuid.NewString()),
	}
	device.Mobile = true
	for _, dest := range [][]byte{r.DeviceID[:], r.IdentityID[:], r.AccessSessionID[:]} {
		if _, err := rand.Read(dest); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *MobileRegistration) userAgent() string {
	return fmt.Sprintf("WhatsApp/%s iOS/%s Device/%s", r.Version, r.OSVersion, r.Model)
}

func (r *MobileRegistration) fields(withToken bool) ([]string, error) {
	if r == nil || r.Device == nil || r.Device.ID != nil || r.Device.NoiseKey == nil || r.Device.IdentityKey == nil || r.Device.SignedPreKey == nil || r.Device.SignedPreKey.Signature == nil || r.Device.SignedPreKey.KeyID >= 1<<24 || !validIOSVersion(r.Version) || !digits(r.CountryCode) || !digits(r.NationalNumber) {
		return nil, errors.New("invalid mobile registration state")
	}
	d := r.Device
	reg := make([]byte, 4)
	binary.BigEndian.PutUint32(reg, d.RegistrationID)
	preKey := make([]byte, 4)
	binary.BigEndian.PutUint32(preKey, d.SignedPreKey.KeyID)
	encode := base64.URLEncoding.EncodeToString
	id := make([]byte, 0, len(r.IdentityID)*3)
	for _, b := range r.IdentityID {
		id = append(id, '%', "0123456789ABCDEF"[b>>4], "0123456789ABCDEF"[b&15])
	}
	fields := []string{
		"cc", r.CountryCode, "in", r.NationalNumber, "rc", "0", "lg", "en", "lc", "US",
		"authkey", encode(d.NoiseKey.Pub[:]), "e_regid", encode(reg), "e_keytype", encode([]byte{ecc.DjbType}),
		"e_ident", encode(d.IdentityKey.Pub[:]), "e_skey_id", encode(preKey[1:]),
		"e_skey_val", encode(d.SignedPreKey.Pub[:]), "e_skey_sig", encode(d.SignedPreKey.Signature[:]),
		"fdid", strings.ToUpper(r.PhoneID), "expid", encode(r.DeviceID[:]), "id", string(id),
		"access_session_id", base64.RawURLEncoding.EncodeToString(r.AccessSessionID[:]),
	}
	if withToken {
		versionHash := md5.Sum([]byte(r.Version))
		tokenHash := md5.Sum([]byte(iosRegistrationSecret + hex.EncodeToString(versionHash[:]) + r.NationalNumber))
		fields = append(fields, "token", hex.EncodeToString(tokenHash[:]))
	}
	return append(fields, "push_token", ""), nil
}

func mobileEncrypt(plain []byte, ephemeral *ecdh.PrivateKey) (string, error) {
	if ephemeral == nil {
		var err error
		ephemeral, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
	}
	server, err := ecdh.X25519().NewPublicKey(mobileRegistrationPublicKey[:])
	if err != nil {
		return "", err
	}
	secret, err := ephemeral.ECDH(server)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, make([]byte, gcm.NonceSize()), plain, nil)
	return base64.RawURLEncoding.EncodeToString(append(ephemeral.PublicKey().Bytes(), ciphertext...)), nil
}

func (r *MobileRegistration) request(ctx context.Context, path string, fields []string) (*MobileRegistrationResponse, error) {
	if len(fields)%2 != 0 {
		return nil, errors.New("unpaired mobile registration fields")
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
	enc, err := mobileEncrypt([]byte(plain.String()), nil)
	if err != nil {
		return nil, err
	}
	endpoint := r.Endpoint
	if endpoint == "" {
		endpoint = mobileRegistrationURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(endpoint, "/")+path, bytes.NewBufferString("ENC="+enc))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", r.userAgent())
	req.Header.Set("request_token", strings.ToUpper(uuid.NewString()))
	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result MobileRegistrationResponse
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("%s: invalid response: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK || result.Reason != "" || (result.Status != "ok" && result.Status != "sent" && result.Status != "verified") {
		return &result, &MobileRegistrationError{Path: path, HTTPStatus: resp.StatusCode, Response: result}
	}
	return &result, nil
}

// CheckExists returns the response from /exist, including reason=incorrect.
// It does not retry or request a verification code.
func (r *MobileRegistration) CheckExists(ctx context.Context) (*MobileRegistrationResponse, error) {
	fields, err := r.fields(false)
	if err != nil {
		return nil, err
	}
	result, err := r.request(ctx, "/exist", fields)
	if rejected, ok := err.(*MobileRegistrationError); ok && rejected.Response.Reason == "incorrect" {
		return result, nil
	}
	return result, err
}

// RequestCode makes exactly one request. A timeout may still mean a code was
// dispatched. method must be one of the server-supported channels: sms, voice,
// email_otp, or wa_old (delivered inside an existing WhatsApp session on the number).
func (r *MobileRegistration) RequestCode(ctx context.Context, method string) (*MobileRegistrationResponse, error) {
	if method != "sms" && method != "voice" && method != "email_otp" && method != "wa_old" {
		return nil, errors.New("registration method must be sms, voice, email_otp or wa_old")
	}
	fields, err := r.fields(true)
	if err != nil {
		return nil, err
	}
	fields = append(fields, "method", method, "sim_mcc", "000", "sim_mnc", "000", "jailbroken", "0", "cellular_strength", "1")
	return r.request(ctx, "/code", fields)
}

// PickMethod returns the delivery channel the server suggests for this
// number based on /exist eligibility, preferring the recommended_method list and
// falling back to an eligible channel. It returns "" if /exist was not called or
// no usable channel is available. The official app reads these fields instead of
// always asking for SMS: for numbers with an existing account, SMS is usually
// not eligible (send_sms_eligible=0) while wa_old is.
func (e *MobileRegistrationResponse) PickMethod() string {
	if e == nil {
		return ""
	}
	for _, m := range e.RecommendedMethod {
		if m == "wa_old" || m == "sms" || m == "voice" {
			return m
		}
	}
	if e.WaOldEligible == 1 {
		return "wa_old"
	}
	if e.SendSMSEligible == 1 {
		return "sms"
	}
	return ""
}

// VerifyCode confirms an existing OTP without requesting another code.
func (r *MobileRegistration) VerifyCode(ctx context.Context, code string) (*MobileRegistrationResponse, error) {
	code = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", "")
	if !digits(code) || len(code) < 4 || len(code) > 10 {
		return nil, errors.New("invalid registration code")
	}
	return r.confirmCode(ctx, "/register", code)
}

// ConfirmConsent confirms the consent/age-verification step the server
// requires for fresh numbers (/register answers reason=consent,
// pending=app_store_age). On success the response carries the account LID and
// enterprise access token, and the device is persisted as registered.
func (r *MobileRegistration) ConfirmConsent(ctx context.Context) (*MobileRegistrationResponse, error) {
	fields, err := r.fields(true)
	if err != nil {
		return nil, err
	}
	result, err := r.request(ctx, "/consent", fields)
	if err == nil && result.Status != "ok" {
		return result, &MobileRegistrationError{Path: "/consent", HTTPStatus: http.StatusOK, Response: *result}
	}
	if err == nil {
		err = r.persistAsRegistered(ctx, result)
	}
	return result, err
}

// persistAsRegistered validates the server's login and saves the mobile device,
// shared by /register and /consent success responses.
func (r *MobileRegistration) persistAsRegistered(ctx context.Context, result *MobileRegistrationResponse) error {
	login := result.Login
	if login == "" {
		login = r.CountryCode + r.NationalNumber
	}
	if !digits(login) || login != r.CountryCode+r.NationalNumber || r.Device.ID != nil {
		return errors.New("invalid mobile registration login")
	}
	jid := types.NewJID(login, types.DefaultUserServer)
	r.Device.ID = &jid
	r.Device.Mobile = true
	r.Device.MobileVersion = r.Version
	r.Device.MobilePhoneID = r.PhoneID
	r.Device.MobileOSVersion = r.OSVersion
	r.Device.MobileModel = r.Model
	if r.Device.PushName == "" {
		r.Device.PushName = "~"
	}
	if r.Device.Container != nil {
		if saveErr := r.Device.Save(ctx); saveErr != nil {
			return fmt.Errorf("registered phone but failed to persist mobile device: %w", saveErr)
		}
	}
	return nil
}

// ConfirmChallenge submits the answer to a server-issued image/audio CAPTCHA.
func (r *MobileRegistration) ConfirmChallenge(ctx context.Context, answer string) (*MobileRegistrationResponse, error) {
	answer = strings.TrimSpace(answer)
	if answer == "" || len(answer) > 32 || strings.ContainsAny(answer, "&=\r\n") {
		return nil, errors.New("invalid challenge answer")
	}
	return r.confirmCode(ctx, "/challenge", answer)
}

// ConfirmTwoFactorPIN submits an account's existing 2FA PIN when requested.
func (r *MobileRegistration) ConfirmTwoFactorPIN(ctx context.Context, pin string) (*MobileRegistrationResponse, error) {
	if !digits(pin) || len(pin) < 4 || len(pin) > 10 {
		return nil, errors.New("invalid two-factor PIN")
	}
	return r.confirmCode(ctx, "/security", pin)
}

func (r *MobileRegistration) confirmCode(ctx context.Context, path, code string) (*MobileRegistrationResponse, error) {
	fields, err := r.fields(true)
	if err != nil {
		return nil, err
	}
	result, err := r.request(ctx, path, append(fields, "code", code))
	if err == nil && result.Status != "verified" && result.Status != "ok" {
		return result, &MobileRegistrationError{Path: path, HTTPStatus: http.StatusOK, Response: *result}
	}
	if err == nil {
		err = r.persistAsRegistered(ctx, result)
	}
	return result, err
}
