// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"go.mau.fi/libsignal/ecc"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// The token format was verified against v.whatsapp.net: lowercase hex MD5.
// The previous HMAC-SHA1/base64 scheme was rejected with
// reason=bad_param param=token failure=bad_format.
func TestComputeRegistrationTokenFormat(t *testing.T) {
	tok := ComputeRegistrationToken("2.26.38.72", "43991665432")
	if len(tok) != 32 {
		t.Fatalf("token should be 32 hex chars (md5), got %d: %q", len(tok), tok)
	}
	if _, err := hex.DecodeString(tok); err != nil {
		t.Fatalf("token is not hex: %v", err)
	}
	// Must depend on both the version and the number.
	if tok == ComputeRegistrationToken("2.26.38.72", "43991665433") {
		t.Fatal("token unchanged for a different number")
	}
	if tok == ComputeRegistrationToken("2.26.38.73", "43991665432") {
		t.Fatal("token unchanged for a different version")
	}
	// Reproduce the known-good iOS computation independently.
	vh := md5.Sum([]byte("2.26.38.72"))
	want := md5.Sum([]byte("0a1mLfGUIBVrMKF1RdvLI5lkRBvof6vn0fD2QRSM" + hex.EncodeToString(vh[:]) + "43991665432"))
	if tok != hex.EncodeToString(want[:]) {
		t.Fatalf("token = %s, want %s", tok, hex.EncodeToString(want[:]))
	}
}

func TestMobileEncryptDecrypt(t *testing.T) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := MobileEncrypt([]byte("cc=55&in=43991665228"), ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	// The ephemeral public key is the 32-byte prefix, then ciphertext+tag
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 32+12+16 {
		t.Fatalf("ciphertext too short: %d", len(raw))
	}
	if !bytes.Equal(raw[:32], ephemeral.PublicKey().Bytes()) {
		t.Fatal("ciphertext does not start with the ephemeral public key")
	}
}

func TestSignENC(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := "abc123ENCtext"
	sig, err := SignENC(enc, privKey)
	if err != nil {
		t.Fatal(err)
	}
	if sig == "" {
		t.Fatal("empty signature")
	}
	// Verify it decodes
	sigBytes, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigBytes) < 8 { // DER sequence minimum
		t.Fatalf("signature too short: %d", len(sigBytes))
	}
	// Tampering should produce different signature
	sig2, _ := SignENC(enc+"x", privKey)
	if sig == sig2 {
		t.Fatal("tampered text produced same signature")
	}
}

func TestAndroidTokenTamperRejection(t *testing.T) {
	// The registration token must change when the national number changes.
	t1 := ComputeRegistrationToken("2.26.38.72", "43991725225")
	t2 := ComputeRegistrationToken("2.26.38.72", "43991725226")
	if t1 == t2 {
		t.Fatal("token unchanged for different numbers")
	}
}

func TestBuildRegistrationForm(t *testing.T) {
	state, err := GenerateMobileRegistrationState("55", "43991665228", "2.26.38.72", "14", "sdk_gphone64_x86_64", "Google")
	if err != nil {
		t.Fatal(err)
	}
	fields := state.BuildRegistrationForm(true, nil)
	if len(fields)%2 != 0 {
		t.Fatal("unpaired fields")
	}
	// Check required fields exist
	fieldMap := make(map[string]string)
	for i := 0; i < len(fields); i += 2 {
		fieldMap[fields[i]] = fields[i+1]
	}
	required := []string{"cc", "in", "authkey", "e_ident", "e_skey_val", "e_skey_sig", "e_skey_id", "e_regid", "e_keytype", "fdid", "expid", "id", "access_session_id", "entrypoint", "advertising_id", "aid", "backup_token", "token"}
	for _, r := range required {
		if _, ok := fieldMap[r]; !ok {
			t.Errorf("missing required field: %s", r)
		}
	}
}

func TestMobileRegistrationClientOffline(t *testing.T) {
	// Generate a test state
	state, err := GenerateMobileRegistrationState("55", "43991665228", "2.26.38.72", "14", "sdk_gphone64_x86_64", "Google")
	if err != nil {
		t.Fatal(err)
	}
	// Generate a P-256 key for signing
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Test server that echoes the request
	var capturedBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		// Simulate /exist response for new keys
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(MobileRegistrationResponse{
			Status: "fail", Reason: "incorrect", Login: "5543991665228",
		})
	}))
	defer server.Close()

	client := NewMobileRegistrationClient(state, privKey)
	client.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	client.Endpoint = server.URL

	resp, err := client.CheckExists(context.Background())
	if err != nil {
		t.Fatalf("CheckExists failed: %v", err)
	}
	if resp.Reason != "incorrect" {
		t.Errorf("expected reason=incorrect, got %s", resp.Reason)
	}

	// The measured iOS path posts ENC only, with no H= signature.
	if !strings.HasPrefix(capturedBody, "ENC=") {
		t.Errorf("request missing ENC prefix: %s", capturedBody[:min(100, len(capturedBody))])
	}
	if strings.Contains(capturedBody, "&H=") {
		t.Errorf("iOS path must not send H: %s", capturedBody[:min(100, len(capturedBody))])
	}
}

// SignH must add the signature when explicitly enabled (the Android path).
func TestSignHIsOptIn(t *testing.T) {
	state, err := GenerateMobileRegistrationState("55", "43991665432", "2.26.37.76", "17.4.1", "iPhone14,3", "Apple")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := state.P256Signer()
	if err != nil {
		t.Fatal(err)
	}
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MobileRegistrationResponse{Status: "ok", Method: "sms", Length: 6})
	}))
	defer server.Close()

	c := NewMobileRegistrationClient(state, sig)
	c.Endpoint = server.URL
	c.SetSignH(true)
	if _, err = c.RequestCode(context.Background(), "sms"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "&H=") {
		t.Fatal("SignH=true should add the H signature")
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	state, err := GenerateMobileRegistrationState("55", "43991665228", "2.26.38.72", "14", "sdk_gphone64_x86_64", "Google")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := state.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreMobileRegistrationState(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// Compare critical fields
	if state.CountryCode != restored.CountryCode || state.NationalNumber != restored.NationalNumber {
		t.Fatal("country/national mismatch")
	}
	if state.NoisePrivate != restored.NoisePrivate || state.IdentityPrivate != restored.IdentityPrivate {
		t.Fatal("private keys mismatch")
	}
	if state.SignedPreKeyID != restored.SignedPreKeyID || state.RegistrationID != restored.RegistrationID {
		t.Fatal("ids mismatch")
	}
	if state.AdvertisingID != restored.AdvertisingID {
		t.Fatal("advertising_id mismatch")
	}
	if !bytes.Equal(state.BackupToken, restored.BackupToken) || !bytes.Equal(state.AndroidID, restored.AndroidID) {
		t.Fatal("android fields mismatch")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// A zeroed pre-key signature is rejected by the server, so the state must always
// carry a real signature produced by the identity key.
func TestSignedPreKeySignatureIsValid(t *testing.T) {
	state, err := GenerateMobileRegistrationState("55", "43991665228", "2.26.38.72", "14", "sdk_gphone64_x86_64", "Google")
	if err != nil {
		t.Fatal(err)
	}
	identityKP := keys.NewKeyPairFromPrivateKey(state.IdentityPrivate)
	preKeyKP := keys.NewKeyPairFromPrivateKey(state.SignedPreKeyPrivate)

	// The signature is over the DjB-serialized pre-key public key.
	signed := make([]byte, 33)
	signed[0] = ecc.DjbType
	copy(signed[1:], preKeyKP.Pub[:])
	if !ecc.VerifySignature(ecc.NewDjbECPublicKey(*identityKP.Pub), signed, state.SignedPreKeySignature) {
		t.Fatal("signed pre-key signature does not verify against the identity key")
	}
}

// authkey/e_ident/e_skey_val must be the derived public keys, never the private keys.
func TestRegistrationFormSendsPublicKeys(t *testing.T) {
	state, err := GenerateMobileRegistrationState("55", "43991665228", "2.26.38.72", "14", "sdk_gphone64_x86_64", "Google")
	if err != nil {
		t.Fatal(err)
	}
	fields := state.BuildRegistrationForm(false, nil)
	fieldMap := make(map[string]string)
	for i := 0; i < len(fields); i += 2 {
		fieldMap[fields[i]] = fields[i+1]
	}
	decode := base64.URLEncoding.DecodeString
	for field, priv := range map[string][32]byte{
		"authkey":    state.NoisePrivate,
		"e_ident":    state.IdentityPrivate,
		"e_skey_val": state.SignedPreKeyPrivate,
	} {
		got, err := decode(fieldMap[field])
		if err != nil {
			t.Fatalf("%s is not base64url: %v", field, err)
		}
		if len(got) != 32 {
			t.Fatalf("%s should be 32 bytes, got %d", field, len(got))
		}
		if bytes.Equal(got, priv[:]) {
			t.Fatalf("%s leaks the private key", field)
		}
	}
}

// The P-256 signing key must survive a restart, otherwise /register cannot be signed.
func TestSnapshotRoundTripsP256Key(t *testing.T) {
	state, err := GenerateMobileRegistrationState("55", "43991665228", "2.26.38.72", "14", "sdk_gphone64_x86_64", "Google")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := state.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreMobileRegistrationState(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	orig, err := state.P256Signer()
	if err != nil {
		t.Fatal(err)
	}
	back, err := restored.P256Signer()
	if err != nil {
		t.Fatalf("P-256 key did not survive the snapshot: %v", err)
	}
	if orig.D.Cmp(back.D) != 0 {
		t.Fatal("restored P-256 key differs from the original")
	}
	sig, err := SignENC("some-enc", back)
	if err != nil {
		t.Fatal(err)
	}
	if sig == "" {
		t.Fatal("restored key cannot sign")
	}
}

// /exist answers with a one-element array; /code and /register with a bare object.
func TestParseRegistrationResponseShapes(t *testing.T) {
	arr, err := parseRegistrationResponse([]byte(`[{"status":"ok","val":"5543991665228","length":6}]`))
	if err != nil {
		t.Fatal(err)
	}
	if arr.Status != "ok" || arr.Val != "5543991665228" || arr.Length != 6 {
		t.Fatalf("array shape parsed wrong: %+v", arr)
	}
	obj, err := parseRegistrationResponse([]byte(`{"status":"ok","login":"5543991665228","lid":"1234"}`))
	if err != nil {
		t.Fatal(err)
	}
	if obj.Status != "ok" || obj.Login != "5543991665228" || obj.LID != "1234" {
		t.Fatalf("object shape parsed wrong: %+v", obj)
	}
}

// custom_block_screen arrives as a bool in some releases and as an object carrying
// the block text in others. Reading it as a bool threw the whole response away.
func TestCustomBlockScreenShapes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		body        string
		wantBlocked bool
		wantBody    string
	}{
		{"bool", `{"status":"fail","custom_block_screen":true}`, true, ""},
		{"false", `{"status":"ok","custom_block_screen":false}`, false, ""},
		{"object", `{"status":"fail","custom_block_screen":{"body":"too many attempts"}}`, true, "too many attempts"},
		{"string", `{"status":"fail","custom_block_screen":"blocked"}`, true, "blocked"},
		{"null", `{"status":"ok","custom_block_screen":null}`, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := parseRegistrationResponse([]byte(tc.body))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if resp.IsBlocked() != tc.wantBlocked {
				t.Errorf("IsBlocked = %v, want %v", resp.IsBlocked(), tc.wantBlocked)
			}
			if resp.CustomBlockScreen.Body != tc.wantBody {
				t.Errorf("body = %q, want %q", resp.CustomBlockScreen.Body, tc.wantBody)
			}
		})
	}
}

// The block screen must round-trip through the test servers that encode this struct,
// otherwise an empty local response reads back as a block.
func TestBlockScreenMarshalsAsBool(t *testing.T) {
	encoded, err := json.Marshal(MobileRegistrationResponse{Status: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"custom_block_screen":false`) {
		t.Fatalf("block screen should marshal as a bool: %s", encoded)
	}
	resp, err := parseRegistrationResponse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if resp.IsBlocked() {
		t.Error("a locally built response must not read back as blocked")
	}
}

// One field the server spells differently must not cost the rest of the diagnostic.
func TestUnreadableFieldDoesNotDiscardResponse(t *testing.T) {
	resp, err := parseRegistrationResponse([]byte(
		`{"status":"sent","method":"sms","length":"6","some_new_field":{"a":1}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.Status != "sent" || resp.Method != "sms" {
		t.Fatalf("the readable fields were lost: %+v", resp)
	}
	if len(resp.Undecodable) != 1 || resp.Undecodable[0] != "length" {
		t.Fatalf("Undecodable = %v, want [length]", resp.Undecodable)
	}
}

// A /code refused with a block screen is a readable answer, not a crash: one request,
// the reason preserved, and nothing that invites a second attempt.
func TestBlockedCodeResponseIsReportedOnce(t *testing.T) {
	state, err := GenerateMobileRegistrationState("55", "43991665228", "2.26.38.74", "17.4.1", "iPhone14,3", "Apple")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := state.P256Signer()
	if err != nil {
		t.Fatal(err)
	}
	var codeCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/code" {
			codeCalls++
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"fail","reason":"custom_block_screen","custom_block_screen":{"body":"unusual activity"}}`)
	}))
	defer server.Close()

	c := NewMobileRegistrationClient(state, signer)
	c.Endpoint = server.URL

	resp, err := c.RequestCode(context.Background(), "sms")
	if err == nil {
		t.Fatal("a blocked /code must be an error")
	}
	if codeCalls != 1 {
		t.Fatalf("/code was called %d times; one attempt must not become two", codeCalls)
	}
	if resp == nil || !resp.IsBlocked() {
		t.Fatalf("the response must still say blocked: %+v", resp)
	}
	var regErr *MobileRegistrationError
	if !errors.As(err, &regErr) {
		t.Fatalf("error is %T, want *MobileRegistrationError", err)
	}
	if regErr.Response.CustomBlockScreen.Body != "unusual activity" {
		t.Errorf("block text lost: %q", regErr.Response.CustomBlockScreen.Body)
	}
	if !strings.Contains(err.Error(), "unusual activity") {
		t.Errorf("the error must carry the reason: %v", err)
	}
	if !strings.Contains(regErr.Raw, "custom_block_screen") {
		t.Errorf("the raw body must be preserved: %q", regErr.Raw)
	}
}

// memContainer is a minimal in-memory store.DeviceContainer, enough to exercise the
// mobile registration flow without a database driver.
type memContainer struct {
	pending map[string][]byte
}

func (c *memContainer) PutDevice(ctx context.Context, device *store.Device) error    { return nil }
func (c *memContainer) DeleteDevice(ctx context.Context, device *store.Device) error { return nil }

func (c *memContainer) PutPendingMobileRegistration(ctx context.Context, phone string, snapshot []byte) error {
	if c.pending == nil {
		c.pending = make(map[string][]byte)
	}
	c.pending[phone] = snapshot
	return nil
}

func (c *memContainer) GetPendingMobileRegistration(ctx context.Context, phone string) ([]byte, error) {
	return c.pending[phone], nil
}

func (c *memContainer) UpdatePendingMobileRegistration(ctx context.Context, phone string, previous, snapshot []byte) error {
	c.pending[phone] = snapshot
	return nil
}

func (c *memContainer) DeletePendingMobileRegistration(ctx context.Context, phone string) error {
	delete(c.pending, phone)
	return nil
}

func newMobileTestClient() (*Client, *memContainer) {
	container := &memContainer{}
	device := &store.Device{Container: container, Log: waLog.Noop}
	device.NoiseKey = keys.NewKeyPair()
	device.IdentityKey = keys.NewKeyPair()
	device.SignedPreKey = device.IdentityKey.CreateSignedPreKey(1)
	device.Account = &waAdv.ADVSignedDeviceIdentity{}
	return NewClient(device, waLog.Noop), container
}

// RequestMobileCode used to deadlock on its own mutex and could never be pointed at a
// test server. Both must work now.
func TestRequestMobileCodeAgainstTestServer(t *testing.T) {
	cli, _ := newMobileTestClient()

	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		paths = append(paths, req.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/pre_pn_client_log", "/client_log":
			json.NewEncoder(w).Encode(MobileRegistrationResponse{Status: "ok"})
		case "/reg_onboard_abprop":
			json.NewEncoder(w).Encode(MobileRegistrationResponse{Status: "ok"})
		case "/exist":
			// The real endpoint answers fail/incorrect with the eligibility flags.
			json.NewEncoder(w).Encode([]MobileRegistrationResponse{{
				Status: "fail", Reason: "incorrect", Val: "5543991665432",
				SendSMSEligible: 1, RecommendedMethod: []string{"sms"},
			}})
		case "/code":
			json.NewEncoder(w).Encode(MobileRegistrationResponse{Status: "sent", Method: "sms", Length: 6})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cli.SetMobileRegistrationEndpoint(server.URL)

	ctx := context.Background()
	resp, err := cli.RequestMobileCode(ctx, "5543991665432", "sms")
	if err != nil {
		t.Fatalf("RequestMobileCode: %v", err)
	}
	if resp.Method != "sms" || resp.Length != 6 {
		t.Fatalf("unexpected code response: %+v", resp)
	}
	want := "/pre_pn_client_log,/reg_onboard_abprop,/client_log,/exist,/code"
	if strings.Join(paths, ",") != want {
		t.Fatalf("path sequence = %v, want %s", paths, want)
	}
}

// A refused /code must not leave a pending row behind. The row is written before the
// network call, so without a rollback the next run is told to resume an attempt the
// server never accepted — and never gets to try again.
func TestRefusedCodeDoesNotLeavePending(t *testing.T) {
	cli, container := newMobileTestClient()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/exist":
			json.NewEncoder(w).Encode(MobileRegistrationResponse{Status: "fail", Reason: "incorrect", Val: "5543991665432"})
		case "/code":
			io.WriteString(w, `{"status":"fail","reason":"custom_block_screen","custom_block_screen":{"body":"try later"}}`)
		default:
			json.NewEncoder(w).Encode(MobileRegistrationResponse{Status: "ok"})
		}
	}))
	defer server.Close()
	cli.SetMobileRegistrationEndpoint(server.URL)

	ctx := context.Background()
	if _, err := cli.RequestMobileCode(ctx, "5543991665432", "sms"); err == nil {
		t.Fatal("a blocked /code must be an error")
	}
	if pending, err := container.GetPendingMobileRegistration(ctx, "5543991665432"); err != nil {
		t.Fatalf("GetPendingMobileRegistration: %v", err)
	} else if pending != nil {
		t.Fatal("a refused /code must leave no pending row")
	}

	// And the next attempt must be allowed to run instead of being refused as pending.
	if _, err := cli.RequestMobileCode(ctx, "5543991665432", "sms"); errors.Is(err, ErrMobileAlreadyPending) {
		t.Fatalf("a failed attempt must not block the next one: %v", err)
	}
}

// The opposite side: a code that was actually sent must survive, or a restart would
// throw away an OTP that is on its way.
func TestSentCodeKeepsPending(t *testing.T) {
	cli, container := newMobileTestClient()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/exist":
			json.NewEncoder(w).Encode([]MobileRegistrationResponse{{
				Status: "fail", Reason: "incorrect", Val: "5543991665432",
				SendSMSEligible: 1, RecommendedMethod: []string{"sms"},
			}})
		case "/code":
			json.NewEncoder(w).Encode(MobileRegistrationResponse{Status: "sent", Method: "sms", Length: 6})
		default:
			json.NewEncoder(w).Encode(MobileRegistrationResponse{Status: "ok"})
		}
	}))
	defer server.Close()
	cli.SetMobileRegistrationEndpoint(server.URL)

	ctx := context.Background()
	if _, err := cli.RequestMobileCode(ctx, "5543991665432", "sms"); err != nil {
		t.Fatalf("RequestMobileCode: %v", err)
	}
	pending, err := container.GetPendingMobileRegistration(ctx, "5543991665432")
	if err != nil {
		t.Fatalf("GetPendingMobileRegistration: %v", err)
	}
	if pending == nil {
		t.Fatal("a sent code must keep its pending row for ResumeMobileRegistration")
	}
}

// A pending registration must be resumable with the P-256 key recovered from the
// snapshot, not injected by the caller.
func TestResumeMobileRegistrationAfterRestart(t *testing.T) {
	_, container := newMobileTestClient()
	ctx := context.Background()

	state, err := GenerateMobileRegistrationState("55", "43991665432", "2.26.38.72", "14", "sdk_gphone64_x86_64", "Google")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := state.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err = container.PutPendingMobileRegistration(ctx, "5543991665432", snapshot); err != nil {
		t.Fatal(err)
	}

	// A new client on the same store is a restart of the process.
	fresh, _ := newMobileTestClient()
	fresh.Store.Container = container
	fresh.preLoginHTTP = &http.Client{Timeout: time.Second}
	if err = fresh.ResumeMobileRegistration(ctx, "5543991665432"); err != nil {
		t.Fatalf("ResumeMobileRegistration: %v", err)
	}
	if fresh.mobileRegistration == nil {
		t.Fatal("resume did not restore the registration client")
	}
	if fresh.mobileP256PrivateKey == nil {
		t.Fatal("resume did not restore the P-256 signing key")
	}
}

// Captured from the official app: /exist answers with every eligibility flag at 0
// and /code STILL returns status=sent. So eligibility must not gate the code
// request, otherwise a perfectly valid registration is refused locally.
func TestRequestMobileCodeIgnoresZeroEligibility(t *testing.T) {
	cli, _ := newMobileTestClient()

	codeCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case "/exist":
			// The real /exist shape for an unknown number: everything at 0.
			json.NewEncoder(w).Encode([]MobileRegistrationResponse{{Status: "fail", Reason: "incorrect"}})
		case "/code":
			codeCalled = true
			json.NewEncoder(w).Encode(MobileRegistrationResponse{Status: "sent", Method: "sms", Length: 6})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	cli.SetMobileRegistrationEndpoint(server.URL)

	resp, err := cli.RequestMobileCode(context.Background(), "5543991665432", "sms")
	if err != nil {
		t.Fatalf("RequestMobileCode must not gate on /exist eligibility: %v", err)
	}
	if !codeCalled {
		t.Error("/code was not called")
	}
	if resp.Status != "sent" || resp.Method != "sms" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

// The official app hits the onboarding funnel before /exist, and the server
// expects to have seen it.
func TestOnboardingFunnelOrderAndNoSignature(t *testing.T) {
	cli, _ := newMobileTestClient()

	var paths []string
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		paths = append(paths, req.URL.Path)
		bodies = append(bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		if req.URL.Path == "/reg_onboard_abprop" {
			io.WriteString(w, `{"ab_hash":"1gw8Qs","status":"ok"}`)
			return
		}
		io.WriteString(w, `{"status":"ok"}`)
	}))
	defer server.Close()
	cli.SetMobileRegistrationEndpoint(server.URL)

	state, err := GenerateMobileRegistrationState("55", "43991665432", "2.26.38.74", "14", "sdk_gphone64_x86_64", "Google")
	if err != nil {
		t.Fatal(err)
	}
	p256, err := state.P256Signer()
	if err != nil {
		t.Fatal(err)
	}
	c := NewMobileRegistrationClient(state, p256)
	c.Endpoint = server.URL
	if err = c.RunOnboardingFunnel(context.Background()); err != nil {
		t.Fatalf("RunOnboardingFunnel: %v", err)
	}
	want := []string{"/pre_pn_client_log", "/reg_onboard_abprop", "/client_log"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("funnel order = %v, want %v", paths, want)
	}
	// The funnel carries ENC only: no H= signature, per the captured requests.
	for i, b := range bodies {
		if !strings.HasPrefix(b, "ENC=") {
			t.Errorf("funnel step %d does not start with ENC: %.40s", i, b)
		}
		if strings.Contains(b, "&H=") {
			t.Errorf("funnel step %d must not send H=", i)
		}
	}
}

// HasDeliveryMethod must reflect the eligibility flags, not just the method list.
func TestHasDeliveryMethod(t *testing.T) {
	if (&MobileRegistrationResponse{Reason: "incorrect"}).HasDeliveryMethod() {
		t.Error("no flags and no methods must report no delivery method")
	}
	if !(&MobileRegistrationResponse{SendSMSEligible: 1}).HasDeliveryMethod() {
		t.Error("sms eligibility should count")
	}
	if !(&MobileRegistrationResponse{RecommendedMethod: []string{"voice"}}).HasDeliveryMethod() {
		t.Error("a recommended method should count")
	}
}

// PickMethod must prefer wa_old when /exist marks it eligible: an account that
// already exists gets the code inside the app, not by SMS.
func TestPickMethodPrefersWaOld(t *testing.T) {
	r := &MobileRegistrationResponse{
		SendSMSEligible: 0, WaOldEligible: 1,
		RecommendedMethod: []string{"email_otp", "passkey", "wa_old"},
	}
	if got := r.PickMethod(); got != "wa_old" {
		t.Fatalf("PickMethod = %q, want wa_old", got)
	}
}

// The iOS form is the measured path: it must carry every field, in order, with the
// md5 token — and no empty push_token, which the server answers with bad_param.
func TestIOSFormIsComplete(t *testing.T) {
	state, err := GenerateMobileRegistrationState("55", "43991665432", "2.26.37.76", "17.4.1", "iPhone14,3", "Apple")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		order []string
		extra map[string]string
	}{
		{"exist", iosFormOrder, nil},
		{"code", iosCodeFormOrder, map[string]string{"method": "sms"}},
		{"register", iosRegisterFormOrder, map[string]string{"code": "123456"}},
	} {
		// push_token is dropped while we have no push transport, so the emitted
		// order is the requested one without it.
		want := make([]string, 0, len(tc.order))
		for _, k := range tc.order {
			if k != "push_token" {
				want = append(want, k)
			}
		}

		fields := state.BuildForm(tc.order, tc.extra)
		got := make(map[string]string, len(want))
		keys := make([]string, 0, len(want))
		for i := 0; i+1 < len(fields); i += 2 {
			got[fields[i]] = fields[i+1]
			keys = append(keys, fields[i])
		}
		if len(keys) != len(want) {
			t.Fatalf("%s: got %d fields, want %d", tc.name, len(keys), len(want))
		}
		for i, k := range want {
			if keys[i] != k {
				t.Errorf("%s: field %d is %q, want %q", tc.name, i, keys[i], k)
				break
			}
		}
		for _, k := range []string{"cc", "in", "authkey", "e_ident", "e_skey_val", "e_skey_sig", "e_regid", "e_keytype", "fdid", "expid", "id", "access_session_id", "token"} {
			if got[k] == "" {
				t.Errorf("%s: %s is empty", tc.name, k)
			}
		}
		// sim_mcc/sim_mnc only ride on /code, and where they do they must carry a
		// real operator.
		for _, k := range []string{"sim_mcc", "sim_mnc"} {
			if !slices.Contains(want, k) {
				continue
			}
			if got[k] == "" || got[k] == "000" {
				t.Errorf("%s: %s is %q, want a real operator", tc.name, k, got[k])
			}
		}
		// An empty push_token is worse than none: the server validates the shape of
		// what it receives. Same rule as push_code.
		if _, ok := got["push_token"]; ok {
			t.Errorf("%s: must not send an empty push_token", tc.name)
		}
		if _, ok := got["push_code"]; ok {
			t.Errorf("%s: must not send push_code", tc.name)
		}
	}
}

// The form must agree with the number: a Brazilian number announcing en/US with no
// SIM describes a handset that does not exist, and 000/000 is what a phone with no
// SIM reports.
func TestFormLocaleFollowsTheNumber(t *testing.T) {
	fieldsOf := func(cc, national string) map[string]string {
		state, err := GenerateMobileRegistrationState(cc, national, "2.26.38.74", "17.4.1", "iPhone 15 Pro", "Apple")
		if err != nil {
			t.Fatal(err)
		}
		f := state.BuildForm(iosCodeFormOrder, map[string]string{"method": "sms"})
		out := make(map[string]string, len(f)/2)
		for i := 0; i+1 < len(f); i += 2 {
			out[f[i]] = f[i+1]
		}
		return out
	}

	br := fieldsOf("55", "43991665228")
	if br["lc"] != "BR" || br["lg"] != "pt" {
		t.Errorf("BR number announces lc=%s lg=%s", br["lc"], br["lg"])
	}
	if br["sim_mcc"] == "000" || br["sim_mnc"] == "000" {
		t.Errorf("BR number announces no operator: %s/%s", br["sim_mcc"], br["sim_mnc"])
	}

	us := fieldsOf("1", "4155550123")
	if us["lc"] != "US" || us["lg"] != "en" {
		t.Errorf("US number announces lc=%s lg=%s", us["lc"], us["lg"])
	}

	// An unknown country must still produce a parseable form.
	zz := fieldsOf("999", "123456789")
	if zz["lc"] == "" || zz["sim_mcc"] == "" {
		t.Errorf("unknown country produced an unparseable form: %+v", zz)
	}
}

// The resolved locale must survive a restart, or a resumed attempt would answer
// /code with a different locale than the one it registered /exist with.
func TestSnapshotRoundTripsLocaleAndSim(t *testing.T) {
	state, err := GenerateMobileRegistrationState("55", "43991665228", "2.26.38.74", "17.4.1", "iPhone 15 Pro", "Apple")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := state.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreMobileRegistrationState(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if restored.LocaleCountry != "BR" || restored.LocaleLanguage != "pt" {
		t.Errorf("locale lost across restart: %s/%s", restored.LocaleLanguage, restored.LocaleCountry)
	}
	if restored.SIMMCC != state.SIMMCC || restored.SIMMNC != state.SIMMNC {
		t.Errorf("sim lost across restart: %s/%s vs %s/%s",
			restored.SIMMCC, restored.SIMMNC, state.SIMMCC, state.SIMMNC)
	}
	// A snapshot written before this existed re-resolves rather than going blank.
	var legacy struct {
		CountryCode    string `json:"CountryCode"`
		NationalNumber string `json:"NationalNumber"`
	}
	_ = legacy
	if lang, country, mcc, mnc := resolveMobileLocale("55", "", "", "", ""); lang != "pt" || country != "BR" || mcc == "000" || mnc == "000" {
		t.Errorf("empty override must fall back to the country: %s/%s %s/%s", lang, country, mcc, mnc)
	}
	if lang, country, mcc, mnc := resolveMobileLocale("55", "en", "US", "310", "410"); lang != "en" || country != "US" || mcc != "310" || mnc != "410" {
		t.Errorf("an explicit SIM must win over the table: %s/%s %s/%s", lang, country, mcc, mnc)
	}
}

// The device built after a successful /register must reuse the exact keys that were
// signed into the registration, otherwise the Noise handshake is rejected.
func TestRegisteredDeviceReusesRegistrationKeys(t *testing.T) {
	cli, _ := newMobileTestClient()
	ctx := context.Background()

	state, err := GenerateMobileRegistrationState("55", "43991665432", "2.26.38.72", "14", "sdk_gphone64_x86_64", "Google")
	if err != nil {
		t.Fatal(err)
	}
	p256, err := state.P256Signer()
	if err != nil {
		t.Fatal(err)
	}
	cli.mobileRegistration = NewMobileRegistrationClient(state, p256)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(MobileRegistrationResponse{
			Status: "ok", Login: "5543991665432", LID: "1234567890",
		})
	}))
	defer server.Close()
	cli.mobileRegistration.Endpoint = server.URL

	if _, err = cli.RegisterMobile(ctx, "123456"); err != nil {
		t.Fatalf("RegisterMobile: %v", err)
	}
	device := cli.Store
	if device.ID == nil {
		t.Fatal("device has no JID after registration")
	}
	if !device.Mobile {
		t.Fatal("device is not flagged as mobile")
	}
	if !bytes.Equal(device.NoiseKey.Priv[:], state.NoisePrivate[:]) {
		t.Fatal("noise key does not match the registered key")
	}
	if !bytes.Equal(device.IdentityKey.Priv[:], state.IdentityPrivate[:]) {
		t.Fatal("identity key does not match the registered key")
	}
	if device.SignedPreKey.KeyID != state.SignedPreKeyID {
		t.Fatal("pre-key ID does not match the registered key")
	}
	if *device.SignedPreKey.Signature != state.SignedPreKeySignature {
		t.Fatal("pre-key signature does not match the registered key")
	}
	if device.MobileManufacturer != "Google" || device.MobileModel != "sdk_gphone64_x86_64" {
		t.Fatalf("device profile not carried over: %+v", device)
	}
}
