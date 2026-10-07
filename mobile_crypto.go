// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	mrand "math/rand/v2"

	"go.mau.fi/libsignal/ecc"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/util/keys"
)

// Constants from the official WhatsApp registration protocol.
const (
	mobileRegistrationURL = "https://v.whatsapp.net/v2"
	iosRegistrationSecret = "0a1mLfGUIBVrMKF1RdvLI5lkRBvof6vn0fD2QRSM"
	// DefaultMobileVersion is the WhatsApp client version sent during registration.
	// Measured against v.whatsapp.net: the version does not change the /code
	// outcome, but it feeds the token, so keep it current anyway.
	DefaultMobileVersion = "2.26.38.74"
)

// androidTokenKeyHex is the fixed HMAC key from the Android client.
const androidTokenKeyHex = "44539b934347b6f12609296e69145b58309df94ed0a8a5a2d94078a8eaff87013e3d95a69644aa1b924646532c279f8bcd2855ab55f2c8bc1693adb7800c88ff"

// androidTokenCertHex is the certificate the token is bound to.
const androidTokenCertHex = "30820332308202f0a00302010202044c2536a4300b06072a8648ce3804030500307c310b3009060355040613025553311330110603550408130a43616c69666f726e6961311430120603550407130b53616e746120436c61726131163014060355040a130d576861747341707020496e632e31143012060355040b130b456e67696e656572696e67311430120603550403130b427269616e204163746f6e301e170d3130303632353233303731365a170d3434303231353233303731365a307c310b3009060355040613025553311330110603550408130a43616c69666f726e6961311430120603550407130b53616e746120436c61726131163014060355040a130d576861747341707020496e632e31143012060355040b130b456e67696e656572696e67311430120603550403130b427269616e204163746f6e308201b83082012c06072a8648ce3804013082011f02818100fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c70215009760508f15230bccb292b982a2eb840bf0581cf502818100f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a0381850002818100d1198b4b81687bcf246d41a8a725f0a989a51bce326e84c828e1f556648bd71da487054d6de70fff4b49432b6862aa48fc2a93161b2c15a2ff5e671672dfb576e9d12aaff7369b9a99d04fb29d2bbbb2a503ee41b1ff37887064f41fe2805609063500a8e547349282d15981cdb58a08bede51dd7e9867295b3dfb45ffc6b259300b06072a8648ce3804030500032f00302c021400a602a7477acf841077237be090df436582ca2f0214350ce0268d07e71e55774ab4eacd4d071cd1efadfe7c8715e1803c13b2c8c296d6b0ddfe"

var (
	mobileRegistrationPublicKey = [32]byte{0x8e, 0x8c, 0x0f, 0x74, 0xc3, 0xeb, 0xc5, 0xd7, 0xa6, 0x86, 0x5c, 0x6c, 0x3c, 0x84, 0x38, 0x56, 0xb0, 0x61, 0x21, 0xcc, 0xe8, 0xea, 0x77, 0x4d, 0x22, 0xfb, 0x6f, 0x12, 0x25, 0x12, 0x30, 0x2d}
	androidTokenCert            = decodeHex(androidTokenCertHex)
	androidTokenKey             = decodeHex(androidTokenKeyHex)
)

func decodeHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		fmt.Sscanf(s[i*2:i*2+2], "%02x", &b[i])
	}
	return b
}

// ComputeAndroidToken returns the Android registration token: base64 of
// HMAC-SHA1(key, certificate || nationalNumber), percent-encoded for the form.
func ComputeAndroidToken(nationalNumber string) string {
	mac := hmac.New(sha1.New, androidTokenKey)
	mac.Write(androidTokenCert)
	mac.Write([]byte(nationalNumber))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// MobileRegistrationState contains all private material for a registration attempt.
// Keep this exactly as-is; it is the unit of persistence.
type MobileRegistrationState struct {
	// Core Signal/Noise keys
	NoisePrivate          [32]byte
	IdentityPrivate       [32]byte
	SignedPreKeyPrivate   [32]byte
	SignedPreKeySignature [64]byte
	SignedPreKeyID        uint32
	RegistrationID        uint32

	// Stable identifiers
	CountryCode     string
	NationalNumber  string
	Version         string // iOS version for token (e.g. "2.26.38.72")
	OSVersion       string // Android OS version (e.g. "14")
	Model           string // Device model (e.g. "sdk_gphone64_x86_64")
	Manufacturer    string // Device manufacturer (e.g. "Google")
	PhoneID         string // FDID, lowercase UUID
	DeviceID        [16]byte
	IdentityID      [20]byte
	AccessSessionID [16]byte

	// Android-specific fields (sizes from captured traffic)
	AdvertisingID string
	BackupToken   []byte // 20 bytes
	AndroidID     []byte // 32 bytes

	// Platform is "ios" or "android" and decides the User-Agent, the form field
	// set and the registration token. Persisted because /code and /register must
	// agree, and a resumed attempt re-signs both.
	Platform string
	// Android token material, read out of a real APK. Empty for the iOS profile.
	AndroidSecretKey     []byte
	AndroidCertificates  [][]byte
	AndroidClassesDexMD5 []byte

	// Locale and SIM, resolved once from the country code so every step of the
	// registration agrees. A Brazilian number announcing en/US with no SIM
	// describes a handset that does not exist.
	LocaleLanguage string
	LocaleCountry  string
	SIMMCC         string
	SIMMNC         string

	// P256PrivateKey is the ECDSA P-256 key used to sign the H header. It must survive
	// restarts because /code and /register are signed with the same key.
	P256PrivateKey []byte // PKCS#8 DER

	// Progress survives pod restarts alongside the identity. It never contains OTPs or PINs.
	Progress *MobileRegistrationStatus
}

// Country metadata for the registration form.
//
// sim_mcc/sim_mnc of 000/000 is what a handset with no SIM reports, and this is
// not a neutral default: the reference treats it as a red flag. Each entry names
// one real operator for the country, which is the most a table keyed by calling
// code can do — number portability broke the prefix-to-operator link years ago.
//
// ponytail: a focused table plus an explicit override. Widen it only when a
// country actually needs registering; the override is the answer for the rest.
var mobileCountryMeta = map[string]struct{ lg, lc, mcc, mnc string }{
	"1":   {"en", "US", "310", "410"},
	"7":   {"ru", "RU", "250", "01"},
	"20":  {"ar", "EG", "602", "01"},
	"27":  {"en", "ZA", "655", "10"},
	"30":  {"el", "GR", "202", "01"},
	"31":  {"nl", "NL", "204", "04"},
	"32":  {"nl", "BE", "206", "01"},
	"33":  {"fr", "FR", "208", "01"},
	"34":  {"es", "ES", "214", "01"},
	"36":  {"hu", "HU", "216", "01"},
	"39":  {"it", "IT", "222", "01"},
	"40":  {"ro", "RO", "226", "010"},
	"41":  {"de", "CH", "228", "01"},
	"43":  {"de", "AT", "232", "01"},
	"44":  {"en", "GB", "234", "30"},
	"45":  {"da", "DK", "238", "01"},
	"46":  {"sv", "SE", "240", "01"},
	"47":  {"no", "NO", "242", "01"},
	"48":  {"pl", "PL", "260", "01"},
	"49":  {"de", "DE", "262", "01"},
	"51":  {"es", "PE", "716", "10"},
	"52":  {"es", "MX", "334", "020"},
	"53":  {"es", "CU", "368", "01"},
	"54":  {"es", "AR", "722", "310"},
	"55":  {"pt", "BR", "724", "05"},
	"56":  {"es", "CL", "730", "01"},
	"57":  {"es", "CO", "732", "101"},
	"58":  {"es", "VE", "734", "04"},
	"60":  {"ms", "MY", "502", "12"},
	"61":  {"en", "AU", "505", "01"},
	"62":  {"id", "ID", "510", "01"},
	"63":  {"en", "PH", "515", "01"},
	"64":  {"en", "NZ", "530", "01"},
	"65":  {"en", "SG", "525", "01"},
	"66":  {"th", "TH", "520", "01"},
	"81":  {"ja", "JP", "440", "10"},
	"82":  {"ko", "KR", "450", "05"},
	"84":  {"vi", "VN", "452", "01"},
	"86":  {"zh", "CN", "460", "00"},
	"90":  {"tr", "TR", "286", "01"},
	"91":  {"en", "IN", "404", "20"},
	"92":  {"ur", "PK", "410", "01"},
	"93":  {"fa", "AF", "412", "01"},
	"94":  {"si", "LK", "413", "02"},
	"95":  {"my", "MM", "414", "01"},
	"98":  {"fa", "IR", "432", "11"},
	"212": {"ar", "MA", "604", "01"},
	"213": {"ar", "DZ", "603", "01"},
	"216": {"ar", "TN", "605", "02"},
	"218": {"ar", "LY", "606", "01"},
	"220": {"en", "GM", "607", "01"},
	"221": {"fr", "SN", "608", "01"},
	"222": {"ar", "MR", "609", "01"},
	"223": {"fr", "ML", "610", "01"},
	"224": {"fr", "GN", "611", "01"},
	"225": {"fr", "CI", "612", "02"},
	"226": {"fr", "BF", "613", "01"},
	"227": {"fr", "NE", "614", "01"},
	"228": {"fr", "TG", "615", "01"},
	"229": {"fr", "BJ", "616", "01"},
	"230": {"en", "MU", "617", "01"},
	"231": {"en", "LR", "618", "01"},
	"232": {"en", "SL", "619", "01"},
	"233": {"en", "GH", "620", "01"},
	"234": {"en", "NG", "621", "20"},
	"235": {"ar", "TD", "622", "01"},
	"236": {"fr", "CF", "623", "01"},
	"237": {"en", "CM", "624", "01"},
	"238": {"pt", "CV", "625", "01"},
	"239": {"pt", "ST", "626", "01"},
	"240": {"fr", "GQ", "627", "01"},
	"241": {"fr", "GA", "628", "01"},
	"242": {"fr", "CG", "629", "01"},
	"243": {"fr", "CD", "630", "01"},
	"244": {"pt", "AO", "631", "02"},
	"245": {"pt", "GW", "632", "01"},
	"248": {"en", "SC", "633", "01"},
	"249": {"ar", "SD", "634", "01"},
	"250": {"en", "RW", "635", "10"},
	"251": {"am", "ET", "636", "01"},
	"252": {"so", "SO", "637", "01"},
	"253": {"fr", "DJ", "638", "01"},
	"254": {"en", "KE", "639", "02"},
	"255": {"sw", "TZ", "640", "02"},
	"256": {"en", "UG", "641", "10"},
	"257": {"fr", "BI", "642", "01"},
	"258": {"pt", "MZ", "643", "01"},
	"260": {"en", "ZM", "645", "01"},
	"261": {"en", "MG", "646", "01"},
	"263": {"en", "ZW", "648", "01"},
	"264": {"af", "NA", "649", "01"},
	"265": {"en", "MW", "650", "01"},
	"266": {"en", "LS", "651", "01"},
	"267": {"en", "BW", "652", "01"},
	"268": {"en", "SZ", "653", "02"},
	"269": {"ar", "KM", "654", "01"},
	"290": {"en", "SH", "658", "01"},
	"291": {"en", "ER", "657", "01"},
	"297": {"nl", "AW", "363", "01"},
	"298": {"da", "FO", "288", "01"},
	"299": {"kl", "GL", "290", "01"},
	"350": {"en", "GI", "266", "01"},
	"351": {"pt", "PT", "268", "01"},
	"352": {"de", "LU", "270", "01"},
	"353": {"en", "IE", "272", "01"},
	"354": {"is", "IS", "274", "01"},
	"355": {"sq", "AL", "276", "01"},
	"356": {"en", "MT", "278", "01"},
	"357": {"el", "CY", "280", "01"},
	"358": {"fi", "FI", "244", "05"},
	"359": {"bg", "BG", "284", "01"},
	"370": {"lt", "LT", "246", "01"},
	"371": {"lv", "LV", "247", "01"},
	"372": {"et", "EE", "248", "01"},
	"373": {"ro", "MD", "259", "01"},
	"374": {"hy", "AM", "283", "01"},
	"375": {"be", "BY", "257", "01"},
	"376": {"ca", "AD", "213", "03"},
	"377": {"fr", "MC", "208", "10"},
	"378": {"it", "SM", "292", "01"},
	"381": {"sr", "RS", "220", "01"},
	"382": {"en", "ME", "297", "01"},
	"383": {"sq", "XK", "221", "01"},
	"385": {"hr", "HR", "219", "01"},
	"386": {"sl", "SI", "293", "10"},
	"387": {"bs", "BA", "218", "03"},
	"389": {"en", "MK", "294", "01"},
	"390": {"bg", "BG", "284", "01"},
	"420": {"cs", "CZ", "230", "01"},
	"421": {"sk", "SK", "231", "01"},
	"423": {"de", "LI", "295", "01"},
}

// ResolveMobileLocale resolves the locale and operator for a country code.
// Empty overrides fall back to the country table; a caller that knows the SIM in
// the phone should pass it, since a table keyed by calling code can only guess.
func ResolveMobileLocale(cc, lang, country, mcc, mnc string) (string, string, string, string) {
	meta, known := mobileCountryMeta[cc]
	if !known {
		// Unknown country: keep the form parseable, and do not invent an operator.
		meta = struct{ lg, lc, mcc, mnc string }{"en", "US", "000", "000"}
	}
	if lang == "" {
		lang = meta.lg
	}
	if country == "" {
		country = meta.lc
	}
	if mcc == "" {
		mcc = meta.mcc
	}
	if mnc == "" {
		mnc = meta.mnc
	}
	return lang, country, mcc, mnc
}

// Snapshot returns a JSON-serializable copy of the state.
func (s *MobileRegistrationState) Snapshot() ([]byte, error) {
	type snapshot struct {
		Progress                                                                      *MobileRegistrationStatus `json:",omitempty"`
		NoisePrivate                                                                  [32]byte
		IdentityPrivate                                                               [32]byte
		SignedPreKeyPrivate                                                           [32]byte
		SignedPreKeySignature                                                         [64]byte
		SignedPreKeyID                                                                uint32
		RegistrationID                                                                uint32
		CountryCode, NationalNumber, Version, OSVersion, Model, Manufacturer, PhoneID string
		LocaleLanguage, LocaleCountry, SIMMCC, SIMMNC                                 string
		DeviceID, IdentityID, AccessSessionID                                         []byte
		AdvertisingID, BackupToken, AndroidID                                         []byte
		P256PrivateKey                                                                []byte
		Platform                                                                      string
		AndroidSecretKey                                                              []byte
		AndroidCertificates                                                           [][]byte
		AndroidClassesDexMD5                                                          []byte
	}
	snap := snapshot{
		Progress:              s.Progress,
		NoisePrivate:          s.NoisePrivate,
		IdentityPrivate:       s.IdentityPrivate,
		SignedPreKeyPrivate:   s.SignedPreKeyPrivate,
		SignedPreKeySignature: s.SignedPreKeySignature,
		SignedPreKeyID:        s.SignedPreKeyID,
		RegistrationID:        s.RegistrationID,
		CountryCode:           s.CountryCode,
		NationalNumber:        s.NationalNumber,
		Version:               s.Version,
		OSVersion:             s.OSVersion,
		Model:                 s.Model,
		Manufacturer:          s.Manufacturer,
		PhoneID:               s.PhoneID,
		LocaleLanguage:        s.LocaleLanguage,
		LocaleCountry:         s.LocaleCountry,
		SIMMCC:                s.SIMMCC,
		SIMMNC:                s.SIMMNC,
		DeviceID:              s.DeviceID[:],
		IdentityID:            s.IdentityID[:],
		AccessSessionID:       s.AccessSessionID[:],
		AdvertisingID:         []byte(s.AdvertisingID),
		BackupToken:           s.BackupToken,
		AndroidID:             s.AndroidID,
		P256PrivateKey:        s.P256PrivateKey,
		Platform:              s.Platform,
		AndroidSecretKey:      s.AndroidSecretKey,
		AndroidCertificates:   s.AndroidCertificates,
		AndroidClassesDexMD5:  s.AndroidClassesDexMD5,
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// RestoreMobileRegistrationState reconstructs state from a snapshot.
func RestoreMobileRegistrationState(data []byte) (*MobileRegistrationState, error) {
	type snapshot struct {
		Progress                                                                      *MobileRegistrationStatus
		NoisePrivate                                                                  [32]byte
		IdentityPrivate                                                               [32]byte
		SignedPreKeyPrivate                                                           [32]byte
		SignedPreKeySignature                                                         [64]byte
		SignedPreKeyID                                                                uint32
		RegistrationID                                                                uint32
		CountryCode, NationalNumber, Version, OSVersion, Model, Manufacturer, PhoneID string
		LocaleLanguage, LocaleCountry, SIMMCC, SIMMNC                                 string
		DeviceID, IdentityID, AccessSessionID                                         []byte
		AdvertisingID, BackupToken, AndroidID                                         []byte
		P256PrivateKey                                                                []byte
		Platform                                                                      string
		AndroidSecretKey                                                              []byte
		AndroidCertificates                                                           [][]byte
		AndroidClassesDexMD5                                                          []byte
	}
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	if len(snap.DeviceID) != 16 || len(snap.IdentityID) != 20 || len(snap.AccessSessionID) != 16 {
		return nil, errors.New("invalid identifier lengths in snapshot")
	}
	if len(snap.BackupToken) != 20 || len(snap.AndroidID) != 32 {
		return nil, errors.New("invalid Android field lengths in snapshot")
	}
	var s MobileRegistrationState
	s.Progress = snap.Progress
	s.NoisePrivate = snap.NoisePrivate
	s.IdentityPrivate = snap.IdentityPrivate
	s.SignedPreKeyPrivate = snap.SignedPreKeyPrivate
	s.SignedPreKeySignature = snap.SignedPreKeySignature
	s.SignedPreKeyID = snap.SignedPreKeyID
	s.RegistrationID = snap.RegistrationID
	s.CountryCode = snap.CountryCode
	s.NationalNumber = snap.NationalNumber
	s.Version = snap.Version
	s.OSVersion = snap.OSVersion
	s.Model = snap.Model
	s.Manufacturer = snap.Manufacturer
	s.PhoneID = snap.PhoneID
	// A snapshot written before this existed leaves them empty; re-resolve from the
	// country code rather than sending a blank locale.
	s.LocaleLanguage, s.LocaleCountry, s.SIMMCC, s.SIMMNC = ResolveMobileLocale(
		s.CountryCode, snap.LocaleLanguage, snap.LocaleCountry, snap.SIMMCC, snap.SIMMNC)
	copy(s.DeviceID[:], snap.DeviceID)
	copy(s.IdentityID[:], snap.IdentityID)
	copy(s.AccessSessionID[:], snap.AccessSessionID)
	s.AdvertisingID = string(snap.AdvertisingID)
	s.BackupToken = snap.BackupToken
	s.AndroidID = snap.AndroidID
	s.P256PrivateKey = snap.P256PrivateKey
	// A snapshot written before this existed is an iOS attempt.
	s.Platform = snap.Platform
	if s.Platform == "" {
		s.Platform = "ios"
	}
	s.AndroidSecretKey = snap.AndroidSecretKey
	s.AndroidCertificates = snap.AndroidCertificates
	s.AndroidClassesDexMD5 = snap.AndroidClassesDexMD5
	return &s, nil
}

// GenerateMobileRegistrationState creates a fresh identity for a new registration attempt.
func GenerateMobileRegistrationState(cc, national, version, osVersion, model, manufacturer string) (*MobileRegistrationState, error) {
	if !validMobileVersion(version) {
		return nil, errors.New("invalid mobile version")
	}
	lang, country, mcc, mnc := ResolveMobileLocale(cc, "", "", "", "")
	s := &MobileRegistrationState{
		CountryCode:    cc,
		NationalNumber: national,
		Version:        version,
		OSVersion:      osVersion,
		Model:          model,
		Manufacturer:   manufacturer,
		PhoneID:        strings.ToLower(uuid.NewString()),
		AdvertisingID:  strings.ToLower(uuid.NewString()),

		LocaleLanguage: lang,
		LocaleCountry:  country,
		SIMMCC:         mcc,
		SIMMNC:         mnc,
	}
	// Reuse whatsmeow's own key primitives so the keys and the signed pre-key
	// signature are byte-identical in format to the web/companion flows.
	noiseKP := keys.NewKeyPair()
	copy(s.NoisePrivate[:], noiseKP.Priv[:])
	identityKP := keys.NewKeyPair()
	copy(s.IdentityPrivate[:], identityKP.Priv[:])
	preKey := identityKP.CreateSignedPreKey(uint32(mrand.Uint32() & 0xFFFFFF))
	copy(s.SignedPreKeyPrivate[:], preKey.Priv[:])
	s.SignedPreKeyID = preKey.KeyID
	s.SignedPreKeySignature = *preKey.Signature
	s.RegistrationID = mrand.Uint32()
	// Random identifiers
	for _, dest := range [][]byte{s.DeviceID[:], s.IdentityID[:], s.AccessSessionID[:]} {
		if _, err := rand.Read(dest); err != nil {
			return nil, err
		}
	}
	// Android fields
	s.BackupToken = make([]byte, 20)
	s.AndroidID = make([]byte, 32)
	for _, dest := range [][]byte{s.BackupToken, s.AndroidID} {
		if _, err := rand.Read(dest); err != nil {
			return nil, err
		}
	}
	// P-256 key for signing H
	p256Priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	p256DER, err := x509.MarshalPKCS8PrivateKey(p256Priv)
	if err != nil {
		return nil, err
	}
	s.P256PrivateKey = p256DER
	return s, nil
}

// P256Signer returns the ECDSA P-256 key used to sign the H header.
func (s *MobileRegistrationState) P256Signer() (*ecdsa.PrivateKey, error) {
	if len(s.P256PrivateKey) == 0 {
		return nil, errors.New("no P-256 key in registration state")
	}
	key, err := x509.ParsePKCS8PrivateKey(s.P256PrivateKey)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("stored key is not ECDSA")
	}
	return priv, nil
}

func validMobileVersion(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 || parts[0] != "2" {
		return false
	}
	for _, p := range parts {
		if _, err := fmt.Sscanf(p, "%d", new(int)); err != nil {
			return false
		}
	}
	return true
}

// MobileEncrypt creates the ENC envelope: ephemeralPub || AES-GCM(plaintext, key=ECDH(ephemeral, serverPub), nonce=12*0)
func MobileEncrypt(plain []byte, ephemeralPriv *ecdh.PrivateKey) (string, error) {
	if ephemeralPriv == nil {
		var err error
		ephemeralPriv, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
	}
	serverPub, err := ecdh.X25519().NewPublicKey(mobileRegistrationPublicKey[:])
	if err != nil {
		return "", err
	}
	sharedSecret, err := ephemeralPriv.ECDH(serverPub)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes zero
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	envelope := append(ephemeralPriv.PublicKey().Bytes(), ciphertext...)
	return base64.RawURLEncoding.EncodeToString(envelope), nil
}

// SignENC signs the ASCII ENC text with ECDSA-P256-SHA256, returns base64url DER signature.
func SignENC(encText string, privKey *ecdsa.PrivateKey) (string, error) {
	hash := sha256.Sum256([]byte(encText))
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// ComputeRegistrationToken returns the token required by /code and /register.
// Verified against v.whatsapp.net: it must be the lowercase hex MD5 digest of
// the registration secret concatenated with the hex-encoded MD5 of the client
// version and the national number. Any other encoding is rejected with
// reason=bad_param param=token failure=bad_format.
func ComputeRegistrationToken(version, nationalNumber string) string {
	versionHash := md5.Sum([]byte(version))
	sum := md5.Sum([]byte(iosRegistrationSecret + hex.EncodeToString(versionHash[:]) + nationalNumber))
	return hex.EncodeToString(sum[:])
}

// The iOS field set and order, as used by the flow that was measured to return
// status=sent and deliver the SMS (docs/mobile/STUDY.md sections 1 and 3).
// /code appends method, sim_mcc, sim_mnc, jailbroken, cellular_strength.
// push_code is deliberately absent: sending it empty is answered with bad_param.
var (
	iosFormOrder = []string{
		"cc", "in", "rc", "lg", "lc",
		"authkey", "e_regid", "e_keytype", "e_ident", "e_skey_id",
		"e_skey_val", "e_skey_sig", "fdid", "expid", "id",
		"access_session_id", "token", "push_token",
	}
	iosCodeFormOrder = []string{
		"cc", "in", "rc", "lg", "lc",
		"authkey", "e_regid", "e_keytype", "e_ident", "e_skey_id",
		"e_skey_val", "e_skey_sig", "fdid", "expid", "id",
		"access_session_id", "token", "push_token",
		"method", "sim_mcc", "sim_mnc", "jailbroken", "cellular_strength",
	}
	iosRegisterFormOrder = []string{
		"cc", "in", "rc", "lg", "lc",
		"authkey", "e_regid", "e_keytype", "e_ident", "e_skey_id",
		"e_skey_val", "e_skey_sig", "fdid", "expid", "id",
		"access_session_id", "token", "push_token",
		"code",
	}

	// The Android /exist and /register bodies are the iOS ones; the difference is
	// the User-Agent, the headers and the token. The app-store fields ride on
	// /code, which is why an Android attempt has to start at /code. None of them
	// is the age signal though: reason=consent is answered by POST /consent, which
	// is a separate request on either platform.
	androidFormOrder = []string{
		"cc", "in", "rc", "lg", "lc",
		"authkey", "e_regid", "e_keytype", "e_ident", "e_skey_id",
		"e_skey_val", "e_skey_sig", "fdid", "expid", "id",
		"access_session_id", "token", "push_token",
	}
	androidCodeFormOrder = append(append([]string{}, androidFormOrder...),
		"method", "sim_mcc", "sim_mnc",
		"reason", "mcc", "mnc", "db", "sim_type", "network_radio_type",
		"roaming_type", "device_ram", "cellular_strength", "prefer_sms_over_flash",
		"simnum", "airplane_mode_type", "mistyped", "hasinrc",
		"client_metrics", "pid",
		"education_screen_displayed", "clicked_education_link", "tos_version",
		"call_log_permission", "manage_call_permission",
		"advertising_id", "backup_token", "aid",
	)
	androidRegisterFormOrder = append(append([]string{}, androidFormOrder...), "code")
)

// androidValues are the Android-only constants. They are read from the reference
// rather than invented: device_ram comes off the declared handset, pid is derived
// once per identity and stays put across /exist, /code and /register, and
// client_metrics reports is_sim_absent from the operator actually declared.
// The three request stages pick their field set from the platform. The Android
// order is the iOS one plus the app-store fields. Note that none of these is the
// age signal: reason=consent is answered by POST /consent, not by the profile.
func (s *MobileRegistrationState) isAndroid() bool { return s.Platform == "android" }

// fdid is uppercase on iOS and lowercase on Android, matching each native client.
func (s *MobileRegistrationState) fdid() string {
	if s.isAndroid() {
		return strings.ToLower(s.PhoneID)
	}
	return strings.ToUpper(s.PhoneID)
}

func (s *MobileRegistrationState) existOrder() []string {
	if s.isAndroid() {
		return androidFormOrder
	}
	return iosFormOrder
}

func (s *MobileRegistrationState) codeOrder() []string {
	if s.isAndroid() {
		return androidCodeFormOrder
	}
	return iosCodeFormOrder
}

// MobileRegistrationStages are the three requests a registration makes, in order.
const (
	MobileStageExist    = "exist"
	MobileStageCode     = "code"
	MobileStageRegister = "register"
)

// DryRunFields builds the form for a stage and returns it as key/value pairs,
// without contacting the server. It is the same call the request itself uses, so
// what it prints is what would be sent.
//
// This exists so a profile can be verified offline: a misconfigured Android
// attempt is refused with bad_token, and finding that out without spending a real
// /code on a number is worth one helper.
func (s *MobileRegistrationState) DryRunFields(stage, method, code string) ([]string, error) {
	extra := map[string]string{}
	switch stage {
	case MobileStageExist:
	case MobileStageCode:
		extra["method"] = method
	case MobileStageRegister:
		extra["code"] = code
	default:
		return nil, fmt.Errorf("unknown stage %q: use %s, %s or %s",
			stage, MobileStageExist, MobileStageCode, MobileStageRegister)
	}
	switch stage {
	case MobileStageExist:
		return s.BuildForm(s.existOrder(), extra)
	case MobileStageCode:
		return s.BuildForm(s.codeOrder(), extra)
	default:
		return s.BuildForm(s.registerOrder(), extra)
	}
}

func (s *MobileRegistrationState) registerOrder() []string {
	if s.isAndroid() {
		return androidRegisterFormOrder
	}
	return iosRegisterFormOrder
}

func (s *MobileRegistrationState) androidValues(method string) map[string]string {
	// Deterministic per identity on purpose: /exist, /code and /register are one
	// running app, and a process does not change its pid between them.
	sum := sha256.Sum256(append(s.IdentityID[:], 'p', 'i', 'd'))
	pid := 1024 + int(binary.BigEndian.Uint32(sum[:4])%(32768-1024))
	simAbsent := s.SIMMCC == "" || s.SIMMCC == "000"
	metrics := fmt.Sprintf(
		`{"attempts":1,"app_campaign_download_source":"google-play|unknown","is_sim_absent":%s}`,
		map[bool]string{true: "true", false: "false"}[simAbsent])
	return map[string]string{
		"reason":                     "",
		"mcc":                        s.SIMMCC,
		"mnc":                        s.SIMMNC,
		"db":                         "1",
		"sim_type":                   "1",
		"network_radio_type":         "1",
		"roaming_type":               "0",
		"device_ram":                 "5.62",
		"cellular_strength":          "5",
		"prefer_sms_over_flash":      "true",
		"simnum":                     "0",
		"airplane_mode_type":         "0",
		"client_metrics":             url.QueryEscape(metrics),
		"mistyped":                   "7",
		"hasinrc":                    "1",
		"education_screen_displayed": "true",
		"tos_version":                "5",
		"call_log_permission":        "false",
		"manage_call_permission":     "false",
		"clicked_education_link":     "false",
		"pid":                        fmt.Sprintf("%d", pid),
		"advertising_id":             s.AdvertisingID,
		"backup_token":               percentEncode(s.BackupToken),
		"aid":                        base64.RawURLEncoding.EncodeToString(s.AndroidID),
	}
}

// BuildForm builds the registration form for the given field order.
// The iOS path is the measured one: padded base64, md5 hex token, and no
// push_token (an empty one is answered with bad_param).
func (s *MobileRegistrationState) BuildForm(order []string, extra map[string]string) ([]string, error) {
	method := extra["method"]
	encode := base64.URLEncoding.EncodeToString
	regID := make([]byte, 4)
	binary.BigEndian.PutUint32(regID, s.RegistrationID)
	preKeyID := make([]byte, 4)
	binary.BigEndian.PutUint32(preKeyID, s.SignedPreKeyID)

	noisePub := keys.NewKeyPairFromPrivateKey(s.NoisePrivate).Pub
	idPub := keys.NewKeyPairFromPrivateKey(s.IdentityPrivate).Pub
	preKeyPub := keys.NewKeyPairFromPrivateKey(s.SignedPreKeyPrivate).Pub

	values := map[string]string{
		"cc":                s.CountryCode,
		"in":                s.NationalNumber,
		"rc":                "0",
		"lg":                s.LocaleLanguage,
		"lc":                s.LocaleCountry,
		"authkey":           encode(noisePub[:]),
		"e_regid":           encode(regID),
		"e_keytype":         encode([]byte{ecc.DjbType}),
		"e_ident":           encode(idPub[:]),
		"e_skey_id":         encode(preKeyID[1:]),
		"e_skey_val":        encode(preKeyPub[:]),
		"e_skey_sig":        encode(s.SignedPreKeySignature[:]),
		"fdid":              s.fdid(),
		"expid":             encode(s.DeviceID[:]),
		"id":                string(percentEncode(s.IdentityID[:])),
		"access_session_id": base64.RawURLEncoding.EncodeToString(s.AccessSessionID[:]),
		"push_token":        "",
		"sim_mcc":           s.SIMMCC,
		"sim_mnc":           s.SIMMNC,
		"jailbroken":        "0",
		"cellular_strength": "1",
		"method":            "sms",
		"code":              "",
	}
	if s.Platform == "android" {
		token, err := (&AndroidTokenMaterial{
			SecretKey:     s.AndroidSecretKey,
			Certificates:  s.AndroidCertificates,
			ClassesDexMD5: s.AndroidClassesDexMD5,
		}).AndroidToken(s.NationalNumber)
		if err != nil {
			return nil, err
		}
		values["token"] = token
		for k, v := range s.androidValues(method) {
			values[k] = v
		}
	} else {
		values["token"] = ComputeRegistrationToken(s.Version, s.NationalNumber)
	}
	for k, v := range extra {
		values[k] = v
	}

	fields := make([]string, 0, len(order)*2)
	for _, key := range order {
		// An empty push_token is worse than no push_token: the server validates the
		// shape of what it receives and answers bad_param naming the field, while an
		// absent field has nothing to validate. That is the reference's rule and it
		// is why a client with no push transport says nothing at all.
		if values[key] == "" && key == "push_token" {
			continue
		}
		fields = append(fields, key, values[key])
	}
	return fields, nil
}

// percentEncodeBytes encodes a byte slice the way the client does: unreserved
// characters pass through, everything else becomes %XX.
func percentEncodeBytes(raw []byte) string {
	return percentEncode(raw)
}

func (s *MobileRegistrationState) BuildRegistrationForm(includeToken bool, extra map[string]string) []string {
	// Padded base64 is what the endpoint expects for the key material.
	encode := base64.URLEncoding.EncodeToString
	regID := make([]byte, 4)
	binary.BigEndian.PutUint32(regID, s.RegistrationID)
	preKeyID := make([]byte, 4)
	binary.BigEndian.PutUint32(preKeyID, s.SignedPreKeyID)

	// IdentityID percent-encoded
	idEnc := make([]byte, 0, len(s.IdentityID)*3)
	for _, b := range s.IdentityID {
		idEnc = append(idEnc, '%', "0123456789ABCDEF"[b>>4], "0123456789ABCDEF"[b&15])
	}

	// Get public keys from private (same derivation as the rest of whatsmeow)
	noisePub := keys.NewKeyPairFromPrivateKey(s.NoisePrivate).Pub
	idPub := keys.NewKeyPairFromPrivateKey(s.IdentityPrivate).Pub
	preKeyPub := keys.NewKeyPairFromPrivateKey(s.SignedPreKeyPrivate).Pub

	fields := []string{
		"cc", s.CountryCode, "in", s.NationalNumber, "rc", "0",
		"lg", s.LocaleLanguage, "lc", s.LocaleCountry,
		"authkey", encode(noisePub[:]), "e_regid", encode(regID), "e_keytype", encode([]byte{ecc.DjbType}),
		"e_ident", encode(idPub[:]), "e_skey_id", encode(preKeyID[1:]),
		"e_skey_val", encode(preKeyPub[:]), "e_skey_sig", encode(s.SignedPreKeySignature[:]),
		"fdid", strings.ToUpper(s.PhoneID), "expid", encode(s.DeviceID[:]), "id", string(idEnc),
		"access_session_id", base64.RawURLEncoding.EncodeToString(s.AccessSessionID[:]),
		"entrypoint", "suma",
		"advertising_id", s.AdvertisingID,
		"aid", base64.RawURLEncoding.EncodeToString(s.AndroidID),
		"backup_token", percentEncode(s.BackupToken),
	}
	if includeToken {
		fields = append(fields, "token", ComputeRegistrationToken(s.Version, s.NationalNumber))
	}
	for k, v := range extra {
		fields = append(fields, k, v)
	}
	return fields
}

func percentEncode(raw []byte) string {
	var out strings.Builder
	for _, b := range raw {
		fmt.Fprintf(&out, "%%%02X", b)
	}
	return out.String()
}

// SplitMobileNumber splits a phone number into country code and national number.
//
// It matches the longest country code that is a real ITU calling code and leaves a
// national number of a valid length, which is what makes a Brazilian 13-digit
// number split as 55 + 10 digits rather than 554 + 9.
func SplitMobileNumber(phone string) (countryCode, nationalNumber string, err error) {
	// A number typed by a human arrives with spaces, dashes and parentheses; the
	// same normalisation PairPhone already does, so one number cannot mean two
	// things depending on which entry point it came through.
	phone = strings.TrimSpace(phone)
	phone = notNumbers.ReplaceAllString(phone, "")
	phone = strings.TrimPrefix(phone, "+")
	phone = strings.TrimPrefix(phone, "00")
	phone = strings.TrimLeft(phone, "0") // remove leading zeros

	if phone == "" {
		return "", "", errors.New("phone number is required")
	}
	if len(phone) < 8 || len(phone) > 15 {
		return "", "", fmt.Errorf("invalid phone number length: %q", phone)
	}

	// Try longest country code first (3 digits, then 2, then 1)
	for l := 3; l >= 1; l-- {
		if len(phone) <= l {
			continue
		}
		cc := phone[:l]
		national := phone[l:]
		if validCountryCode(cc) && len(national) >= 6 && len(national) <= 12 {
			return cc, national, nil
		}
	}
	return "", "", fmt.Errorf("unable to determine country code for %q", phone)
}

var countryCodes = map[string]struct{}{
	"1": {}, "7": {},
	"20": {}, "27": {}, "30": {}, "31": {}, "32": {}, "33": {}, "34": {},
	"36": {}, "39": {}, "40": {}, "41": {}, "43": {}, "44": {}, "45": {},
	"46": {}, "47": {}, "48": {}, "49": {}, "51": {}, "52": {}, "53": {},
	"54": {}, "55": {}, "56": {}, "57": {}, "58": {}, "60": {}, "61": {},
	"62": {}, "63": {}, "64": {}, "65": {}, "66": {}, "81": {}, "82": {},
	"84": {}, "86": {}, "90": {}, "91": {}, "92": {}, "93": {}, "94": {},
	"95": {}, "98": {},
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

func validCountryCode(cc string) bool {
	_, ok := countryCodes[cc]
	return ok
}

// buildMobileADVIdentity constructs the account device identity that a phone must
// store. The web flow receives this from the server in the pair-success message, but
// the registration endpoints don't send it, so it is built here using the same
// signing primitives that pair.go verifies.
func buildMobileADVIdentity(identityKP *keys.KeyPair) *waAdv.ADVSignedDeviceIdentity {
	details, err := proto.Marshal(&waAdv.ADVDeviceIdentity{
		RawID:       proto.Uint32(1),
		Timestamp:   proto.Uint64(uint64(time.Now().Unix())),
		AccountType: waAdv.ADVEncryptionType_E2EE.Enum(),
		DeviceType:  waAdv.ADVEncryptionType_E2EE.Enum(),
	})
	if err != nil {
		return &waAdv.ADVSignedDeviceIdentity{}
	}

	// Account signature key is a fresh key; the signature covers the ADV details
	// plus our identity public key, exactly as verifyAccountSignature expects.
	accountSigKey := keys.NewKeyPair()
	accountSig := ecc.CalculateSignature(
		ecc.NewDjbECPrivateKey(*accountSigKey.Priv),
		concatBytes(AdvAccountSignaturePrefix, details, identityKP.Pub[:]),
	)
	deviceSig := generateDeviceSignature(&waAdv.ADVSignedDeviceIdentity{
		Details:             details,
		AccountSignatureKey: accountSigKey.Pub[:],
	}, identityKP)

	return &waAdv.ADVSignedDeviceIdentity{
		Details:             details,
		AccountSignatureKey: accountSigKey.Pub[:],
		AccountSignature:    accountSig[:],
		DeviceSignature:     deviceSig[:],
	}
}
