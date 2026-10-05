package store

import (
	"testing"

	"go.mau.fi/whatsmeow/proto/waWa6"
	"go.mau.fi/whatsmeow/types"
)

// Preserve the payload used by the locally validated registration after merging
// the older remote implementation. Web sessions must still use companion login.
func TestMobileAndWebLoginPayload(t *testing.T) {
	jid := types.NewJID("5511999999999", types.DefaultUserServer)
	jid.Device = 7
	device := &Device{ID: &jid, Mobile: true, MobileVersion: "2.26.38.74",
		MobileManufacturer: "Apple", MobileModel: "iPhone 15 Pro", MobileOSVersion: "17.4.1", MobilePhoneID: "phone-id"}
	payload := device.GetClientPayload()
	if payload.GetDevice() != 0 || payload.GetPassive() || payload.WebInfo != nil ||
		payload.UserAgent.GetPlatform() != waWa6.ClientPayload_UserAgent_ANDROID ||
		payload.UserAgent.GetManufacturer() != device.MobileManufacturer ||
		payload.UserAgent.GetPhoneID() != device.MobilePhoneID ||
		payload.UserAgent.AppVersion.GetQuaternary() != 74 {
		t.Fatalf("mobile login changed: %v", payload)
	}
	device.Mobile = false
	payload = device.GetClientPayload()
	if payload.GetDevice() != 7 || !payload.GetPassive() || payload.WebInfo == nil ||
		payload.UserAgent.GetPlatform() != waWa6.ClientPayload_UserAgent_WEB {
		t.Fatalf("web login changed: %v", payload)
	}
	device.Mobile = true
	device.ID = nil
	if device.GetClientPayload() != nil {
		t.Fatal("an unregistered mobile device must not pair as a web companion")
	}
}
