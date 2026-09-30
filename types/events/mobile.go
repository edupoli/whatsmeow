// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package events

// MobileCodeRequested is emitted after RequestMobileCode has dispatched a
// verification code out-of-band (SMS, voice, wa_old, or email_otp). The code
// itself is never part of the event; the application receives it outside the
// library and passes it back to RegisterMobile.
type MobileCodeRequested struct {
	// Phone is the full international number (country code + national number).
	Phone string
	// Method is the delivery channel that was used (sms, voice, wa_old, email_otp).
	Method string
	// Length is the number of digits in the verification code.
	Length int
	// RetryAfter is how many seconds to wait before requesting another code.
	RetryAfter int
}

// MobileRegistered is emitted after RegisterMobile successfully registers the
// device as a primary device for the given phone number.
type MobileRegistered struct {
	// Phone is the full international number (country code + national number).
	Phone string
	// LID is the account's linked ID returned by the registration server.
	LID string
}