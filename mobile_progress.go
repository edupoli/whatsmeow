package whatsmeow

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"go.mau.fi/whatsmeow/store"
)

// Registration stages are persisted, not goroutines waiting for frontend input.
const (
	MobileRegistrationChannels       = "channels"
	MobileRegistrationWaitingCode    = "waiting_code"
	MobileRegistrationWaitingPIN     = "waiting_pin"
	MobileRegistrationWaitingConsent = "waiting_consent"
	MobileRegistrationUnknown        = "outcome_unknown"
	MobileRegistrationBlocked        = "blocked"
	MobileRegistrationChallenge      = "challenge_required"
	MobileRegistrationFailed         = "failed"
	MobileRegistrationRegistered     = "registered"
)

var (
	ErrMobileRegistrationState = errors.New("operation is not allowed in the current mobile registration stage")
	ErrMobileOutcomeUnknown    = errors.New("previous mobile request may have reached WhatsApp; do not resend automatically")
)

// MobileCooldownError is a local refusal: no WhatsApp request was made.
// RetryAt is a Unix timestamp in seconds, suitable for a frontend countdown.
type MobileCooldownError struct {
	RetryAt int64
}

func (e *MobileCooldownError) Error() string {
	return fmt.Sprintf("mobile registration cooldown until %s", time.Unix(e.RetryAt, 0).UTC().Format(time.RFC3339))
}

// saveMobileProgress records the attempt's position alongside its identity.
//
// The store refuses to overwrite a pending row outright, which is what protects the
// keys; progress is not key material, so this reads the row and writes through the
// store's compare-and-swap. That keeps two writers from clobbering each other: the
// second one fails instead of silently reverting the first one's stage.
//
// Callers hold mobileRegistrationLock. That is process-local, so it does not stop a
// second worker for the same number; durable command dedup belongs to the consumer.
func (cli *Client) saveMobileProgress(client *MobileRegistrationClient) error {
	snapshot, err := client.State.Snapshot()
	if err != nil {
		return err
	}
	phone := client.State.CountryCode + client.State.NationalNumber

	// Independent of the caller's context: cancelling an HTTP command must not
	// cancel recording what WhatsApp answered.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	container, ok := cli.Store.Container.(store.DeviceContainer)
	if !ok {
		return errors.New("device store does not support mobile registration persistence")
	}
	stored, err := container.GetPendingMobileRegistration(ctx, phone)
	if err != nil {
		return err
	}
	if stored == nil {
		return container.PutPendingMobileRegistration(ctx, phone, snapshot)
	}
	if bytes.Equal(stored, snapshot) {
		return nil
	}
	return container.UpdatePendingMobileRegistration(ctx, phone, stored, snapshot)
}

// mobileOperation journals the intention before making an external request. A
// crash/timeout between sending and persisting the reply leaves outcome_unknown,
// never a fresh identity eligible for an automatic replay.
func (cli *Client) mobileOperation(ctx context.Context, operation, method string, call func() (*MobileRegistrationResponse, error)) (*MobileRegistrationResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	client := cli.mobileRegistration
	p := client.State.Progress
	if p == nil {
		p = &MobileRegistrationStatus{Phone: client.State.CountryCode + client.State.NationalNumber}
		client.State.Progress = p
	}
	previousStage := p.Stage
	p.Stage, p.Operation, p.UpdatedAt = MobileRegistrationUnknown, operation, time.Now().Unix()
	if operation == "/code" {
		p.CodeAttempted = true
		// Recorded before the call, so a dropped connection still leaves the channel
		// the user asked for.
		p.Method = method
	}
	if err := cli.saveMobileProgress(client); err != nil {
		return nil, fmt.Errorf("persist mobile request intention: %w", err)
	}
	resp, err := call()
	p.UpdatedAt = time.Now().Unix()
	p.LastResponse = resp
	p.HTTPStatus = 0
	var regErr *MobileRegistrationError
	if errors.As(err, &regErr) {
		p.HTTPStatus = regErr.HTTPStatus
	} else if err == nil {
		p.HTTPStatus = 200
	}
	if resp != nil {
		if p.RetryAtByMethod == nil {
			p.RetryAtByMethod = make(map[string]int64)
		}
		for _, method := range serverMethods {
			if wait := resp.cooldownSeconds(method); wait > 0 {
				p.RetryAtByMethod[method] = max(p.RetryAtByMethod[method], p.UpdatedAt+int64(wait))
			}
		}
		if resp.RetryAfter > 0 {
			p.RetryAt = max(p.RetryAt, p.UpdatedAt+int64(resp.RetryAfter))
		}
		if operation == "/code" {
			p.CodeResponse, p.CodeRespAt = resp, p.UpdatedAt
		}
	}
	// A server/proxy HTTP failure does not prove that the operation was rejected.
	if err == nil {
		switch operation {
		case "/code":
			p.Method = method
			p.Stage = MobileRegistrationWaitingCode
		default:
			p.Stage, p.Registered, p.LID = MobileRegistrationRegistered, true, resp.LID
		}
	} else if p.HTTPStatus == 200 && resp != nil {
		switch {
		case resp.Reason == "blocked" || resp.IsBlocked():
			p.Stage = MobileRegistrationBlocked
		case resp.IsChallenge():
			p.Stage = MobileRegistrationChallenge
		case resp.Reason == "security_code":
			p.Stage = MobileRegistrationWaitingPIN
		case isMobileConsentGate(resp):
			p.Stage = MobileRegistrationWaitingConsent
		case resp.Reason == "incorrect" || resp.Reason == "too_recent" || resp.Reason == "too_many_guesses" || resp.Reason == "guessed_too_fast":
			p.Stage = previousStage
			if operation == "/code" {
				p.Stage = MobileRegistrationChannels
			}
		case operation == "/code" && (resp.Reason == "no_routes" || resp.Reason == "provider_unroutable"):
			p.Stage = MobileRegistrationChannels
			// Keep the refusal so the panel can show why this channel was dropped.
			p.LastResponse = resp
		default:
			p.Stage = MobileRegistrationFailed
		}
	}
	if saveErr := cli.saveMobileProgress(client); saveErr != nil {
		// Keep the in-memory state conservative too. The saved intention remains
		// unknown if the result could not be recorded.
		p.Stage = MobileRegistrationUnknown
		return resp, errors.Join(err, fmt.Errorf("persist mobile response: %w", saveErr))
	}
	return resp, err
}

func checkMobileStep(p *MobileRegistrationStatus, stage, method string) error {
	if p == nil { // Legacy snapshots predate stage tracking.
		return nil
	}
	if p.Stage == MobileRegistrationUnknown {
		return ErrMobileOutcomeUnknown
	}
	if p.Stage != stage {
		return fmt.Errorf("%w: stage=%s, expected=%s", ErrMobileRegistrationState, p.Stage, stage)
	}
	retryAt := max(p.RetryAt, p.RetryAtByMethod[method])
	if retryAt > time.Now().Unix() {
		return &MobileCooldownError{RetryAt: retryAt}
	}
	return nil
}

// RetryMobileCode requests a code on an existing identity, after an explicit user
// action. ResumeMobileRegistration restores it after restart. No /exist, key
// rotation, sleeps or channel fallback are performed. The worker must also enforce
// durable command IDs and per-phone limits across different instances.
func (cli *Client) RetryMobileCode(ctx context.Context, method string) (*MobileRegistrationResponse, error) {
	if cli == nil {
		return nil, ErrClientIsNil
	}
	if !SupportedMethod(method) {
		return nil, errors.New("method must be sms, voice, email_otp, or wa_old")
	}
	if !cli.mobileRegistrationLock.TryLock() {
		return nil, errors.New("mobile registration already in progress")
	}
	defer cli.mobileRegistrationLock.Unlock()
	if cli.mobileRegistration == nil || cli.Store.ID != nil {
		return nil, ErrMobileRegistrationState
	}
	p := cli.mobileRegistration.State.Progress
	if p == nil {
		return nil, fmt.Errorf("%w: legacy snapshot has no delivery outcome", ErrMobileOutcomeUnknown)
	}
	stage := MobileRegistrationChannels
	if p.Stage == MobileRegistrationWaitingCode {
		stage = MobileRegistrationWaitingCode
	}
	if err := checkMobileStep(p, stage, method); err != nil {
		return nil, err
	}
	// No route is evidence only for the attempted channel. Do not manufacture a
	// retry deadline when the server gave none.
	if p.Method == method && p.LastResponse != nil &&
		(p.LastResponse.Reason == "no_routes" || p.LastResponse.Reason == "provider_unroutable") &&
		max(p.RetryAt, p.RetryAtByMethod[method]) == 0 {
		return p.LastResponse, fmt.Errorf("%w: no route for %s and no retry deadline", ErrMobileRegistrationState, method)
	}
	p.Method = method
	return cli.mobileOperation(ctx, "/code", method, func() (*MobileRegistrationResponse, error) {
		return cli.mobileRegistration.RequestCode(ctx, method)
	})
}
