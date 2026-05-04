// Package fido2plugin is a Go plugin that provides FIDO2 HMAC-secret assertion
// via the go-libfido2 CGO bindings. It is compiled separately:
//
//	go build -buildmode=plugin -o /usr/lib/booster/fido2plugin.so ./init/fido2plugin/
//
// The booster init binary loads this plugin at runtime only when a FIDO2 token
// is actually required, so libfido2.so is not a hard dependency of init itself.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anatol/booster/init/fido2iface"
	libfido2 "github.com/keys-pub/go-libfido2"
)

// Plugin is the exported symbol loaded by the init binary via plugin.Lookup.
// It is exported as the fido2iface.Fido2Plugin interface so the init binary
// can verify it with a single type assertion.
var Plugin fido2iface.Fido2Plugin = &fido2Impl{}

type fido2Impl struct{}

func (f *fido2Impl) Fido2Assertion(devPath string, credID, saltBytes []byte, relyingParty, pin string, pinRequired, userPresenceRequired, userVerificationRequired bool, notifyTouch func()) ([]byte, error) {
	// go-libfido2 passes empty string as NULL to fido_dev_get_assert, which
	// bypasses PIN verification and proceeds to touch. When a PIN is required,
	// reject empty input immediately so the retry loop re-prompts the user.
	if pinRequired && pin == "" {
		return nil, libfido2.ErrPinInvalid
	}

	dev, err := libfido2.NewDevice(devPath)
	if err != nil {
		return nil, err
	}

	opts := &libfido2.AssertionOpts{
		Extensions: []libfido2.Extension{libfido2.HMACSecretExtension},
		HMACSalt:   saltBytes,
	}
	if userPresenceRequired {
		opts.UP = libfido2.True
	}
	if userVerificationRequired {
		opts.UV = libfido2.True
	}

	var clientDataHash [32]byte

	type assertResult struct {
		assertion *libfido2.Assertion
		err       error
	}
	ch := make(chan assertResult, 1)
	go func() {
		a, e := dev.Assertion(relyingParty, clientDataHash[:], [][]byte{credID}, pin, opts)
		ch <- assertResult{a, e}
	}()

	var res assertResult
	if userPresenceRequired {
		// Give the device a moment to return a quick error (e.g. wrong PIN).
		// If it's still running after 500ms the device is waiting for touch.
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case res = <-ch:
			timer.Stop()
		case <-timer.C:
			if notifyTouch != nil {
				notifyTouch()
			}
			res = <-ch
		}
	} else {
		res = <-ch
	}

	// CTAP2.1 throttling: after a wrong PIN the device may require touch before
	// accepting another PIN attempt. It signals this by returning ErrUPRequired
	// immediately (not blocking). Notify the user and retry; the retry blocks
	// until the device detects touch, then verifies the PIN.
	if errors.Is(res.err, libfido2.ErrUPRequired) {
		if notifyTouch != nil {
			notifyTouch()
		}
		res.assertion, res.err = dev.Assertion(relyingParty, clientDataHash[:], [][]byte{credID}, pin, opts)
	}

	if res.err != nil {
		return nil, res.err
	}
	if len(res.assertion.HMACSecret) == 0 {
		return nil, fmt.Errorf("no HMAC secret in assertion")
	}

	return []byte(base64.StdEncoding.EncodeToString(res.assertion.HMACSecret)), nil
}

// IsFido2PinInvalid covers the user-typed-the-wrong-PIN family of CTAP errors.
// All three should consume a PIN attempt and re-prompt; without 51 and 63 the
// caller treats them as opaque errors and never retries the PIN.
//   - FIDO_ERR_PIN_INVALID      (0x31 / 49) → ErrPinInvalid (mapped sentinel)
//   - FIDO_ERR_PIN_AUTH_INVALID (0x33 / 51) → unmapped, generic error string
//   - FIDO_ERR_UV_INVALID       (0x3f / 63) → unmapped, generic error string
func (f *fido2Impl) IsFido2PinInvalid(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, libfido2.ErrPinInvalid) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "libfido2 error 51") || strings.Contains(msg, "libfido2 error 63")
}

func (f *fido2Impl) IsFido2PinAuthBlocked(err error) bool {
	return errors.Is(err, libfido2.ErrPinAuthBlocked)
}

func (f *fido2Impl) IsFido2PinBlocked(err error) bool {
	// FIDO_ERR_PIN_BLOCKED (0x32 = 50) means the PIN retry counter reached zero
	// and the PIN must be reset before any FIDO2 operations can proceed.
	// go-libfido2 does not expose this as a named error; detect it by its generic
	// error string from errFromCode's default case.
	return err != nil && strings.Contains(err.Error(), "libfido2 error 50")
}

// IsFido2WrongDevice reports whether the device rejected our credential —
// either it was never enrolled here, or the credential ID we supplied is
// invalid for it. Common when the user has multiple FIDO2 keys plugged in:
// only one was enrolled with this volume; the others should be skipped
// silently rather than logged at info level as opaque errors.
//   - FIDO_ERR_NO_CREDENTIALS     (0x2e / 46) → ErrNoCredentials
//   - FIDO_ERR_INVALID_CREDENTIAL (0x22 / 34) → ErrInvalidCredential
func (f *fido2Impl) IsFido2WrongDevice(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, libfido2.ErrNoCredentials) || errors.Is(err, libfido2.ErrInvalidCredential)
}

// IsFido2PinRequired reports whether the device says it requires a PIN that
// we did not supply. Hits when credential metadata says no PIN is required
// but the token has had one set since enrollment (firmware update, policy
// change). Caller should re-prompt with PIN entry enabled.
//   - FIDO_ERR_PIN_REQUIRED (0x36 / 54) → ErrPinRequired
func (f *fido2Impl) IsFido2PinRequired(err error) bool {
	return errors.Is(err, libfido2.ErrPinRequired)
}

// IsFido2TouchTimeout reports whether the user did not touch the FIDO2 device
// in time. libfido2 has two distinct codes for this — device-side timeout vs
// host-side wait expiry — and we treat both the same:
//   - FIDO_ERR_ACTION_TIMEOUT      (0x3a / 58) → ErrActionTimeout (mapped sentinel)
//   - FIDO_ERR_USER_ACTION_TIMEOUT (0x2f / 47) → unmapped, generic error string
func (f *fido2Impl) IsFido2TouchTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, libfido2.ErrActionTimeout) {
		return true
	}
	return strings.Contains(err.Error(), "libfido2 error 47")
}
