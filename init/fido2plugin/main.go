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

	libfido2 "github.com/keys-pub/go-libfido2"
)

// Fido2Assertion and IsFido2PinInvalid are the exported plugin symbols looked
// up by the init binary via plugin.Lookup. They must be package-level
// variables (not bare functions) for plugin.Lookup to find them.
var Fido2Assertion func(devPath string, credID, saltBytes []byte, relyingParty, pin string, pinRequired, userPresenceRequired, userVerificationRequired bool, notifyTouch func()) ([]byte, error) = fido2Assertion

var IsFido2PinInvalid func(err error) bool = isFido2PinInvalidError

var IsFido2PinAuthBlocked func(err error) bool = isFido2PinAuthBlockedError

func fido2Assertion(devPath string, credID, saltBytes []byte, relyingParty, pin string, pinRequired, userPresenceRequired, userVerificationRequired bool, notifyTouch func()) ([]byte, error) {
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
		if notifyTouch != nil && !pinRequired {
			notifyTouch()
		}
	}
	if userVerificationRequired {
		opts.UV = libfido2.True
	}

	var clientDataHash [32]byte

	assertion, err := dev.Assertion(relyingParty, clientDataHash[:], [][]byte{credID}, pin, opts)
	if err != nil {
		return nil, err
	}
	if len(assertion.HMACSecret) == 0 {
		return nil, fmt.Errorf("no HMAC secret in assertion")
	}

	return []byte(base64.StdEncoding.EncodeToString(assertion.HMACSecret)), nil
}

func isFido2PinInvalidError(err error) bool {
	return errors.Is(err, libfido2.ErrPinInvalid)
}

func isFido2PinAuthBlockedError(err error) bool {
	return errors.Is(err, libfido2.ErrPinAuthBlocked)
}
