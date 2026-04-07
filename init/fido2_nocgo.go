//go:build !cgo

package main

import "fmt"

func fido2Assertion(devPath string, credID, saltBytes []byte, relyingParty, pin string, pinRequired, userPresenceRequired, userVerificationRequired bool, notifyTouch func()) ([]byte, error) {
	return nil, fmt.Errorf("FIDO2 not supported in this build (requires CGO)")
}

func isFido2PinInvalidError(err error) bool {
	return false
}

func isFido2PinAuthBlockedError(err error) bool {
	return false
}
