// Package fido2iface defines the Fido2Plugin interface shared between the
// booster init binary and the fido2plugin.so plugin. Both import this package
// so that Go's type system can verify the plugin implements the interface at
// load time via a single type assertion.
package fido2iface

// Fido2Plugin is implemented by fido2plugin.so and loaded at runtime via plugin.Open.
type Fido2Plugin interface {
	Fido2Assertion(devPath string, credID, saltBytes []byte, relyingParty, pin string, pinRequired, userPresenceRequired, userVerificationRequired bool, notifyTouch func()) ([]byte, error)

	// Fido2Preflight reports whether the authenticator at devPath holds the
	// given credential, without consuming a PIN attempt or requiring touch.
	// It performs a CTAP2 assertion with up=FIDO_OPT_FALSE, no PIN, and no
	// HMAC-secret extension; the device either returns FIDO_OK (credential
	// present → true) or FIDO_ERR_NO_CREDENTIALS (not present → false).
	// Any other error is surfaced unchanged.
	//
	// When the LUKS token requires user verification (uv-required=true),
	// pre-flight may not be possible — per CTAP 2.1 §7.4 some authenticators
	// reject `up=false` requests when UV is required. In that case
	// implementations should return (true, nil) so the caller proceeds to
	// the full assertion.
	Fido2Preflight(devPath string, credID []byte, relyingParty string, userVerificationRequired bool) (bool, error)

	IsFido2PinInvalid(err error) bool
	IsFido2PinAuthBlocked(err error) bool
	IsFido2PinBlocked(err error) bool
	IsFido2WrongDevice(err error) bool
	IsFido2PinRequired(err error) bool
	IsFido2TouchTimeout(err error) bool
}
