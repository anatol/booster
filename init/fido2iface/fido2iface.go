// Package fido2iface defines the Fido2Plugin interface shared between the
// booster init binary and the fido2plugin.so plugin. Both import this package
// so that Go's type system can verify the plugin implements the interface at
// load time via a single type assertion.
package fido2iface

// Fido2Plugin is implemented by fido2plugin.so and loaded at runtime via plugin.Open.
type Fido2Plugin interface {
	Fido2Assertion(devPath string, credID, saltBytes []byte, relyingParty, pin string, pinRequired, userPresenceRequired, userVerificationRequired bool, notifyTouch func()) ([]byte, error)
	IsFido2PinInvalid(err error) bool
	IsFido2PinAuthBlocked(err error) bool
}
