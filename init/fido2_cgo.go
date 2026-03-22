//go:build cgo

package main

import (
	"fmt"
	"plugin"
	"sync"
)

// fido2PluginPath is the location of the FIDO2 plugin inside the initramfs.
// The generator bundles it at this path only when enable_fido2: true is set in booster.yaml.
const fido2PluginPath = "/usr/lib/booster/fido2plugin.so"

var (
	fido2Once        sync.Once
	fido2AssertFn    *func(string, []byte, []byte, string, string, bool, bool, bool, func()) ([]byte, error)
	fido2PinFn       *func(error) bool
	fido2PinBlockFn  *func(error) bool
)

func loadFido2Plugin() {
	fido2Once.Do(func() {
		p, err := plugin.Open(fido2PluginPath)
		if err != nil {
			warning("fido2: cannot open plugin %s: %v", fido2PluginPath, err)
			return
		}
		sym1, err := p.Lookup("Fido2Assertion")
		if err != nil {
			warning("fido2: plugin missing Fido2Assertion symbol: %v", err)
			return
		}
		sym2, err := p.Lookup("IsFido2PinInvalid")
		if err != nil {
			warning("fido2: plugin missing IsFido2PinInvalid symbol: %v", err)
			return
		}
		sym3, err := p.Lookup("IsFido2PinAuthBlocked")
		if err != nil {
			warning("fido2: plugin missing IsFido2PinAuthBlocked symbol: %v", err)
			return
		}
		fido2AssertFn, _ = sym1.(*func(string, []byte, []byte, string, string, bool, bool, bool, func()) ([]byte, error))
		fido2PinFn, _ = sym2.(*func(error) bool)
		fido2PinBlockFn, _ = sym3.(*func(error) bool)
	})
}

func fido2Assertion(devPath string, credID, saltBytes []byte, relyingParty, pin string, pinRequired, userPresenceRequired, userVerificationRequired bool, notifyTouch func()) ([]byte, error) {
	loadFido2Plugin()
	if fido2AssertFn == nil {
		return nil, fmt.Errorf("FIDO2 plugin unavailable (%s not found or invalid)", fido2PluginPath)
	}
	return (*fido2AssertFn)(devPath, credID, saltBytes, relyingParty, pin, pinRequired, userPresenceRequired, userVerificationRequired, notifyTouch)
}

func isFido2PinInvalidError(err error) bool {
	loadFido2Plugin()
	if fido2PinFn == nil {
		return false
	}
	return (*fido2PinFn)(err)
}

func isFido2PinAuthBlockedError(err error) bool {
	loadFido2Plugin()
	if fido2PinBlockFn == nil {
		return false
	}
	return (*fido2PinBlockFn)(err)
}
