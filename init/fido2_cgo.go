//go:build cgo

package main

import (
	"fmt"
	"plugin"
	"sync"

	"github.com/anatol/booster/init/fido2iface"
)

// fido2PluginPath is the location of the FIDO2 plugin inside the initramfs.
// The generator bundles it at this path only when enable_fido2: true is set in booster.yaml.
const fido2PluginPath = "/usr/lib/booster/fido2plugin.so"

var (
	fido2Once   sync.Once
	fido2plugin fido2iface.Fido2Plugin
)

func loadFido2Plugin() {
	fido2Once.Do(func() {
		p, err := plugin.Open(fido2PluginPath)
		if err != nil {
			warning("fido2: cannot open plugin %s: %v", fido2PluginPath, err)
			return
		}
		sym, err := p.Lookup("Plugin")
		if err != nil {
			warning("fido2: plugin missing Plugin symbol: %v", err)
			return
		}
		pl, ok := sym.(*fido2iface.Fido2Plugin)
		if !ok {
			warning("fido2: Plugin symbol does not implement Fido2Plugin interface")
			return
		}
		fido2plugin = *pl
	})
}

func fido2Assertion(devPath string, credID, saltBytes []byte, relyingParty, pin string, pinRequired, userPresenceRequired, userVerificationRequired bool, notifyTouch func()) ([]byte, error) {
	loadFido2Plugin()
	if fido2plugin == nil {
		return nil, fmt.Errorf("FIDO2 plugin unavailable (%s not found or invalid)", fido2PluginPath)
	}
	return fido2plugin.Fido2Assertion(devPath, credID, saltBytes, relyingParty, pin, pinRequired, userPresenceRequired, userVerificationRequired, notifyTouch)
}

func isFido2PinInvalidError(err error) bool {
	loadFido2Plugin()
	if fido2plugin == nil {
		return false
	}
	return fido2plugin.IsFido2PinInvalid(err)
}

func isFido2PinAuthBlockedError(err error) bool {
	loadFido2Plugin()
	if fido2plugin == nil {
		return false
	}
	return fido2plugin.IsFido2PinAuthBlocked(err)
}
