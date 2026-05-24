//go:build cgo

package main

// Tests for the FIDO2 pre-flight gate in recoverSystemdFido2Password.
// The gate keeps tokens whose credential isn't on any connected hidraw
// from reaching the PIN prompt.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/anatol/booster/init/fido2iface"
	"github.com/anatol/luks.go"
)

// fidoHIDDescriptor is a minimal HID report descriptor that satisfies
// isHidRawFido2's FIDO Alliance Usage Page (0xd0f1) check. Used by the
// test helpers that materialise fake /sys/class/hidraw entries.
//
// Item prefix 0b00000110 (size=2), then 0xd0 0xf1 (FIDO).
var fidoHIDDescriptor = []byte{0x06, 0xd0, 0xf1}

// withFakeHidrawDevices creates a tempdir styled like /sys/class/hidraw/
// with the requested device names, swaps hidrawSysPath for body's duration,
// and restores it on cleanup.
func withFakeHidrawDevices(t *testing.T, devNames []string, body func()) {
	t.Helper()
	tmp := t.TempDir()
	for _, name := range devNames {
		devDir := filepath.Join(tmp, name, "device")
		if err := os.MkdirAll(devDir, 0o755); err != nil {
			t.Fatalf("setup tempdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(devDir, "report_descriptor"), fidoHIDDescriptor, 0o644); err != nil {
			t.Fatalf("write descriptor: %v", err)
		}
	}
	prev := hidrawSysPath
	hidrawSysPath = tmp + "/"
	t.Cleanup(func() { hidrawSysPath = prev })
	body()
}

// installFakeFido2Plugin pre-fires fido2Once so loadFido2Plugin won't try to
// plugin.Open the real .so (which doesn't exist in test binaries and would
// emit a warning). Substitutes fake for the duration of the test.
func installFakeFido2Plugin(t *testing.T, fake fido2iface.Fido2Plugin) {
	t.Helper()
	fido2Once.Do(func() {}) // mark as fired so real loader stays out
	prev := fido2plugin
	fido2plugin = fake
	t.Cleanup(func() { fido2plugin = prev })
}

// fakeFidoForPreflight implements fido2iface.Fido2Plugin for the test. It
// records pre-flight calls and lets the test decide which credentials are
// "present" without ever invoking real libfido2.
type fakeFidoForPreflight struct {
	presentCreds      map[string]bool // devPath + ":" + string(credID) → present
	assertionCalls    int
	preflightCalls    int
	assertionRequests []string // devPath of each full assertion
}

func (f *fakeFidoForPreflight) Fido2Preflight(devPath string, credID []byte, rp string, uv bool) (bool, error) {
	f.preflightCalls++
	return f.presentCreds[devPath+":"+string(credID)], nil
}

func (f *fakeFidoForPreflight) Fido2Assertion(devPath string, credID, salt []byte, rp, pin string, pinRequired, up, uv bool, notifyTouch func()) ([]byte, error) {
	f.assertionCalls++
	f.assertionRequests = append(f.assertionRequests, devPath)
	return []byte("ok"), nil
}

func (f *fakeFidoForPreflight) IsFido2PinInvalid(error) bool     { return false }
func (f *fakeFidoForPreflight) IsFido2PinAuthBlocked(error) bool { return false }
func (f *fakeFidoForPreflight) IsFido2PinBlocked(error) bool     { return false }
func (f *fakeFidoForPreflight) IsFido2WrongDevice(error) bool    { return false }
func (f *fakeFidoForPreflight) IsFido2PinRequired(error) bool    { return false }
func (f *fakeFidoForPreflight) IsFido2TouchTimeout(error) bool   { return false }

// makeFido2TokenPayload builds the systemd-fido2 LUKS token JSON payload
// that recoverSystemdFido2Password unmarshals.
func makeFido2TokenPayload(t *testing.T, credID, salt []byte, rp string, pinRequired, upRequired, uvRequired bool) []byte {
	t.Helper()
	p := struct {
		Credential               string `json:"fido2-credential"`
		Salt                     string `json:"fido2-salt"`
		RelyingParty             string `json:"fido2-rp"`
		PinRequired              bool   `json:"fido2-clientPin-required"`
		UserPresenceRequired     bool   `json:"fido2-up-required"`
		UserVerificationRequired bool   `json:"fido2-uv-required"`
	}{
		Credential:               base64.StdEncoding.EncodeToString(credID),
		Salt:                     base64.StdEncoding.EncodeToString(salt),
		RelyingParty:             rp,
		PinRequired:              pinRequired,
		UserPresenceRequired:     upRequired,
		UserVerificationRequired: uvRequired,
	}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return body
}

// TestRecoverFido2SkipsPinPromptWhenCredentialAbsent: when no connected
// hidraw holds the token's credential, recoverSystemdFido2Password must
// NOT call Fido2Assertion (the real call would prompt for PIN). Must
// return errFido2FallbackToKeyboard so the serial dispatcher advances to
// the next token. Uses pinRequired=false to keep the test independent of
// console-prompt mocking.
func TestRecoverFido2SkipsPinPromptWhenCredentialAbsent(t *testing.T) {
	credID := []byte("other-keys-credential")
	fake := &fakeFidoForPreflight{
		presentCreds: map[string]bool{}, // nothing present
	}
	installFakeFido2Plugin(t, fake)

	withFakeHidrawDevices(t, []string{"hidraw0", "hidraw1"}, func() {
		token := luks.Token{
			Type:    "systemd-fido2",
			ID:      0,
			Slots:   []int{2},
			Payload: makeFido2TokenPayload(t, credID, []byte("salt"), "io.systemd.cryptsetup", false, false, false),
		}
		_, err := recoverSystemdFido2Password(context.Background(), token, "cryptroot")
		if !errors.Is(err, errFido2FallbackToKeyboard) {
			t.Fatalf("expected errFido2FallbackToKeyboard when credential absent, got: %v", err)
		}
		if fake.assertionCalls != 0 {
			t.Fatalf("expected zero full-assertion (PIN-prompting) calls, got %d (requests: %v)", fake.assertionCalls, fake.assertionRequests)
		}
		if fake.preflightCalls == 0 {
			t.Fatalf("expected pre-flight to be invoked at least once")
		}
	})
}
