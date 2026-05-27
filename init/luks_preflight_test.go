//go:build cgo

package main

// Tests for the FIDO2 pre-flight gate in recoverSystemdFido2Password.
// The gate keeps tokens whose credential isn't on any connected hidraw
// from reaching the PIN prompt.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anatol/booster/init/fido2iface"
	"github.com/anatol/luks.go"
	"github.com/stretchr/testify/require"
)

// withReadyUsbhid substitutes usbhidReady with an already-closed channel so
// waitForUsbhid returns immediately. ctx-aware-fido's primitive blocks until
// udev fires the first hidraw bind event, but unit tests run no udev — so
// without this swap recoverSystemdFido2Password parks on the channel.
func withReadyUsbhid(t *testing.T) {
	t.Helper()
	prev := usbhidReady
	closed := make(chan struct{})
	close(closed)
	usbhidReady = closed
	t.Cleanup(func() { usbhidReady = prev })
}

// withEmptyHidrawSysPath swaps hidrawSysPath to a fresh tempdir with NO
// entries. Returns the tempdir so the test can plug a hidraw in mid-flight
// by writing report_descriptor into it and calling broadcastHidrawDevice.
func withEmptyHidrawSysPath(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	prev := hidrawSysPath
	hidrawSysPath = tmp + "/"
	t.Cleanup(func() { hidrawSysPath = prev })
	return tmp
}

// plugFakeHidraw materialises a FIDO2-capable hidraw entry at tmp/<name>/device/.
// Returns immediately; the caller then calls broadcastHidrawDevice(name) to
// wake the listener-channel select.
func plugFakeHidraw(t *testing.T, tmp, name string) {
	t.Helper()
	devDir := filepath.Join(tmp, name, "device")
	require.NoError(t, os.MkdirAll(devDir, 0o755), "mkdir %s", devDir)
	require.NoError(t, os.WriteFile(filepath.Join(devDir, "report_descriptor"), fidoHIDDescriptor, 0o644), "write descriptor")
}

// waitForListenerRegistered polls until at least n broadcast listeners are
// registered or the deadline fires. recoverSystemdFido2Password registers
// its listener early; tests injecting via broadcastHidrawDevice must wait
// for that registration so the event isn't dropped on an empty registry.
func waitForListenerRegistered(t *testing.T, n int) {
	t.Helper()
	require.Eventually(t, func() bool {
		hidrawListenersMu.Lock()
		defer hidrawListenersMu.Unlock()
		return len(hidrawListeners) >= n
	}, 2*time.Second, 2*time.Millisecond, "listener not registered within deadline (wanted %d)", n)
}

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
		require.NoError(t, os.MkdirAll(devDir, 0o755), "setup tempdir")
		require.NoError(t, os.WriteFile(filepath.Join(devDir, "report_descriptor"), fidoHIDDescriptor, 0o644), "write descriptor")
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
	require.NoError(t, err, "marshal payload")
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
	withReadyUsbhid(t)

	withFakeHidrawDevices(t, []string{"hidraw0", "hidraw1"}, func() {
		token := luks.Token{
			Type:    "systemd-fido2",
			ID:      0,
			Slots:   []int{2},
			Payload: makeFido2TokenPayload(t, credID, []byte("salt"), "io.systemd.cryptsetup", false, false, false),
		}
		_, err := recoverSystemdFido2Password(context.Background(), token, "cryptroot")
		require.ErrorIs(t, err, errFido2FallbackToKeyboard, "expected fallback when credential absent")
		require.Zero(t, fake.assertionCalls, "expected zero full-assertion (PIN-prompting) calls; requests: %v", fake.assertionRequests)
		require.NotZero(t, fake.preflightCalls, "expected pre-flight to be invoked at least once")
	})
}

// TestRecoverFido2RunsAssertionWhenCredentialPresent: when pre-flight
// green-lights a connected device's credential, recoverSystemdFido2Password
// must proceed to the full assertion against that exact device. Uses
// pinRequired=false to keep the test independent of console-prompt
// mocking; the green-light → assertion path is PIN-independent.
func TestRecoverFido2RunsAssertionWhenCredentialPresent(t *testing.T) {
	credID := []byte("our-credential")
	fake := &fakeFidoForPreflight{
		presentCreds: map[string]bool{
			"/dev/hidraw1:" + string(credID): true,
		},
	}
	installFakeFido2Plugin(t, fake)
	withReadyUsbhid(t)

	withFakeHidrawDevices(t, []string{"hidraw0", "hidraw1"}, func() {
		token := luks.Token{
			Type:    "systemd-fido2",
			ID:      3,
			Slots:   []int{4},
			Payload: makeFido2TokenPayload(t, credID, []byte("salt"), "io.systemd.cryptsetup", false, true, false),
		}
		_, err := recoverSystemdFido2Password(context.Background(), token, "cryptroot")
		require.NoError(t, err, "expected unlock to proceed")
		require.Equal(t, 1, fake.assertionCalls, "expected exactly one full-assertion call")
		require.Equal(t, []string{"/dev/hidraw1"}, fake.assertionRequests, "expected assertion against /dev/hidraw1")
	})
}

// TestSerialMultiFido2TokensAdvancesPastNonMatching: two systemd-fido2
// tokens enrolled, only one physical key plugged in, ascending token-ID
// dispatch. The token whose credential ISN'T on the connected key must
// short-circuit via fallback (no PIN prompt) so the dispatcher reaches
// the matching token. Reproduces a user-reported multi-key scenario where
// only the second-enrolled key was inserted at boot. Uses pinRequired=false
// to keep the test independent of console-prompt mocking; the invariants
// (short-circuit on non-match; assertion against match exactly once) are
// PIN-independent.
func TestSerialMultiFido2TokensAdvancesPastNonMatching(t *testing.T) {
	wrongCred := []byte("old-keys-credential")
	rightCred := []byte("new-keys-credential")
	fake := &fakeFidoForPreflight{
		presentCreds: map[string]bool{
			"/dev/hidraw1:" + string(rightCred): true,
		},
	}
	installFakeFido2Plugin(t, fake)
	withReadyUsbhid(t)

	withFakeHidrawDevices(t, []string{"hidraw0", "hidraw1"}, func() {
		// Token 0 (will not match).
		_, err := recoverSystemdFido2Password(context.Background(), luks.Token{
			Type:    "systemd-fido2",
			ID:      0,
			Slots:   []int{2},
			Payload: makeFido2TokenPayload(t, wrongCred, []byte("salt0"), "io.systemd.cryptsetup", false, true, false),
		}, "cryptroot")
		require.ErrorIs(t, err, errFido2FallbackToKeyboard, "Token 0 should fall back (not present on inserted key)")
		require.Zero(t, fake.assertionCalls, "Token 0 must not invoke full assertion (PIN prompt)")

		// Token 3 (matches).
		_, err = recoverSystemdFido2Password(context.Background(), luks.Token{
			Type:    "systemd-fido2",
			ID:      3,
			Slots:   []int{4},
			Payload: makeFido2TokenPayload(t, rightCred, []byte("salt3"), "io.systemd.cryptsetup", false, true, false),
		}, "cryptroot")
		require.NoError(t, err, "Token 3 should unlock against the inserted key")
		require.Equal(t, 1, fake.assertionCalls, "Token 3 should invoke exactly one full assertion")
	})
}

// TestEmptyHidrawAtEntryThenHotPlugMatchingUnlocks pins the empty-hidraw
// asymmetry fix. When /sys/class/hidraw is empty at function entry, the
// bail-out gate's len(dir) > 0 guard suppresses the immediate fallback so
// the loop instead waits on hidrawDevices for udev to deliver an 'add'
// event. A user who boots without the key inserted then plugs it in mid-boot
// must be able to unlock — the prior gate fired errFido2FallbackToKeyboard
// on iteration 1 before the channel could deliver anything.
func TestEmptyHidrawAtEntryThenHotPlugMatchingUnlocks(t *testing.T) {
	credID := []byte("our-credential")
	fake := &fakeFidoForPreflight{
		presentCreds: map[string]bool{
			"/dev/hidraw0:" + string(credID): true,
		},
	}
	installFakeFido2Plugin(t, fake)

	withReadyUsbhid(t)
	tmp := withEmptyHidrawSysPath(t)

	token := luks.Token{
		Type:    "systemd-fido2",
		ID:      0,
		Slots:   []int{2},
		Payload: makeFido2TokenPayload(t, credID, []byte("salt"), "io.systemd.cryptsetup", false, true, false),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	type result struct {
		password []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		pw, err := recoverSystemdFido2Password(ctx, token, "cryptroot")
		done <- result{pw, err}
	}()

	waitForListenerRegistered(t, 1)

	// Materialise the FIDO2 hidraw and broadcast its arrival. The listener
	// inside recoverSystemdFido2Password should pick it up, preflight it,
	// and run a full assertion.
	plugFakeHidraw(t, tmp, "hidraw0")
	broadcastHidrawDevice("hidraw0")

	select {
	case r := <-done:
		require.NoError(t, r.err, "expected unlock to succeed after hot-plug")
		require.Equal(t, 1, fake.assertionCalls, "expected exactly one assertion call against hot-plugged device")
		require.Equal(t, []string{"/dev/hidraw0"}, fake.assertionRequests, "expected assertion against /dev/hidraw0")
	case <-time.After(3 * time.Second):
		require.Fail(t, "recoverSystemdFido2Password did not return after hot-plug")
	}
}

// TestEmptyHidrawAtEntryHotPlugNonMatchingKeepsWaiting verifies the loop
// keeps waiting after a non-matching FIDO2 device hot-plugs. Because
// /sys/class/hidraw was empty at entry, the bail-out gate's len(dir) > 0
// guard remains false even after the hot-plug event is processed —
// uniqueDevicesProcessed grows but the gate condition never trips. The
// function therefore exits only via ctx cancellation, never spontaneously
// returning errFido2FallbackToKeyboard. Pre-flight is invoked but no
// assertion runs.
func TestEmptyHidrawAtEntryHotPlugNonMatchingKeepsWaiting(t *testing.T) {
	credID := []byte("our-credential")
	fake := &fakeFidoForPreflight{
		presentCreds: map[string]bool{}, // nothing matches
	}
	installFakeFido2Plugin(t, fake)

	withReadyUsbhid(t)
	tmp := withEmptyHidrawSysPath(t)

	token := luks.Token{
		Type:    "systemd-fido2",
		ID:      0,
		Slots:   []int{2},
		Payload: makeFido2TokenPayload(t, credID, []byte("salt"), "io.systemd.cryptsetup", false, true, false),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := recoverSystemdFido2Password(ctx, token, "cryptroot")
		done <- err
	}()

	waitForListenerRegistered(t, 1)

	plugFakeHidraw(t, tmp, "hidraw0")
	broadcastHidrawDevice("hidraw0")

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.DeadlineExceeded, "expected ctx.DeadlineExceeded after non-matching hot-plug")
		require.GreaterOrEqual(t, fake.preflightCalls, 1, "expected pre-flight to run on the hot-plugged device")
		require.Zero(t, fake.assertionCalls, "expected zero assertion calls when credential absent")
	case <-time.After(2 * time.Second):
		require.Fail(t, "recoverSystemdFido2Password did not return within deadline overrun budget")
	}
}
