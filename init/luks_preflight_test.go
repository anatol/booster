//go:build cgo

package main

// Tests for the FIDO2 pre-flight gate in recoverSystemdFido2Password.
// The gate keeps tokens whose credential isn't on any connected hidraw
// from reaching the PIN prompt.
//
// Note for eager-prompt tests below: the PIN-required path in
// recoverSystemdFido2Password routes through recoverFido2WithEagerPrompt,
// which calls askFido2Pin (a package var) for PIN entry. Tests substitute
// a scripted responder via withFakeFido2Pin so the flow runs
// deterministically without a console TTY or plymouthd.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	// assertionFn lets tests script success/failure per assertion call.
	// nil → return ([]byte("ok"), nil) on every call.
	assertionFn func(call int, devPath, pin string) ([]byte, error)
	// pinInvalidFn classifies errors returned by assertionFn as PIN-invalid.
	pinInvalidFn func(error) bool
}

func (f *fakeFidoForPreflight) Fido2Preflight(devPath string, credID []byte, rp string, uv bool) (bool, error) {
	f.preflightCalls++
	return f.presentCreds[devPath+":"+string(credID)], nil
}

func (f *fakeFidoForPreflight) Fido2Assertion(devPath string, credID, salt []byte, rp, pin string, pinRequired, up, uv bool, notifyTouch func()) ([]byte, error) {
	call := f.assertionCalls
	f.assertionCalls++
	f.assertionRequests = append(f.assertionRequests, devPath)
	if f.assertionFn != nil {
		return f.assertionFn(call, devPath, pin)
	}
	return []byte("ok"), nil
}

// Per-error-class predicate hooks let tests script assertion outcomes.
func (f *fakeFidoForPreflight) IsFido2PinInvalid(err error) bool {
	if f.pinInvalidFn != nil {
		return f.pinInvalidFn(err)
	}
	return false
}
func (f *fakeFidoForPreflight) IsFido2PinAuthBlocked(error) bool { return false }
func (f *fakeFidoForPreflight) IsFido2PinBlocked(error) bool     { return false }
func (f *fakeFidoForPreflight) IsFido2WrongDevice(error) bool    { return false }
func (f *fakeFidoForPreflight) IsFido2PinRequired(error) bool    { return false }
func (f *fakeFidoForPreflight) IsFido2TouchTimeout(error) bool   { return false }

// withFakeFido2Pin substitutes askFido2Pin with a scripted responder that
// returns the given replies in order. After the last reply, further calls
// return ctx.Err() so a misbehaving test can't hang. Restores on cleanup.
func withFakeFido2Pin(t *testing.T, replies []string) *fakePinResponder {
	t.Helper()
	r := &fakePinResponder{replies: replies}
	prev := askFido2Pin
	askFido2Pin = r.respond
	t.Cleanup(func() { askFido2Pin = prev })
	return r
}

type fakePinResponder struct {
	replies []string
	prompts []string
	calls   int
	// beforeReply, if set, fires after each call is recorded but before the
	// reply is returned. The call argument is 1-indexed and identifies which
	// reply is about to be issued — letting a test mutate side state (plug
	// in a device, flip a fake-plugin map) between prompts.
	beforeReply func(call int)
}

func (r *fakePinResponder) respond(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
	r.prompts = append(r.prompts, prompt)
	r.calls++
	if r.beforeReply != nil {
		r.beforeReply(r.calls)
	}
	if r.calls > len(r.replies) {
		return nil, context.Canceled
	}
	return []byte(r.replies[r.calls-1]), nil
}

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

// TestEagerPromptEmptyEnterReturnsFido2Skipped: when a PIN-required token's
// enrolled key IS connected but the user empty-Enters at the PIN prompt, the
// function returns errFido2Skipped so the serial dispatcher can advance to
// the next PIN-bearing token (TPM2-PIN, etc.) without waiting for the full
// token-timeout. This is the deadlock break the eager-prompt path exists for.
func TestEagerPromptEmptyEnterReturnsFido2Skipped(t *testing.T) {
	credID := []byte("our-credential")
	fake := &fakeFidoForPreflight{
		presentCreds: map[string]bool{"/dev/hidraw0:" + string(credID): true},
	}
	installFakeFido2Plugin(t, fake)
	resp := withFakeFido2Pin(t, []string{""}) // empty Enter

	withFakeHidrawDevices(t, []string{"hidraw0"}, func() {
		token := luks.Token{
			Type:    "systemd-fido2",
			ID:      0,
			Slots:   []int{2},
			Payload: makeFido2TokenPayload(t, credID, []byte("salt"), "io.systemd.cryptsetup", true, true, false),
		}
		_, err := recoverSystemdFido2Password(context.Background(), token, "cryptroot")
		require.ErrorIs(t, err, errFido2Skipped, "expected errFido2Skipped on empty PIN")
		require.Zero(t, fake.assertionCalls, "expected zero assertion calls when user skips")
		require.Equal(t, 1, resp.calls, "expected exactly one PIN prompt")
	})
}

// TestEagerPromptSkipsWhenNoMatchingDevice: pre-flight gate at the top of
// the loop. When no connected hidraw holds this token's credential, the
// function must return errFido2FallbackToKeyboard immediately without ever
// firing the PIN prompt — typing a PIN for a key that can't validate it is
// pure wasted UX. Reproduces the multi-Yubikey scenario where token #0 is
// enrolled to a key not currently inserted; the user shouldn't have to
// empty-Enter through a dead prompt to reach token #1.
func TestEagerPromptSkipsWhenNoMatchingDevice(t *testing.T) {
	credID := []byte("our-credential")
	fake := &fakeFidoForPreflight{presentCreds: map[string]bool{}} // nothing present
	installFakeFido2Plugin(t, fake)
	resp := withFakeFido2Pin(t, []string{}) // no replies expected — no prompt fires

	withFakeHidrawDevices(t, []string{}, func() {
		token := luks.Token{
			Type:    "systemd-fido2",
			ID:      0,
			Slots:   []int{2},
			Payload: makeFido2TokenPayload(t, credID, []byte("salt"), "io.systemd.cryptsetup", true, true, false),
		}
		_, err := recoverSystemdFido2Password(context.Background(), token, "cryptroot")
		require.ErrorIs(t, err, errFido2FallbackToKeyboard, "expected fallback when credential not on any connected device")
		require.Zero(t, resp.calls, "expected zero PIN prompts when no device holds the credential")
		require.Zero(t, fake.assertionCalls, "expected zero assertion calls")
	})
}

// TestEagerPromptInvalidPinExhaustsAt3Attempts: assertion returns PIN-invalid
// three times in a row. The function reprompts after attempts 1 and 2 with a
// "PIN incorrect" prefix, and bails to keyboard fallback after the 3rd. Only
// assertion calls that actually attempted with a PIN count toward the cap.
func TestEagerPromptInvalidPinExhaustsAt3Attempts(t *testing.T) {
	credID := []byte("our-credential")
	pinErr := errors.New("pin invalid sentinel")
	fake := &fakeFidoForPreflight{
		presentCreds: map[string]bool{"/dev/hidraw0:" + string(credID): true},
		assertionFn: func(call int, devPath, pin string) ([]byte, error) {
			return nil, pinErr // always wrong
		},
		pinInvalidFn: func(err error) bool { return errors.Is(err, pinErr) },
	}
	installFakeFido2Plugin(t, fake)
	resp := withFakeFido2Pin(t, []string{"1111", "2222", "3333"})

	withFakeHidrawDevices(t, []string{"hidraw0"}, func() {
		token := luks.Token{
			Type:    "systemd-fido2",
			ID:      0,
			Slots:   []int{2},
			Payload: makeFido2TokenPayload(t, credID, []byte("salt"), "io.systemd.cryptsetup", true, true, false),
		}
		_, err := recoverSystemdFido2Password(context.Background(), token, "cryptroot")
		require.ErrorIs(t, err, errFido2FallbackToKeyboard, "expected errFido2FallbackToKeyboard after PIN attempts exhausted")
		require.Equal(t, 3, fake.assertionCalls, "expected exactly 3 assertion calls (PIN cap)")
		require.Equal(t, 3, resp.calls, "expected exactly 3 PIN prompts")
		require.Contains(t, resp.prompts[1], "PIN incorrect", "expected second prompt to include 'PIN incorrect'")
	})
}

// TestEagerPromptFiresPromptBeforeUsbhidReady: the eager-prompt path must
// surface a PIN prompt without waiting on the usbhid uevent, so the user can
// type as soon as pre-flight green-lights the connected key. Regression
// guard: previous revisions called waitForUsbhid up-front, which in QEMU
// (no USB HID device → no usbhid uevent → usbhidReady never closes) blocked
// the goroutine until tokenTimeout, defeating the entire feature.
func TestEagerPromptFiresPromptBeforeUsbhidReady(t *testing.T) {
	// Force a fresh, never-closed usbhidReady for this test (other tests in
	// the package close it as a side effect, so we cannot rely on initial
	// state).
	prevUsbhid := usbhidReady
	usbhidReady = make(chan struct{})
	t.Cleanup(func() { usbhidReady = prevUsbhid })

	credID := []byte("our-credential")
	fake := &fakeFidoForPreflight{
		presentCreds: map[string]bool{"/dev/hidraw0:" + string(credID): true},
	}
	installFakeFido2Plugin(t, fake)
	resp := withFakeFido2Pin(t, []string{""}) // empty Enter → errFido2Skipped

	withFakeHidrawDevices(t, []string{"hidraw0"}, func() {
		token := luks.Token{
			Type:    "systemd-fido2",
			ID:      0,
			Slots:   []int{2},
			Payload: makeFido2TokenPayload(t, credID, []byte("salt"), "io.systemd.cryptsetup", true, true, false),
		}
		done := make(chan error, 1)
		go func() {
			_, err := recoverSystemdFido2Password(context.Background(), token, "cryptroot")
			done <- err
		}()
		select {
		case err := <-done:
			require.ErrorIs(t, err, errFido2Skipped, "expected errFido2Skipped on empty PIN")
		case <-time.After(time.Second):
			require.Fail(t, "eager-prompt blocked waiting for usbhid — PIN prompt never fired")
		}
		require.Equal(t, 1, resp.calls, "expected exactly one PIN prompt")
	})
}

// TestEagerPromptHappyPath: device present at function entry, PIN correct on
// first try → single prompt, single assertion, success.
func TestEagerPromptHappyPath(t *testing.T) {
	credID := []byte("our-credential")
	fake := &fakeFidoForPreflight{
		presentCreds: map[string]bool{"/dev/hidraw0:" + string(credID): true},
	}
	installFakeFido2Plugin(t, fake)
	resp := withFakeFido2Pin(t, []string{"1234"})

	withFakeHidrawDevices(t, []string{"hidraw0"}, func() {
		token := luks.Token{
			Type:    "systemd-fido2",
			ID:      0,
			Slots:   []int{2},
			Payload: makeFido2TokenPayload(t, credID, []byte("salt"), "io.systemd.cryptsetup", true, true, false),
		}
		_, err := recoverSystemdFido2Password(context.Background(), token, "cryptroot")
		require.NoError(t, err, "expected unlock to succeed")
		require.Equal(t, 1, resp.calls, "expected exactly 1 PIN prompt")
		require.Equal(t, 1, fake.assertionCalls, "expected exactly 1 assertion call")
	})
}
