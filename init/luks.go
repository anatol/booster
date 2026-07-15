package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anatol/clevis.go"
	"github.com/anatol/luks.go"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/sys/unix"
)

// specifies information needed to process/open a LUKS device
// often these mappings specified by a user via command-line
type luksMapping struct {
	ref             *deviceRef
	name            string
	keyfile         string
	options         []string
	header          string        // detached LUKS header path (empty = embedded header)
	headerDeviceRef *deviceRef    // non-nil when header is a file on a separate device
	dataDeviceRef   *deviceRef    // non-nil when rd.luks.data= pins the data device (detached-header multi-device)
	tokenTimeout    time.Duration // how long to wait for tokens before also starting keyboard; 0 = wait forever

	// tokenTimeoutExplicit is set when tokenTimeout came from an explicit
	// crypttab/cmdline token-timeout= (not the implicit 30s default). It lets
	// luksOpen know whether a booster.yaml token_timeout or the serialize-mode
	// derived sum may be substituted instead.
	tokenTimeoutExplicit bool

	keyfileDeviceRef *deviceRef    // non-nil when keyfile is on a separate device
	keyfileTimeout   time.Duration // device wait timeout for keyfile device (0 = use MountTimeout)

	keySlot       int   // -1 = all slots; >=0 restricts unlock to that slot
	tries         int   // 0 = unlimited keyboard retries; >0 = max attempts
	noFail        bool  // non-fatal unlock failure — boot continues on error
	keyfileOffset int64 // bytes to skip at start of keyfile
	keyfileSize   int64 // max bytes to read from keyfile (0 = all)

	// measurePCR is the tpm2-measure-pcr= setting for the PCR15 latch.
	// Zero value = measurePCRAuto (extend iff a token binds PCR15).
	measurePCR measurePCRSetting

	// tpm2Signature is the tpm2-signature= setting (signed PCR policy): a path to
	// a systemd PCR signature JSON, "false" to disable, or "" to auto-discover.
	tpm2Signature string
}

// tryPassphraseAgainstSlots tries password against each slot, sending the opened
// volume on volumes if successful.  Returns true on success.
func tryPassphraseAgainstSlots(ctx context.Context, volumes chan *luks.Volume, d luks.Device, checkSlots []int, password []byte) bool {
	for _, s := range checkSlots {
		v, err := d.UnsealVolume(s, password)
		if err == luks.ErrPassphraseDoesNotMatch {
			continue
		} else if err != nil {
			warning("unlocking slot %v: %v", s, err)
			continue
		}
		select {
		case volumes <- v:
		case <-ctx.Done():
		}
		return true
	}
	return false
}

// passphraseCache holds passwords that successfully unlocked a LUKS volume during
// this boot, so subsequent volumes (e.g. btrfs RAID1 members) can be tried
// automatically without prompting the user again.
//
// Ownership/wipe rule: a successful passphrase is appended here BY REFERENCE and
// is thereafter owned by the cache — read sites must not wipe it. The cache is
// scrubbed once, at the boot exits, by wipeSecretCache(). Only unowned secrets
// (failed attempts, consumed PINs) are wiped at their read site.
var passphraseCache struct {
	sync.Mutex
	passwords [][]byte
}

// keyboardMu serializes keyboard password prompts across concurrent luksOpen calls.
// Without this, two devices unlocked simultaneously (e.g. root + swap LUKS, or
// btrfs RAID1 members) both check passphraseCache before either has stored a
// successful password, causing a double prompt. Holding the mutex ensures the
// second device re-checks the cache after the first has finished prompting and
// stored its passphrase.
var keyboardMu sync.Mutex

// pendingPrompts holds the set of keyboard prompts currently awaiting a
// passphrase. Out-of-band password sources (SSH remote unlock) submit through
// this registry so they share the unlock orchestration (ctx cancellation,
// passphraseCache seeding) with the local keyboard path rather than walking
// devices themselves.
var pendingPrompts struct {
	sync.Mutex
	entries map[*promptRegistration]struct{}
}

type promptRegistration struct {
	ctx context.Context
	// cancel is luksOpen's own cancel — calling it ends this device's unlock
	// orchestration (same effect as a token-success cancel). SSH submissions
	// invoke it after a successful UnsealVolume so pendingDeviceNames stops
	// listing the device on the very next prompt-loop iteration. Without it,
	// the entry lingers until luksOpen returns past SetupMapper (~tens of ms),
	// and the next prompt redundantly names the already-unlocked device.
	cancel      context.CancelFunc
	volumes     chan *luks.Volume
	d           luks.Device
	checkSlots  []int
	mappingName string
	// inflight counts goroutines that submitted via trySubmitPassphraseToPending
	// (today: SSH remote unlock) and may still be mid-UnsealVolume after
	// senderWg.Wait() returns. luksOpen's watcher waits on this before
	// close(volumes) so the goroutine can't send on a closed channel and
	// panic pid 1.
	inflight sync.WaitGroup
}

func registerPendingPrompt(p *promptRegistration) {
	pendingPrompts.Lock()
	defer pendingPrompts.Unlock()
	if pendingPrompts.entries == nil {
		pendingPrompts.entries = make(map[*promptRegistration]struct{})
	}
	pendingPrompts.entries[p] = struct{}{}
}

func unregisterPendingPrompt(p *promptRegistration) {
	pendingPrompts.Lock()
	defer pendingPrompts.Unlock()
	delete(pendingPrompts.entries, p)
}

// trySubmitPassphraseToPending tries password against every currently-pending
// keyboard prompt and returns the names of devices that unlocked. UnsealVolume
// is dispatched in parallel — argon2 KDF runs concurrently across devices
// rather than serially, so a single submission against N volumes finishes in
// ~one KDF window instead of N. Without this, the keyboard prompt for a
// not-yet-attempted device briefly displays while SSH works through the rest
// of the queue.
//
// The passphrase is appended to passphraseCache when at least one device
// matches, so subsequent volumes with the same key (e.g. btrfs RAID1 members)
// unlock without further prompts.
func trySubmitPassphraseToPending(password []byte) []string {
	pendingPrompts.Lock()
	snapshot := make([]*promptRegistration, 0, len(pendingPrompts.entries))
	for p := range pendingPrompts.entries {
		if p.ctx.Err() != nil {
			continue
		}
		// Bump inflight under the same lock that owns entries — luksOpen's
		// watcher takes this lock to remove the entry before waiting on
		// inflight, so a snapshot-then-spawn that races the close-volumes
		// path can't sneak in unaccounted.
		p.inflight.Add(1)
		snapshot = append(snapshot, p)
	}
	pendingPrompts.Unlock()

	var (
		mu       sync.Mutex
		unlocked []string
		wg       sync.WaitGroup
	)
	for _, p := range snapshot {
		wg.Go(func() {
			defer p.inflight.Done()
			if tryPassphraseAgainstSlots(p.ctx, p.volumes, p.d, p.checkSlots, password) {
				// Dismiss this device's unlock orchestration now that the
				// volume is in hand — mirrors the token-success cancel.
				// pendingDeviceNames filters by ctx.Err(), so the next
				// sshPromptLoop iteration won't re-list this device while
				// luksOpen is still finishing SetupMapper.
				p.cancel()
				mu.Lock()
				unlocked = append(unlocked, p.mappingName)
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	if len(unlocked) > 0 {
		passphraseCache.Lock()
		passphraseCache.passwords = append(passphraseCache.passwords, password)
		passphraseCache.Unlock()
	}
	return unlocked
}

// pendingDeviceNames returns a sorted snapshot of mapping names currently
// registered for unlock whose ctx is still live. Used by the SSH prompt so
// the operator can see which devices a submission will be broadcast against,
// and so the loop can detect "everything unlocked" and disconnect cleanly.
func pendingDeviceNames() []string {
	pendingPrompts.Lock()
	names := make([]string, 0, len(pendingPrompts.entries))
	for p := range pendingPrompts.entries {
		if p.ctx.Err() != nil {
			continue
		}
		names = append(names, p.mappingName)
	}
	pendingPrompts.Unlock()
	sort.Strings(names)
	return names
}

// rd luks options match systemd naming https://www.freedesktop.org/software/systemd/man/crypttab.html
var rdLuksOptions = map[string]string{
	"discard":                luks.FlagAllowDiscards,
	"same-cpu-crypt":         luks.FlagSameCPUCrypt,
	"submit-from-crypt-cpus": luks.FlagSubmitFromCryptCPUs,
	"no-read-workqueue":      luks.FlagNoReadWorkqueue,
	"no-write-workqueue":     luks.FlagNoWriteWorkqueue,
}

// ctxSleep blocks for d, or returns ctx.Err() as soon as ctx is done, whichever
// comes first. Used to make fixed waits (clevis network-retry backoff, the
// concurrent-mode PIN-prompt pre-delay) abort immediately on a cancel-on-win or
// a serialize-mode per-token timeout instead of sleeping out the full duration.
func ctxSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// waitForUsbhid is the ctx-aware counterpart of usbhidReady. Returns ctx.Err()
// if ctx is cancelled before the first usbhid bind event closes the channel.
func waitForUsbhid(ctx context.Context) error {
	select {
	case <-usbhidReady:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// acquireFido2Lock takes the FIDO2 user-interaction lock. Returns ctx.Err()
// if ctx is cancelled while waiting for the slot.
func acquireFido2Lock(ctx context.Context) error {
	select {
	case fido2Sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func releaseFido2Lock() { <-fido2Sem }

func recoverClevisPassword(ctx context.Context, t luks.Token, luksVersion int) ([]byte, error) {
	var payload []byte
	// Note that token metadata stored differently in LUKS v1 and v2
	if luksVersion == 1 {
		payload = t.Payload
	} else {
		var node struct {
			Jwe json.RawMessage
		}
		if err := json.Unmarshal(t.Payload, &node); err != nil {
			return nil, err
		}
		payload = node.Jwe
	}

	deadline := time.Now().Add(60 * time.Second) // wait for network readiness for 60 seconds max
	waitedForTpm := false
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		password, err := clevis.Decrypt(payload)
		if err != nil {
			var netError *net.OpError
			if errors.Is(err, fs.ErrNotExist) && !waitedForTpm {
				waitedForTpm = true
				// the tpm device might not be ready yet
				// wait max 3 seconds until it is ready
				if tpmAwaitReady() {
					// the tpm is now available, so try again
					continue
				} else {
					// timed out waiting for tpm
					return nil, err
				}
			} else if strings.Contains(err.Error(), "USB error") {
				// USB device not yet ready (e.g. YubiKey still enumerating).
				if time.Now().After(deadline) {
					return nil, fmt.Errorf("timeout waiting for USB device")
				}
				if err := ctxSleep(ctx, 500*time.Millisecond); err != nil {
					return nil, err
				}
				continue
			} else if !errors.As(err, &netError) {
				return nil, err
			}

			// it takes a bit of time to initialize network and DHCP
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timeout waiting for network")
			}
			// else let's sleep and retry
			if err := ctxSleep(ctx, time.Second); err != nil {
				return nil, err
			}
			continue
		}

		return password, nil
	}
}

// hidrawSysPath is the directory enumerated for FIDO2 HID devices. Overridden
// by tests via withFakeHidrawDevices.
var hidrawSysPath = "/sys/class/hidraw/"

func isHidRawFido2(devName string) (bool, error) {
	descriptor, err := os.ReadFile(hidrawSysPath + devName + "/device/report_descriptor")
	if err != nil {
		return false, fmt.Errorf("unable to read HID descriptor for %s", devName)
	}
	lenDescriptor := len(descriptor)
	for id := 0; id < lenDescriptor; id++ {
		itemPrefix := descriptor[id]
		itemSize := itemPrefix & 0b11
		// References:
		// - libfido2 checks Usage Page against 0xd0f1 (FIDO Alliance):
		//     https://github.com/Yubico/libfido2/blob/03c18d396eb209a42bbf62f5f4415203cba2fc50/src/hid_hidapi.c#L146
		// - HID specification 6.2.2.7 Global Item, Usage Page prefix format is 0000 01 nn, nn = length
		//     https://www.usb.org/sites/default/files/hid1_11.pdf
		if itemPrefix&0b11111100 == 0b00000100 &&
			itemSize == 2 &&
			id+2 < lenDescriptor &&
			descriptor[id+1] == 0xd0 && //
			descriptor[id+2] == 0xf1 {
			return true, nil
		}
		id += int(itemSize)
	}

	return false, nil
}

func recoverFido2Password(ctx context.Context, devName string, credID []byte, salt string, relyingParty string, pinRequired bool, userPresenceRequired bool, userVerificationRequired bool, mappingName string, promptPrefix string) ([]byte, error) {
	if err := waitForUsbhid(ctx); err != nil {
		info("FIDO2 unlock for %s cancelled before USB HID ready: %v", mappingName, err)
		return nil, err
	}

	// Defence in depth: recoverSystemdFido2Password pre-filters via
	// isHidRawFido2 + pre-flight, so the !isFido2 branch is unreachable in
	// normal flow. Kept to fail safely if a future caller skips the filter.
	isFido2, err := isHidRawFido2(devName)
	if err != nil {
		return nil, fmt.Errorf("unable to check whether %s is a FIDO2 device", devName)
	}
	if !isFido2 {
		return nil, fmt.Errorf("HID %s is not a FIDO2 device", devName)
	}

	if err := acquireFido2Lock(ctx); err != nil {
		info("FIDO2 unlock for %s cancelled waiting for assertion lock: %v", mappingName, err)
		return nil, err
	}
	defer releaseFido2Lock()

	if plymouthEnabled {
		plymouthMessage("") // clear "No FIDO2 device found" now that we have one and the lock
	}

	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt: %v", err)
	}

	var pin string
	if pinRequired {
		prompt := promptPrefix + "Enter FIDO2 PIN for " + mappingName + " (empty to skip):"
		pinBytes, err := askPasswordWithFallback(ctx, prompt, "")
		if err != nil {
			return nil, err
		}
		pin = string(pinBytes)
	}

	if pinRequired && pin == "" {
		return nil, errFido2Skipped
	}

	notifyTouch := func() {
		statusMessage("Please touch the FIDO2 key for " + mappingName)
	}

	result, err := fido2Assertion("/dev/"+devName, credID, saltBytes, relyingParty, pin, pinRequired, userPresenceRequired, userVerificationRequired, notifyTouch)
	if err != nil && isFido2PinInvalidError(err) {
		return nil, errFido2PinInvalid
	}
	if err != nil && isFido2WrongDeviceError(err) {
		return nil, errFido2WrongDevice
	}
	if err != nil && isFido2PinRequiredError(err) {
		return nil, errFido2PinNeeded
	}
	if err != nil && isFido2TouchTimeoutError(err) {
		return nil, errFido2TouchTimeout
	}
	if err == nil {
		statusMessage("")
	}
	return result, err
}

// hidraw udev events are broadcast to every registered listener so multiple
// FIDO2 tokens (e.g. one PIN-required, one touchless against the same physical
// device) observe device-add events independently. A single shared channel
// would let the first reader steal the event from siblings.
var (
	hidrawListenersMu sync.Mutex
	hidrawListeners   []chan string
)

// Caller must invoke the returned drop function when done so the listener
// doesn't accumulate in the registry.
func registerHidrawListener() (chan string, func()) {
	ch := make(chan string, 16)
	hidrawListenersMu.Lock()
	hidrawListeners = append(hidrawListeners, ch)
	hidrawListenersMu.Unlock()
	return ch, func() {
		hidrawListenersMu.Lock()
		defer hidrawListenersMu.Unlock()
		for i, c := range hidrawListeners {
			if c == ch {
				hidrawListeners = append(hidrawListeners[:i], hidrawListeners[i+1:]...)
				return
			}
		}
	}
}

// Non-blocking per listener: a slow consumer with a full buffer drops the
// event for itself only — siblings still receive it.
func broadcastHidrawDevice(name string) {
	hidrawListenersMu.Lock()
	defer hidrawListenersMu.Unlock()
	for _, ch := range hidrawListeners {
		select {
		case ch <- name:
		default:
		}
	}
}

// fido2Sem serializes FIDO2 user interactions (PIN prompt + touch + assertion)
// across all goroutines. The FIDO2 key can only service one assertion at a
// time, and concurrent goroutines (e.g. multiple systemd-fido2 tokens or
// multiple LUKS devices) would otherwise interleave PIN prompts and touch
// messages. Channel-as-semaphore so acquire is ctx-cancellable.
var fido2Sem = make(chan struct{}, 1)

// fido2NoDeviceMsgOnce dedups the "No FIDO2 device found" status across
// goroutines unlocking the same mapping. Multi-FIDO2-token pinless
// enrollments invoke recoverSystemdFido2Password once per token; each
// arms the no-device timer, but only the first to fire emits the hint.
var fido2NoDeviceMsgOnce sync.Map // mappingName → *sync.Once

// Push a touchless FIDO2 device back into the goroutine's own listener channel
// so the loop retries — the user can then touch the token at any point during
// boot, including while a passphrase prompt is showing, and the unlock succeeds.
//
// Gates (silently no-op if any fail):
//   - pinRequired: PIN tokens have already engaged the user via prompt;
//     re-seeding them silently would be confusing.
//   - elapsed > 1s: bounds hot-loops on fast-fail errors (immediate libfido2
//     rejections that return in microseconds would otherwise spin).
//   - ctx not done: don't re-seed if a sibling token has already won.
func reseedTouchlessFido2(ctx context.Context, listener chan string, devName string, seen set, pinRequired bool, elapsed time.Duration) error {
	if pinRequired || elapsed <= time.Second {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	seen[devName] = false
	select {
	case listener <- devName:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var errFido2Skipped = errors.New("FIDO2 skipped by user")
var errFido2PinInvalid = errors.New("FIDO2 PIN invalid")
var errFido2WrongDevice = errors.New("FIDO2 device does not have our credential")
var errFido2PinNeeded = errors.New("FIDO2 device requires PIN we did not supply")
var errFido2TouchTimeout = errors.New("FIDO2 touch timed out")
var errFido2FallbackToKeyboard = errors.New("FIDO2 falling back to keyboard")
var errTPM2Skipped = errors.New("TPM2 skipped by user")

// askFido2Pin is the prompt entry point for FIDO2 PIN entry. Indirected
// through a package var so tests can substitute a deterministic responder
// without standing up plymouth or a console TTY.
var askFido2Pin = askPasswordWithFallback

func recoverSystemdFido2Password(ctx context.Context, t luks.Token, mappingName string) ([]byte, error) {
	var node struct {
		Credential               string `json:"fido2-credential"` // base64
		Salt                     string `json:"fido2-salt"`       // base64
		RelyingParty             string `json:"fido2-rp"`
		PinRequired              bool   `json:"fido2-clientPin-required"`
		UserPresenceRequired     bool   `json:"fido2-up-required"`
		UserVerificationRequired bool   `json:"fido2-uv-required"`
	}
	if err := json.Unmarshal(t.Payload, &node); err != nil {
		return nil, err
	}

	if node.RelyingParty == "" {
		node.RelyingParty = "io.systemd.cryptsetup"
	}

	credID, err := base64.StdEncoding.DecodeString(node.Credential)
	if err != nil {
		return nil, fmt.Errorf("invalid credential: %v", err)
	}

	// Eager PIN prompt for PIN-required tokens. Token metadata tells us a PIN
	// is enrolled; ask now instead of waiting for device discovery. Lets the
	// user empty-Enter to skip — breaks the serial-dispatcher deadlock where
	// a missing FIDO2 device parks the loop and the next PIN-bearing token
	// (e.g. TPM2-PIN) never gets prompted.
	if node.PinRequired {
		return recoverFido2WithEagerPrompt(ctx, mappingName, credID, node.Salt, node.RelyingParty, node.UserPresenceRequired, node.UserVerificationRequired)
	}

	// Register BEFORE reading /sys/class/hidraw so any 'add' events arriving
	// during/after the scan are buffered. We deliberately do NOT block on
	// waitForUsbhid here: on usbhid-less configs (QEMU without USB,
	// embedded systems, laptops with only PS2/i2c HID) usbhidReady never
	// closes, and blocking would prevent the deferred "No FIDO2 device
	// found" timer below from ever arming. A late-arriving usbhid bind
	// surfaces its hidraw through the listener channel.
	hidrawDevices, dropListener := registerHidrawListener()
	defer dropListener()

	dir, err := os.ReadDir(hidrawSysPath)
	if err != nil {
		return nil, err
	}

	seedDone := make(chan struct{})
	stopSeeding := make(chan struct{})
	defer close(stopSeeding)
	go func() {
		defer close(seedDone)
		for _, d := range dir {
			select {
			case hidrawDevices <- d.Name():
			case <-stopSeeding:
				return
			}
		}
	}()

	seenHidrawDevices := make(set)

	// "No FIDO2 device found" hint, delayed tokenTimeout/2 with 10s floor:
	// a fast non-interactive token (TPM2, clevis) should win silently before
	// the hint fires. PIN-required tokens use the eager-prompt path above.
	var noDeviceC <-chan time.Time
	if len(dir) == 0 && (plymouthEnabled || verbosityLevel >= levelInfo) {
		delay := 30 * time.Second
		if config.TokenTimeout > 0 {
			delay = time.Duration(config.TokenTimeout) * time.Second
		}
		if delay /= 2; delay < 10*time.Second {
			delay = 10 * time.Second
		}
		noDeviceTimer := time.NewTimer(delay)
		defer noDeviceTimer.Stop()
		noDeviceC = noDeviceTimer.C
	}

	var (
		uniqueDevicesProcessed int // unique hidraws filtered through pre-flight; converges to len(dir) once seed drains
		matchedAtLeastOne      bool
	)
	for {
		// Bail with errFido2FallbackToKeyboard once we've exhausted the
		// initial enumeration with no credential match — lets the
		// dispatcher advance to the next token (TPM2-PIN, passphrase,
		// etc.) instead of parking on the channel waiting for a hidraw
		// event that may never arrive. The keyboard prompt only fires
		// after all tokens are exhausted (or tokenTimeout elapses).
		// The len(dir) > 0 guard preserves the empty-hidraw case: with
		// nothing enumerated, the user may still plug a key in — keep
		// waiting for udev. Late hot-plugs arriving between the gate
		// firing and dropListener running are dropped; the serial
		// dispatcher's tokenTimeout bounds the wait either way.
		select {
		case <-seedDone:
			if len(dir) > 0 && uniqueDevicesProcessed >= len(dir) && !matchedAtLeastOne {
				return nil, errFido2FallbackToKeyboard
			}
		default:
		}

		var devName string
		select {
		case <-ctx.Done():
			// serialize-mode per-token timeout (or cancel-on-win) fired
			// while waiting for a FIDO2 device to appear — stop waiting.
			return nil, ctx.Err()
		case <-noDeviceC:
			// Dedup across goroutines for the same mapping (multi-FIDO2-token
			// pinless enrollment): each token's recoverSystemdFido2Password
			// arms its own timer, but only the first to fire emits the hint.
			v, _ := fido2NoDeviceMsgOnce.LoadOrStore(mappingName, &sync.Once{})
			v.(*sync.Once).Do(func() {
				statusMessage("No FIDO2 device found for " + mappingName + ", insert security key or wait for passphrase prompt")
			})
			noDeviceC = nil
			continue
		case devName = <-hidrawDevices:
			// A device arrived: suppress the empty-state message. Without
			// this nil-out, a timer expiry queued while we were processing
			// an earlier device would fire on a subsequent loop iteration
			// and tell the user "no FIDO2 device found" while a key is
			// plugged in.
			noDeviceC = nil
		}
		if seenHidrawDevices[devName] {
			continue
		}
		seenHidrawDevices[devName] = true
		uniqueDevicesProcessed++

		isFido2, err := isHidRawFido2(devName)
		if err != nil {
			info("unable to check whether %s is a FIDO2 device: %v", devName, err)
			continue
		}
		if !isFido2 {
			info("HID %s is not a FIDO2 device", devName)
			continue
		}

		// Silent-skip when pre-flight rejects: users with multiple FIDO2
		// keys plugged in shouldn't see the wrong key's PIN prompt. See
		// fido2iface.Fido2Preflight for the no-PIN-consumed semantics.
		devPath := "/dev/" + devName
		present, err := fido2Preflight(devPath, credID, node.RelyingParty, node.UserVerificationRequired)
		if err != nil {
			info("FIDO2 pre-flight on %s failed: %v", devName, err)
			continue
		}
		if !present {
			debug("FIDO2 device %s does not have our credential, skipping", devName)
			continue
		}
		matchedAtLeastOne = true

		info("HID %s supports FIDO and has our credential, attempting unlock", devName)

		// pinRequired starts from credential metadata but may be flipped on if
		// the device returns FIDO_ERR_PIN_REQUIRED — i.e. metadata said no PIN
		// but the token has had one set since enrollment (firmware update,
		// policy change). On the flip we re-prompt without consuming an attempt.
		pinRequired := node.PinRequired
		maxAttempts := 1
		if pinRequired {
			maxAttempts = 3
		}
		var password []byte
		pinExhausted := false
		promptPrefix := ""
		attempt := 0
		assertStart := time.Now() // for reseedTouchlessFido2's elapsed gate
		for attempt < maxAttempts {
			password, err = recoverFido2Password(ctx, devName, credID, node.Salt, node.RelyingParty, pinRequired, node.UserPresenceRequired, node.UserVerificationRequired, mappingName, promptPrefix)
			if err == nil {
				break
			}
			if errors.Is(err, errFido2PinNeeded) && !pinRequired {
				pinRequired = true
				maxAttempts = 3
				promptPrefix = "FIDO2 token requires PIN — "
				continue
			}
			// Touch timeout on a PIN device: re-prompt without consuming an
			// attempt. The user typed the PIN correctly but didn't touch in
			// time; making them lose 1 of 3 attempts for a fumbled tap is
			// hostile.
			if errors.Is(err, errFido2TouchTimeout) && pinRequired {
				promptPrefix = "FIDO2 touch timed out — "
				continue
			}
			if !errors.Is(err, errFido2PinInvalid) {
				break
			}
			attempt++
			if attempt >= maxAttempts {
				pinExhausted = true
			} else {
				promptPrefix = "FIDO2 PIN incorrect — "
			}
		}

		if err != nil {
			if errors.Is(err, errFido2Skipped) || pinExhausted {
				break // passphrase prompt is self-explanatory
			}
			if isFido2PinAuthBlockedError(err) {
				statusMessageIfPrompt("FIDO2 PIN auth blocked (too many wrong attempts), falling back to passphrase")
				break
			}
			if isFido2PinBlockedError(err) {
				statusMessageIfPrompt("FIDO2 PIN is blocked (reset required), falling back to passphrase")
				break
			}
			// Safety net only — pre-flight should have prevented us getting
			// here. If we somehow attempted against a device that lacked the
			// credential, keep moving and let other devices be tried.
			if errors.Is(err, errFido2WrongDevice) {
				debug("FIDO2 device %s rejected credential at assertion time (pre-flight skew?), skipping", devName)
				continue
			}
			info("%v", err)
			// Private re-seed (not broadcast): sibling FIDO2 goroutines already
			// tracked the device in their own seenHidrawDevices, so broadcasting
			// would be a no-op for them.
			if reseedErr := reseedTouchlessFido2(ctx, hidrawDevices, devName, seenHidrawDevices, pinRequired, time.Since(assertStart)); reseedErr != nil {
				return nil, reseedErr
			}
			continue
		}
		return password, nil
	}

	return nil, errFido2FallbackToKeyboard
}

// recoverFido2WithEagerPrompt drives a PIN-required FIDO2 token by asking
// for the PIN from token metadata BEFORE scanning for a device. On each
// submission we rescan /sys/class/hidraw and pre-flight every FIDO2-capable
// entry for the token's credential; if none match we reprompt with a
// "device not detected" prefix so the user can plug a key in and retype.
// Empty Enter returns errFido2Skipped, which the serial dispatcher uses to
// advance to the next PIN-bearing token (TPM2-PIN) without waiting on a
// device that never arrives.
//
// PIN attempts are bounded at 3 — only assertion calls that consumed a PIN
// attempt count toward the cap. "Device not detected" reprompts and touch
// timeouts do not.
func recoverFido2WithEagerPrompt(ctx context.Context, mappingName string, credID []byte, salt, relyingParty string, userPresenceRequired, userVerificationRequired bool) ([]byte, error) {
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt: %v", err)
	}

	// No waitForUsbhid: findMatchingFido2Device below rescans /sys/class/hidraw
	// on every iteration, so a late-arriving key is picked up next round.

	if err := acquireFido2Lock(ctx); err != nil {
		info("FIDO2 unlock for %s cancelled waiting for assertion lock: %v", mappingName, err)
		return nil, err
	}
	defer releaseFido2Lock()

	const maxPinAttempts = 3
	promptPrefix := ""
	pinAttempts := 0

	for {
		// Pre-flight first so we never fire the PIN prompt for a token
		// whose enrolled key isn't on any connected hidraw — the user
		// shouldn't be asked to type a PIN that can't go anywhere. Also
		// catches a device that gets unplugged mid-prompt: the next
		// iteration's pre-flight exits cleanly instead of reprompting.
		devName, err := findMatchingFido2Device(credID, relyingParty, userVerificationRequired)
		if err != nil {
			info("FIDO2 device discovery error: %v", err)
			return nil, errFido2FallbackToKeyboard
		}
		if devName == "" {
			return nil, errFido2FallbackToKeyboard
		}

		prompt := promptPrefix + "Enter FIDO2 PIN for " + mappingName + " (empty to skip):"
		pinBytes, err := askFido2Pin(ctx, prompt, "")
		if err != nil {
			return nil, err
		}
		if len(pinBytes) == 0 {
			return nil, errFido2Skipped
		}
		pin := string(pinBytes)

		notifyTouch := func() {
			statusMessage("Please touch the FIDO2 key for " + mappingName)
		}
		result, err := fido2Assertion("/dev/"+devName, credID, saltBytes, relyingParty, pin, true, userPresenceRequired, userVerificationRequired, notifyTouch)
		if err == nil {
			statusMessage("")
			return result, nil
		}

		if isFido2PinInvalidError(err) {
			pinAttempts++
			if pinAttempts >= maxPinAttempts {
				statusMessage("FIDO2 PIN attempts exhausted, falling back to passphrase")
				return nil, errFido2FallbackToKeyboard
			}
			promptPrefix = "FIDO2 PIN incorrect — "
			continue
		}
		if isFido2TouchTimeoutError(err) {
			// User typed PIN correctly but didn't touch in time — re-prompt
			// without consuming a PIN attempt.
			promptPrefix = "FIDO2 touch timed out — "
			continue
		}
		if isFido2WrongDeviceError(err) {
			// Pre-flight green-lit this device but assertion rejected the
			// credential. Could be a hot-plug race; retry by reprompting.
			debug("FIDO2 device %s rejected credential at assertion (pre-flight skew?)", devName)
			promptPrefix = "FIDO2 device rejected credential — "
			continue
		}
		if isFido2PinAuthBlockedError(err) {
			statusMessage("FIDO2 PIN auth blocked (too many wrong attempts), falling back to passphrase")
			return nil, errFido2FallbackToKeyboard
		}
		if isFido2PinBlockedError(err) {
			statusMessage("FIDO2 PIN is blocked (reset required), falling back to passphrase")
			return nil, errFido2FallbackToKeyboard
		}
		info("FIDO2 assertion failed: %v", err)
		return nil, errFido2FallbackToKeyboard
	}
}

// findMatchingFido2Device scans /sys/class/hidraw, filters by isHidRawFido2,
// and pre-flights each candidate for credID. Returns the first matching
// devName (e.g. "hidraw1"); returns "" with nil err when no device matches.
// Used by the eager-prompt flow to rescan at each PIN submission.
func findMatchingFido2Device(credID []byte, relyingParty string, userVerificationRequired bool) (string, error) {
	dir, err := os.ReadDir(hidrawSysPath)
	if err != nil {
		return "", err
	}
	for _, d := range dir {
		devName := d.Name()
		isFido2, ferr := isHidRawFido2(devName)
		if ferr != nil {
			info("unable to check whether %s is a FIDO2 device: %v", devName, ferr)
			continue
		}
		if !isFido2 {
			continue
		}
		present, ferr := fido2Preflight("/dev/"+devName, credID, relyingParty, userVerificationRequired)
		if ferr != nil {
			info("FIDO2 pre-flight on %s failed: %v", devName, ferr)
			continue
		}
		if present {
			return devName, nil
		}
	}
	return "", nil
}

// measurePCRSetting is the tpm2-measure-pcr= setting controlling the PCR15 latch.
type measurePCRSetting int

const (
	measurePCRAuto     measurePCRSetting = iota // unset: extend iff a token binds PCR15
	measurePCRForce                             // tpm2-measure-pcr=yes
	measurePCRDisabled                          // tpm2-measure-pcr=no
)

func (s measurePCRSetting) String() string {
	switch s {
	case measurePCRForce:
		return "yes"
	case measurePCRDisabled:
		return "no"
	default:
		return "auto"
	}
}

// parseMeasurePCR maps a tpm2-measure-pcr= value to its setting; ok is false for
// unrecognized values.
func parseMeasurePCR(val string) (setting measurePCRSetting, ok bool) {
	switch val {
	case "yes":
		return measurePCRForce, true
	case "no":
		return measurePCRDisabled, true
	}
	return measurePCRAuto, false
}

// tokenBindsPCR reports whether a systemd-tpm2 token's policy binds the given PCR.
func tokenBindsPCR(t luks.Token, pcr int) bool {
	if t.Type != "systemd-tpm2" {
		return false
	}
	var node struct {
		PCRs []int `json:"tpm2-pcrs"`
	}
	if err := json.Unmarshal(t.Payload, &node); err != nil {
		return false
	}
	for _, p := range node.PCRs {
		if p == pcr {
			return true
		}
	}
	return false
}

// tokenBindsPCR15 reports whether a systemd-tpm2 token binds PCR15 — the signal
// that the user enrolled the uninitialized-PCR15 latch.
func tokenBindsPCR15(t luks.Token) bool {
	return tokenBindsPCR(t, pcrSystemIdentity)
}

// latchMode is the outcome of the PCR15 latch decision: whether to extend, and
// whether a failure to extend must abort the unlock.
type latchMode int

const (
	latchNone     latchMode = iota // do not extend PCR15
	latchRequired                  // extend, fail-closed (the key is bound to PCR15)
	latchDefensive                 // extend, best-effort (no PCR15 token, but a TPM is present)
)

// volumeKeyLatchMode maps the unlock context to a latch mode. tpm2-measure-pcr=
// yes/no force required/none. Otherwise: required when a systemd-tpm2 token binds
// PCR15, defensive when no token binds PCR15 but a TPM is present, none when no
// TPM is present.
func volumeKeyLatchMode(tokens []luks.Token, setting measurePCRSetting, tpmPresent bool) latchMode {
	switch setting {
	case measurePCRForce:
		return latchRequired
	case measurePCRDisabled:
		return latchNone
	default:
		for _, t := range tokens {
			if tokenBindsPCR15(t) {
				return latchRequired
			}
		}
		if tpmPresent {
			return latchDefensive
		}
		return latchNone
	}
}

// unmarshalTPM2Field decodes a systemd-tpm2 token field that is normally a single
// JSON string but is a JSON array of strings when the token is sharded (a
// signed-PCR + pcrlock combined enrollment). It returns the first element and
// whether the field held more than one.
func unmarshalTPM2Field(raw json.RawMessage) (value string, sharded bool, err error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return "", false, nil
	}
	if raw[0] == '[' {
		var a []string
		if err := json.Unmarshal(raw, &a); err != nil {
			return "", false, err
		}
		if len(a) == 0 {
			return "", false, nil
		}
		return a[0], len(a) > 1, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, err
	}
	return s, false, nil
}

// readTPM2PINAuthValue prompts for a TPM2 PIN, derives the systemd-compatible
// auth value, and wipes the PIN bytes before returning. An empty PIN yields
// errTPM2Skipped so the caller falls through to the passphrase prompt.
func readTPM2PINAuthValue(ctx context.Context, prompt string, salt []byte) ([]byte, error) {
	pin, err := askKeyboardPassword(ctx, prompt, "")
	if err != nil {
		return nil, err
	}
	if len(pin) == 0 {
		return nil, errTPM2Skipped
	}
	authValue := tpm2PINAuthValue(pin, salt)
	wipe(pin)
	return authValue, nil
}

func recoverSystemdTPM2Password(ctx context.Context, t luks.Token, mappingName string, tpm2Signature string) ([]byte, error) {
	var node struct {
		Blob       json.RawMessage `json:"tpm2-blob"` // base64 string, or array of strings when sharded
		PCRs       []int           `json:"tpm2-pcrs"`
		PCRBank    string          `json:"tpm2-pcr-bank"`    // either sha1 or sha256
		PolicyHash json.RawMessage `json:"tpm2-policy-hash"` // hex string, or array when sharded
		Pin        bool            `json:"tpm2-pin"`
		Salt       string          `json:"tpm2_salt"`    // base64 random salt; systemd v255+ PIN tokens
		Srk        string          `json:"tpm2_srk"`     // base64 IESYS bytes; systemd v252+ tokens
		Pcrlock    bool            `json:"tpm2_pcrlock"` // sealed via PolicyAuthorizeNV; unsupported
	}
	if err := json.Unmarshal(t.Payload, &node); err != nil {
		return nil, err
	}

	// Reject sharded / pcrlock-bound tokens: booster can neither reconstruct a
	// sharded secret nor satisfy pcrlock's PolicyAuthorizeNV, so fail with a clear
	// message rather than a cryptic JSON-unmarshal error.
	blobStr, blobSharded, err := unmarshalTPM2Field(node.Blob)
	if err != nil {
		return nil, err
	}
	if node.Pcrlock || blobSharded {
		return nil, fmt.Errorf("tpm2 pcrlock-bound tokens are not supported")
	}
	blob, err := base64.StdEncoding.DecodeString(blobStr)
	if err != nil {
		return nil, err
	}
	private, public, err := parseSystemdTPM2Blob(blob)
	if err != nil {
		return nil, err
	}

	bank := parsePCRBank(node.PCRBank)

	var srkHandle tpmutil.Handle
	if node.Srk != "" {
		srkBytes, err := base64.StdEncoding.DecodeString(node.Srk)
		if err != nil {
			return nil, fmt.Errorf("tpm2_srk: %v", err)
		}
		srkHandle = extractSRKHandle(srkBytes)
	}

	// Signed (authorized) policy token (enrolled with --tpm2-public-key): its blob
	// is bound to the key via PolicyAuthorize, not literal PCR values. Detected by
	// tpm2_pubkey and routed to the signed-policy unseal in the loop below, which
	// shares the PIN prompt/retry so signed+PIN works the same as literal+PIN.
	verifyKey, pubkeyPCRs, signed, err := parseSignedToken(t.Payload)
	if err != nil {
		return nil, err
	}

	// tpm2-policy-hash is the precomputed literal-PCR policy digest; only the
	// literal path needs it (the signed path recomputes via PolicyGetDigest), so
	// decode and require it only when the token is not signed.
	var policyHash []byte
	if !signed {
		policyHashStr, _, err := unmarshalTPM2Field(node.PolicyHash)
		if err != nil {
			return nil, err
		}
		if policyHashStr == "" {
			return nil, fmt.Errorf("empty policy hash")
		}
		policyHash, err = hex.DecodeString(policyHashStr)
		if err != nil {
			return nil, err
		}
	}

	// A PCR11-bound signed policy is signed for the enter-initrd phase, so extend
	// it before the unseal (see ensureEnterInitrdBarrier). Fail closed.
	if signed && slices.Contains(pubkeyPCRs, pcrKernelBoot) {
		if err := ensureEnterInitrdBarrier(); err != nil {
			return nil, fmt.Errorf("applying enter-initrd PCR%d barrier: %v", pcrKernelBoot, err)
		}
	}

	var salt []byte
	if node.Salt != "" {
		var err error
		salt, err = base64.StdEncoding.DecodeString(node.Salt)
		if err != nil {
			return nil, fmt.Errorf("tpm2_salt: %v", err)
		}
	}

	maxAttempts := 1
	if node.Pin {
		maxAttempts = 3
	}
	promptPrefix := ""
	for attempt := 0; attempt < maxAttempts; attempt++ {
		var authValue []byte
		if node.Pin {
			prompt := promptPrefix + "Enter TPM2 PIN for " + mappingName + ":"
			authValue, err = readTPM2PINAuthValue(ctx, prompt, salt)
			if err != nil {
				return nil, err
			}
		}

		var password []byte
		if signed {
			password, err = recoverSignedTPM2Password(public, private, node.PCRBank, pubkeyPCRs, node.PCRs, verifyKey, uint32(srkHandle), tpm2Signature, authValue)
		} else {
			password, err = tpm2Unseal(public, private, node.PCRs, bank, policyHash, authValue, srkHandle)
		}
		// The TPM call has consumed authValue; scrub it on every path (a
		// wrong-PIN retry redeclares a fresh one next iteration). nil is a no-op.
		wipe(authValue)
		if err == nil {
			// Keep only the base64 form the caller uses; scrub the raw key.
			encoded := []byte(base64.StdEncoding.EncodeToString(password))
			wipe(password)
			return encoded, nil
		}
		if node.Pin && attempt < maxAttempts-1 {
			promptPrefix = "TPM2 PIN incorrect — "
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("TPM2 PIN incorrect")
}

func parseSystemdTPM2Blob(blob []byte) (private, public []byte, err error) {
	if len(blob) < 2 {
		return nil, nil, fmt.Errorf("invalid TPM2 blob: missing private section size")
	}
	privateSize := int(binary.BigEndian.Uint16(blob[:2]))
	blob = blob[2:]
	if len(blob) < privateSize+2 {
		return nil, nil, fmt.Errorf("invalid TPM2 blob: truncated private section")
	}
	private = blob[:privateSize]
	blob = blob[privateSize:]

	publicSize := int(binary.BigEndian.Uint16(blob[:2]))
	blob = blob[2:]
	if len(blob) < publicSize {
		return nil, nil, fmt.Errorf("invalid TPM2 blob: truncated public section")
	}
	public = blob[:publicSize]

	return private, public, nil
}

// tokenNeedsPin reports whether the token requires a typed PIN at the keyboard.
// PIN tokens are dispatched serially by a single goroutine in luksOpen so
// prompts never interleave; non-PIN tokens (clevis, PCR-only TPM2, touchless
// FIDO2) fan out in parallel and don't delay the keyboard passphrase fallback.
func tokenNeedsPin(t luks.Token) bool {
	switch t.Type {
	case "systemd-tpm2":
		var node struct {
			Pin bool `json:"tpm2-pin"`
		}
		if json.Unmarshal(t.Payload, &node) == nil {
			return node.Pin
		}
	case "systemd-fido2":
		var node struct {
			PinRequired bool `json:"fido2-clientPin-required"`
		}
		if json.Unmarshal(t.Payload, &node) == nil {
			return node.PinRequired
		}
	}
	return false
}

// secondsOr returns cfg seconds as a Duration, or def seconds when cfg is 0
// (unset). Used to resolve the per-token-type serialize-mode bounds.
func secondsOr(cfg, def int) time.Duration {
	if cfg > 0 {
		return time.Duration(cfg) * time.Second
	}
	return time.Duration(def) * time.Second
}

// perTokenTimeout returns the serialize-mode per-token bound for t, or 0 when t
// must not be auto-cancelled. PIN-bearing tokens (interactive — the user has
// the empty-Enter skip) and unknown token types are never bounded. Only used
// when SerializeTokens is set; in concurrent mode tokens race so a blocker
// can't starve siblings.
func perTokenTimeout(t luks.Token) time.Duration {
	if !config.SerializeTokens || tokenNeedsPin(t) {
		return 0
	}
	switch t.Type {
	case "clevis":
		return secondsOr(config.ClevisTimeout, 45)
	case "systemd-tpm2":
		return secondsOr(config.Tpm2Timeout, 15)
	case "systemd-fido2":
		return secondsOr(config.Fido2Timeout, 30)
	}
	return 0
}

// effectiveTokenTimeout resolves how long luksOpen waits for tokens before the
// keyboard/keyfile fallback also starts. Precedence, highest first:
//
//  1. explicit crypttab/cmdline token-timeout= (mapping.tokenTimeoutExplicit)
//  2. booster.yaml token_timeout (config.TokenTimeout)
//  3. serialize mode: sum of the enrolled tokens' per-token bounds, so the
//     keyboard never preempts a serial token that hasn't had its turn (PIN
//     tokens contribute 0 — they're interactive and covered by tokenWg). A
//     zero sum (only PIN/unknown tokens) falls through to case 4 — otherwise
//     a FIDO2-PIN goroutine parked on absent hardware would never release the
//     keyboard fallback and the boot would hang.
//  4. otherwise the mapping's implicit default (30 s; unchanged behaviour)
//
// A return of 0 means "wait for the token goroutines (tokenWg) with no timer".
func effectiveTokenTimeout(mapping *luksMapping, serialTokens []luks.Token) time.Duration {
	if mapping.tokenTimeoutExplicit {
		return mapping.tokenTimeout
	}
	if config.TokenTimeout > 0 {
		return time.Duration(config.TokenTimeout) * time.Second
	}
	if config.SerializeTokens {
		var sum time.Duration
		for _, t := range serialTokens {
			sum += perTokenTimeout(t)
		}
		if sum > 0 {
			return sum
		}
	}
	return mapping.tokenTimeout
}

// pinDelay returns how long luksOpen holds the first interactive PIN prompt so
// a parallel non-interactive token can win first and spare the user the PIN.
// Returns 0 unless pin_delay is set, in serialize mode (strict ID order
// already), or with no parallel non-PIN token (nothing could make the prompt
// unnecessary).
func pinDelay(serialize, hasParallelToken bool) time.Duration {
	if config.PinDelay <= 0 || serialize || !hasParallelToken {
		return 0
	}
	return time.Duration(config.PinDelay) * time.Second
}

func recoverTokenPassword(ctx context.Context, volumes chan *luks.Volume, d luks.Device, t luks.Token, mappingName string, tpm2Signature string) bool {
	var password []byte
	var err error

	switch t.Type {
	case "clevis":
		password, err = recoverClevisPassword(ctx, t, d.Version())
	case "systemd-fido2":
		password, err = recoverSystemdFido2Password(ctx, t, mappingName)
	case "systemd-tpm2":
		password, err = recoverSystemdTPM2Password(ctx, t, mappingName, tpm2Signature)
	default:
		info("token #%d has unknown type: %s", t.ID, t.Type)
		return false
	}

	if errors.Is(err, errFido2FallbackToKeyboard) {
		return false // intentional fallback; message already logged in recoverSystemdFido2Password
	}
	if errors.Is(err, errTPM2Skipped) {
		return false // intentional fallback; message already shown in recoverSystemdTPM2Password
	}
	if errors.Is(err, context.DeadlineExceeded) {
		// serialize-mode per-token timeout — not a failure, advance the
		// serial loop to the next token (or the keyboard fallback).
		info("%s token #%d timed out, moving on", t.Type, t.ID)
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false // another unlock path won (cancel-on-win); stay quiet
	}
	if err != nil {
		warning("recovering %s token #%d failed: %v", t.Type, t.ID, err)
		return false
	}

	info("recovered password from %s token #%d", t.Type, t.ID)
	if !tryPassphraseAgainstSlots(ctx, volumes, d, t.Slots, password) {
		return false
	}
	// TODO: re-evaluate after plymouth!393 lands (auto-dismisses prompt on client disconnect)
	statusMessageIfPrompt(mappingName + " unlocked via " + tokenFriendlyName(t.Type))
	return true
}

// tokenFriendlyName returns a short human-readable label for a token type, used
// in the unlock-confirmation status message.
func tokenFriendlyName(typ string) string {
	switch typ {
	case "systemd-fido2":
		return "FIDO2"
	case "systemd-tpm2":
		return "TPM2"
	case "clevis":
		return "clevis"
	default:
		return typ
	}
}

// readKeyfile reads a keyfile at path, skipping offset bytes and reading at most
// size bytes (0 means read until EOF).
func readKeyfile(path string, offset, size int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, fmt.Errorf("seeking keyfile %s: %v", path, err)
		}
	}

	if size > 0 {
		return io.ReadAll(io.LimitReader(f, size))
	}
	return io.ReadAll(f)
}

// acquireFile mounts ref read-only at mountDir and returns a resolved file path
// constrained to mountDir.
// along with a cleanup function. If ref is nil, filePath is returned as-is with a no-op cleanup.
// This is the shared implementation used by both acquireHeader and acquireKeyfilePassword.
func acquireFile(ref *deviceRef, mountDir, filePath string, timeout time.Duration) (string, func(), error) {
	if ref == nil {
		return filePath, func() {}, nil
	}
	unmount, err := mountDeviceReadOnly(ref, mountDir, timeout)
	if err != nil {
		return "", func() {}, err
	}
	resolved, err := resolvePathInRoot(mountDir, filePath)
	if err != nil {
		unmount()
		return "", func() {}, err
	}
	return resolved, unmount, nil
}

// acquireKeyfilePassword resolves the keyfile path (mounting a separate device if needed),
// reads the file applying any configured offset and size, then releases the mount.
func acquireKeyfilePassword(mapping *luksMapping) ([]byte, error) {
	timeout := mapping.keyfileTimeout
	if timeout == 0 {
		timeout = time.Duration(config.MountTimeout) * time.Second
	}
	path, cleanup, err := acquireFile(mapping.keyfileDeviceRef, "/run/booster/keydev-"+safePathComponent(mapping.name), mapping.keyfile, timeout)
	defer cleanup()
	if err != nil {
		return nil, fmt.Errorf("keyfile device for %s: %v", mapping.name, err)
	}
	return readKeyfile(path, mapping.keyfileOffset, mapping.keyfileSize)
}

func recoverKeyfilePassword(ctx context.Context, volumes chan *luks.Volume, d luks.Device, checkSlots []int, mapping *luksMapping) {
	password, err := acquireKeyfilePassword(mapping)
	if err != nil {
		warning("reading keyfile %s: %v", mapping.keyfile, err)
	}

	if len(password) > 0 {
		if tryPassphraseAgainstSlots(ctx, volumes, d, checkSlots, password) {
			return
		}
	}

	warning("password in keyfile %s was unable to unseal %s", mapping.keyfile, mapping.name)

	// fall back to keyboard
	requestKeyboardPassword(ctx, volumes, d, checkSlots, mapping.name, mapping.tries)
}

// tryCachedPassphrases snapshots passphraseCache and tries each entry against
// checkSlots. Returns true if any unlocked the volume — caller should return
// without prompting. The snapshot avoids holding passphraseCache.Lock across
// the (potentially slow) UnsealVolume calls.
func tryCachedPassphrases(ctx context.Context, volumes chan *luks.Volume, d luks.Device, checkSlots []int) bool {
	passphraseCache.Lock()
	cached := make([][]byte, len(passphraseCache.passwords))
	copy(cached, passphraseCache.passwords)
	passphraseCache.Unlock()

	for _, pw := range cached {
		if tryPassphraseAgainstSlots(ctx, volumes, d, checkSlots, pw) {
			return true
		}
	}
	return false
}

// askKeyboardPassword is the console/plymouth passphrase reader, indirected
// through a var so tests can stub keyboard input. Mirrors askFido2Pin.
var askKeyboardPassword = askPasswordWithFallback

func requestKeyboardPassword(ctx context.Context, volumes chan *luks.Volume, d luks.Device, checkSlots []int, mappingName string, maxTries int) {
	// Wait for plymouth initialization to complete before attempting to use
	// it. Without this, udev events can trigger LUKS password prompts while
	// plymouthd is still starting, causing the graphical prompt to fail.
	// ctx cancellation lets a sibling token unlocking the device dismiss
	// this wait without forcing it to the plymouth-init timeout.
	if err := waitForPlymouthInit(ctx); err != nil {
		return
	}

	// Fast path: try passwords that already unlocked another volume this boot
	// (e.g. two LUKS members of a btrfs RAID1 with the same passphrase).
	if tryCachedPassphrases(ctx, volumes, d, checkSlots) {
		return
	}

	// Serialize prompts across concurrent luksOpen calls. A second device whose
	// keyboard goroutine starts while the first device is prompting will block
	// here, then re-check the cache after the first device succeeds and releases
	// the lock — avoiding a double prompt for shared passphrases (issue #306).
	keyboardMu.Lock()
	defer keyboardMu.Unlock()

	// Re-check after acquiring the lock: another device may have just unlocked.
	select {
	case <-ctx.Done():
		return
	default:
	}

	if tryCachedPassphrases(ctx, volumes, d, checkSlots) {
		return
	}

	attempts := 0
	promptPrefix := ""
	for {
		if maxTries > 0 && attempts >= maxTries {
			warning("maximum passphrase attempts (%d) reached for %s", maxTries, mappingName)
			return
		}

		prompt := promptPrefix + fmt.Sprintf("Enter passphrase for %s:", mappingName)

		password, err := askKeyboardPassword(ctx, prompt, "   Unlocking...")
		if err != nil {
			warning("reading password: %v", err)
			return
		}
		attempts++

		if tryPassphraseAgainstSlots(ctx, volumes, d, checkSlots, password) {
			passphraseCache.Lock()
			passphraseCache.passwords = append(passphraseCache.passwords, password)
			passphraseCache.Unlock()
			statusMessage("") // clear any error message before Plymouth quits
			return
		}

		wipe(password) // failed attempt: no one owns it, scrub it
		promptPrefix = "Incorrect passphrase — "
		if !plymouthEnabled {
			console("   Incorrect passphrase, please try again\n")
		}
	}
}

func mountDeviceReadOnly(ref *deviceRef, mountPoint string, timeout time.Duration) (func(), error) {
	blk, err := waitForDeviceRef(ref, timeout)
	if err != nil {
		return nil, err
	}
	if !blk.isFs {
		return nil, fmt.Errorf("device %s is not a mountable filesystem", blk.path)
	}
	if err := os.MkdirAll(mountPoint, 0o700); err != nil {
		return nil, err
	}
	flags := uintptr(unix.MS_RDONLY | unix.MS_NOEXEC | unix.MS_NOSUID | unix.MS_NODEV)
	if err := unix.Mount(blk.path, mountPoint, blk.format, flags, ""); err != nil {
		return nil, fmt.Errorf("mounting device %s: %v", blk.path, err)
	}
	return func() {
		_ = unix.Unmount(mountPoint, unix.MNT_DETACH)
		_ = os.Remove(mountPoint)
	}, nil
}

// acquireHeader resolves the detached LUKS header path for a mapping, waiting
// for the header device to appear if necessary. The returned cleanup function
// unmounts any temporarily-mounted device; callers must defer it.
// If the mapping has no detached header, path is "" and cleanup is a no-op.
func acquireHeader(m *luksMapping) (path string, cleanup func(), err error) {
	if m.header == "" {
		return "", func() {}, nil
	}
	timeout := time.Duration(config.MountTimeout) * time.Second
	if m.headerDeviceRef != nil {
		// Header is a file on a separate filesystem device — use shared acquireFile.
		return acquireFile(m.headerDeviceRef, "/run/booster/hdrdev-"+safePathComponent(m.name), m.header, timeout)
	}
	if strings.HasPrefix(m.header, "/dev/") {
		// Header is a raw block device — wait for it to appear.
		ref := &deviceRef{refPath, m.header}
		if _, err := waitForDeviceRef(ref, timeout); err != nil {
			return "", nil, fmt.Errorf("header device %s: %v", m.header, err)
		}
	}
	// Bundled initramfs file or now-present block device path.
	return m.header, func() {}, nil
}

func luksOpen(dev string, mapping *luksMapping) error {
	module := loadModules("dm_crypt")

	var (
		d   luks.Device
		err error
	)
	headerPath, headerCleanup, err := acquireHeader(mapping)
	if err != nil {
		return err
	}
	defer headerCleanup()
	if headerPath != "" {
		d, err = luks.OpenWithHeader(dev, headerPath)
	} else {
		d, err = luks.Open(dev)
	}
	if err != nil {
		return err
	}
	defer d.Close()

	availableSlots := d.Slots()
	if len(availableSlots) == 0 {
		return fmt.Errorf("device %s has no slots to unlock", dev)
	}

	// Restrict to the requested key slot if specified.
	if mapping.keySlot >= 0 {
		var filtered []int
		for _, s := range availableSlots {
			if s == mapping.keySlot {
				filtered = append(filtered, s)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("device %s: key-slot=%d not found in available slots", dev, mapping.keySlot)
		}
		availableSlots = filtered
	}

	if err := d.FlagsAdd(mapping.options...); err != nil {
		return err
	}

	volumes := make(chan *luks.Volume)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var senderWg sync.WaitGroup
	var tokenWg sync.WaitGroup

	tokens, err := d.Tokens()
	if err != nil {
		return err
	}

	// Sort ascending by token ID. d.Tokens() iterates a Go map so its return
	// order is randomised every boot; without the sort the user can't predict
	// which token (TPM2 vs FIDO2 vs clevis) tries to unlock first.
	sort.Slice(tokens, func(i, j int) bool { return tokens[i].ID < tokens[j].ID })

	// Tokens dispatched serially go into serialTokens; a single goroutine walks
	// them in ID order so attempts never interleave. PIN-bearing tokens (TPM2
	// with PIN, FIDO2 with PIN) always serialize so prompts never overlap when
	// more than one is enrolled. When serialize_tokens is set every token
	// serializes — the user opted out of booster's token concurrency entirely.
	// Otherwise non-PIN tokens fan out in parallel.
	serialize := config.SerializeTokens
	var serialTokens []luks.Token
	slotsWithTokens := make(map[int]bool)
	// hasParallelToken: a non-PIN token is racing in parallel. Gates the
	// PIN-prompt pre-delay — holding the prompt only helps when a
	// non-interactive token could still win and make it unnecessary.
	hasParallelToken := false
	for _, t := range tokens {
		if t.Type == "systemd-recovery" {
			continue // skipped: entered via keyboard later
		}
		for _, s := range t.Slots {
			slotsWithTokens[s] = true
		}
		if serialize || tokenNeedsPin(t) {
			serialTokens = append(serialTokens, t)
			continue
		}
		t := t
		hasParallelToken = true
		senderWg.Add(1)
		tokenWg.Add(1)
		go func() {
			defer senderWg.Done()
			defer tokenWg.Done()
			if recoverTokenPassword(ctx, volumes, d, t, mapping.name, mapping.tpm2Signature) {
				cancel()
			}
		}()
	}

	delay := pinDelay(serialize, hasParallelToken)

	// Serial tokens: one goroutine walks them in slice order (already sorted by
	// ID above). A skipped/failed token advances to the next; a successful
	// unlock cancels ctx and stops iteration. The ctx check before each
	// iteration lets a parallel non-PIN unlock (when any exist) cancel the loop
	// without waiting for the next prompt to time out.
	if len(serialTokens) > 0 {
		senderWg.Add(1)
		tokenWg.Add(1)
		go func() {
			defer senderWg.Done()
			defer tokenWg.Done()
			pinDelayed := false
			for _, t := range serialTokens {
				select {
				case <-ctx.Done():
					return
				default:
				}
				// Hold the first PIN prompt for pin_delay so the parallel
				// non-interactive token race can win before any prompt is
				// drawn; if it wins (here or later) ctx is cancelled and we
				// return. Applied only once: the delay just buys the race a
				// head start before the user is first interrupted. The race
				// goroutines keep running regardless, and cancel-on-win still
				// dismisses a later prompt — re-paying the delay per PIN token
				// would only add boot latency with no extra benefit.
				if delay > 0 && !pinDelayed && tokenNeedsPin(t) {
					pinDelayed = true
					if err := ctxSleep(ctx, delay); err != nil {
						return // cancel-on-win during the delay
					}
				}
				// Per-token timeout (serialize mode only): bound a
				// non-interactive token so a dead clevis/absent-FIDO2
				// can't stall the chain or starve later tokens. PIN
				// tokens return 0 here (interactive, user has empty-Enter
				// escape) and run under the parent ctx unbounded.
				tctx := ctx
				var tcancel context.CancelFunc
				if pt := perTokenTimeout(t); pt > 0 {
					tctx, tcancel = context.WithTimeout(ctx, pt)
				}
				ok := recoverTokenPassword(tctx, volumes, d, t, mapping.name, mapping.tpm2Signature)
				if tcancel != nil {
					tcancel()
				}
				if ok {
					cancel()
					return
				}
			}
		}()
	}

	// Keyboard always skips slots claimed by any token: a typed passphrase will never
	// unseal a slot enrolled for a hardware credential (TPM2, FIDO2, clevis).
	// Fall back to all slots only when every slot is token-owned (no dedicated
	// passphrase slot exists).
	checkSlotsWithPassword := availableSlots
	if len(slotsWithTokens) > 0 {
		var filtered []int
		for _, s := range availableSlots {
			if !slotsWithTokens[s] {
				filtered = append(filtered, s)
			}
		}
		if len(filtered) > 0 {
			checkSlotsWithPassword = filtered
		}
	}

	// Register the passphrase target for the full lifetime of luksOpen so
	// out-of-band sources (SSH remote unlock) can submit a passphrase against
	// the passphrase slots concurrently with token attempts — not gated behind
	// tokenWg.Wait() like the local keyboard prompt. A successful out-of-band
	// unlock cancels ctx, which dismisses any in-flight token / keyboard
	// prompt via the existing ctx-cancellation path.
	var reg *promptRegistration
	if len(checkSlotsWithPassword) > 0 {
		reg = &promptRegistration{
			ctx:         ctx,
			cancel:      cancel,
			volumes:     volumes,
			d:           d,
			checkSlots:  checkSlotsWithPassword,
			mappingName: mapping.name,
		}
		registerPendingPrompt(reg)
		defer unregisterPendingPrompt(reg)
	}

	// Start keyboard/keyfile unlock after all token goroutines finish (or tokenTimeout
	// elapses). This gives hardware tokens priority over the keyboard prompt.
	// senderWg ensures volumes is closed if this goroutine is the last sender.
	senderWg.Go(func() {
		if tt := effectiveTokenTimeout(mapping, serialTokens); tt > 0 {
			waitTimeout(&tokenWg, tt)
		} else {
			tokenWg.Wait()
		}
		select {
		case <-ctx.Done():
			return // already unlocked by a token
		default:
		}
		if len(checkSlotsWithPassword) > 0 {
			senderWg.Go(func() {
				if mapping.keyfile != "" {
					recoverKeyfilePassword(ctx, volumes, d, checkSlotsWithPassword, mapping)
				} else {
					requestKeyboardPassword(ctx, volumes, d, checkSlotsWithPassword, mapping.name, mapping.tries)
				}
			})
		}
	})

	// Watcher: when every unlock goroutine has given up, close volumes so luksOpen
	// unblocks rather than hanging forever. Check ctx first to avoid closing volumes
	// after a priority token already signalled success.
	go func() {
		senderWg.Wait()
		// Race fence: remove the registration so no new submitter can grab
		// this entry, then wait for already-snapshotted submitters to finish
		// their UnsealVolume + channel send. Without this, an in-flight SSH
		// submission whose UnsealVolume succeeds after close(volumes) would
		// panic pid 1 with "send on closed channel" at tryPassphraseAgainstSlots.
		// Skipped when reg is nil (no passphrase slots — no OOB submitter
		// can target this device).
		if reg != nil {
			pendingPrompts.Lock()
			delete(pendingPrompts.entries, reg)
			pendingPrompts.Unlock()
			reg.inflight.Wait()
		}
		select {
		case <-ctx.Done():
			// Already unlocked — volumes will drain naturally.
		default:
			close(volumes)
		}
	}()

	v, ok := <-volumes

	if !ok {
		return fmt.Errorf("failed to unlock %s: all unlock attempts exhausted", dev)
	}

	if err := loadRequiredCryptoModules(v.StorageEncryption); err != nil {
		return err
	}

	module.Wait()

	// Extend PCR15 with the systemd-compatible volume-key measurement, after the
	// volume key is recovered and before SetupMapper/pivot. volumeKeyLatchMode
	// selects the mode: a required measurement error aborts the unlock, a
	// defensive one only warns.
	switch volumeKeyLatchMode(tokens, mapping.measurePCR, tpmAvailable()) {
	case latchRequired:
		if err := measureVolumeKeyToPCR15(v, mapping.name, v.UUID); err != nil {
			return fmt.Errorf("measuring volume key to PCR%d for %s: %v", pcrSystemIdentity, mapping.name, err)
		}
		debug("PCR%d re-unseal latch engaged for %s", pcrSystemIdentity, mapping.name)
	case latchDefensive:
		// Best-effort: a measurement error warns instead of aborting the unlock.
		if err := measureVolumeKeyToPCR15(v, mapping.name, v.UUID); err != nil {
			warning("PCR%d defensive latch not applied for %s: %v", pcrSystemIdentity, mapping.name, err)
		} else {
			debug("PCR%d defensive re-unseal latch engaged for %s", pcrSystemIdentity, mapping.name)
		}
	case latchNone:
		debug("PCR%d latch not engaged for %s (tpm2-measure-pcr=%s)", pcrSystemIdentity, mapping.name, mapping.measurePCR)
	}

	return v.SetupMapper(mapping.name)
}

func loadRequiredCryptoModules(encryption string) error {
	// at non-booster systems loading crypto modules mechanism is following:
	//   1. dmsetup asks kernel to load a table with some encryption configuration, e.g. xts-camellia-plain
	//   2. kernel's crypto/api.c checks if modules present for mode and block cipher, if not - initiates loading it.
	//      The module names look like crypto_$MODE
	//   3. kernel starts a user process and invokes "modprobe crypto_$MODE" to load the required module
	// As we do not want to add modprobe to the image we try to emulate this functionality here by loading these modules directly
	parts := strings.Split(encryption, "-")
	mode := parts[0]
	cipher := parts[1]
	var modules []string

	cryptoAliases := []string{"crypto_" + mode, "crypto_" + cipher}
	for _, a := range cryptoAliases {
		mods := matchAlias(a)
		if len(mods) == 0 {
			debug("no match found for alias %s", a)
			continue
		}
		modules = append(modules, mods...)
	}

	w := loadModules(modules...)
	w.Wait()

	return nil
}

// unreachableMapperName reports the basename of cmdRoot when it is a
// /dev/mapper/<name> path-ref AND no luksMapping exists with that name. Used
// to surface a diagnostic for the boot pattern that silently hangs when a
// LUKS unlock spec is missing.
func unreachableMapperName() (string, bool) {
	if cmdRoot == nil || cmdRoot.format != refPath {
		return "", false
	}
	p, ok := cmdRoot.data.(string)
	if !ok || !strings.HasPrefix(p, "/dev/mapper/") {
		return "", false
	}
	name := strings.TrimPrefix(p, "/dev/mapper/")
	for _, m := range luksMappings {
		if m.name == name {
			return "", false
		}
	}
	return name, true
}

func matchLuksMapping(blk *blkInfo) *luksMapping {
	for _, m := range luksMappings {
		if blk.matchesRef(m.ref) {
			// Mirror the synthesis-fallback remap so root=UUID=<luks-uuid>
			// keeps working after a crypttab/rd.luks.* entry adds the mapping.
			if blk.matchesRef(cmdRoot) {
				info("LUKS device %s matches root=, re-pointing root to /dev/mapper/%s", blk.path, m.name)
				cmdRoot = &deviceRef{format: refPath, data: "/dev/mapper/" + m.name}
			}
			return m
		}
	}

	// a special case coming from autodiscoverable partitions https://systemd.io/DISCOVERABLE_PARTITIONS/
	// is to check whether this partition was specified as a 'root' and if yes - mount it and re-point root to the new location under /dev/mapper/xxx)
	if blk.matchesRef(cmdRoot) {
		info("LUKS device %s matches root=, unlock this device", blk.path)
		m := &luksMapping{
			ref:          cmdRoot,
			name:         "root",
			keySlot:      -1,
			tokenTimeout: 30 * time.Second, // systemd default: wait 30s for tokens before also prompting keyboard
		}
		cmdRoot = &deviceRef{format: refPath, data: "/dev/mapper/root"}
		return m
	}

	return nil
}

func handleLuksBlockDevice(blk *blkInfo) error {
	m := matchLuksMapping(blk)
	if m == nil {
		// did not find any mappings for the given device
		return nil
	}
	info("a mapping for LUKS device %s has been found", blk.path)

	err := luksOpen(blk.path, m)
	if err != nil && m.noFail {
		warning("ignoring error unlocking LUKS device %s (nofail): %v", blk.path, err)
		return nil
	}
	return err
}

func findOrCreateLuksMapping(uuid UUID) *luksMapping {
	blk := blkInfo{
		uuid: uuid,
	}

	for _, o := range luksMappings {
		if blk.matchesRef(o.ref) {
			return o
		}
	}

	// didn't locate the device make a new one
	m := &luksMapping{
		ref:          &deviceRef{refFsUUID, uuid},
		name:         "luks-" + uuid.toString(),
		keySlot:      -1,
		tokenTimeout: 30 * time.Second, // systemd default: wait 30s for tokens before also prompting keyboard
	}
	luksMappings = append(luksMappings, m)

	return m
}
