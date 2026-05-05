package main

import (
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
	tokenTimeout    time.Duration // how long to wait for tokens before also starting keyboard; 0 = wait forever

	keyfileDeviceRef *deviceRef    // non-nil when keyfile is on a separate device
	keyfileTimeout   time.Duration // device wait timeout for keyfile device (0 = use MountTimeout)

	keySlot       int   // -1 = all slots; >=0 restricts unlock to that slot
	tries         int   // 0 = unlimited keyboard retries; >0 = max attempts
	noFail        bool  // non-fatal unlock failure — boot continues on error
	keyfileOffset int64 // bytes to skip at start of keyfile
	keyfileSize   int64 // max bytes to read from keyfile (0 = all)
}

// tryPassphraseAgainstSlots tries password against each slot, sending the opened
// volume on volumes if successful.  Returns true on success.
func tryPassphraseAgainstSlots(volumes chan *luks.Volume, done <-chan struct{}, d luks.Device, checkSlots []int, password []byte) bool {
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
		case <-done:
		}
		return true
	}
	return false
}

// passphraseCache holds passwords that successfully unlocked a LUKS volume during
// this boot, so subsequent volumes (e.g. btrfs RAID1 members) can be tried
// automatically without prompting the user again.
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

// rd luks options match systemd naming https://www.freedesktop.org/software/systemd/man/crypttab.html
var rdLuksOptions = map[string]string{
	"discard":                luks.FlagAllowDiscards,
	"same-cpu-crypt":         luks.FlagSameCPUCrypt,
	"submit-from-crypt-cpus": luks.FlagSubmitFromCryptCPUs,
	"no-read-workqueue":      luks.FlagNoReadWorkqueue,
	"no-write-workqueue":     luks.FlagNoWriteWorkqueue,
}

func recoverClevisPassword(t luks.Token, luksVersion int) ([]byte, error) {
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
				time.Sleep(500 * time.Millisecond)
				continue
			} else if !errors.As(err, &netError) {
				return nil, err
			}

			// it takes a bit of time to initialize network and DHCP
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timeout waiting for network")
			}
			// else let's sleep and retry
			time.Sleep(time.Second)
			continue
		}

		return password, nil
	}
}

func isHidRawFido2(devName string) (bool, error) {
	descriptor, err := os.ReadFile("/sys/class/hidraw/" + devName + "/device/report_descriptor")
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

func recoverFido2Password(devName string, credential string, salt string, relyingParty string, pinRequired bool, userPresenceRequired bool, userVerificationRequired bool, mappingName string, promptPrefix string) ([]byte, error) {
	usbhidWg.Wait()

	isFido2, err := isHidRawFido2(devName)
	if err != nil {
		return nil, fmt.Errorf("unable to check whether %s is a FIDO2 device", devName)
	}
	if !isFido2 {
		return nil, fmt.Errorf("HID %s is not a FIDO2 device", devName)
	}

	info("HID %s supports FIDO, trying it to recover the password", devName)

	fido2Mu.Lock()
	defer fido2Mu.Unlock()

	if plymouthEnabled {
		plymouthMessage("") // clear "Waiting for FIDO2" now that device is detected and we have the lock
	}

	credID, err := base64.StdEncoding.DecodeString(credential)
	if err != nil {
		return nil, fmt.Errorf("invalid credential: %v", err)
	}
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt: %v", err)
	}

	var pin string
	if pinRequired {
		prompt := promptPrefix + "Enter FIDO2 PIN for " + mappingName + " (empty to skip to passphrase):"
		pinBytes, err := askPasswordWithFallback(prompt, "")
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
	if err == nil {
		statusMessage("")
	}
	return result, err
}

var hidrawDevices = make(chan string, 10) // channel that receives 'add hidraw' events

// fido2Mu serializes FIDO2 user interactions (PIN prompt + touch + assertion)
// across all goroutines. The FIDO2 key can only service one assertion at a time,
// and concurrent goroutines (e.g. multiple systemd-fido2 tokens or multiple LUKS
// devices) would otherwise interleave PIN prompts and touch messages.
var fido2Mu sync.Mutex

var errFido2Skipped = errors.New("FIDO2 skipped by user")
var errFido2PinInvalid = errors.New("FIDO2 PIN invalid")
var errFido2FallbackToKeyboard = errors.New("FIDO2 falling back to keyboard")
var errTPM2Skipped = errors.New("TPM2 skipped by user")

func recoverSystemdFido2Password(t luks.Token, mappingName string) ([]byte, error) {
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

	statusMessage("Waiting for FIDO2 security key for " + mappingName + "...")

	usbhidWg.Wait()

	dir, err := os.ReadDir("/sys/class/hidraw/")
	if err != nil {
		return nil, err
	}

	if len(dir) == 0 {
		statusMessage("No FIDO2 device found for " + mappingName + ", insert security key or wait for passphrase prompt")
	}

	stopSeeding := make(chan struct{})
	defer close(stopSeeding)
	go func() {
		for _, d := range dir {
			select {
			case hidrawDevices <- d.Name():
			case <-stopSeeding:
				return
			}
		}
	}()

	seenHidrawDevices := make(set)

	for devName := range hidrawDevices {
		if seenHidrawDevices[devName] {
			continue
		}
		seenHidrawDevices[devName] = true

		maxAttempts := 1
		if node.PinRequired {
			maxAttempts = 3
		}
		var password []byte
		var err error
		pinExhausted := false
		promptPrefix := ""
		for attempt := 0; attempt < maxAttempts; attempt++ {
			password, err = recoverFido2Password(devName, node.Credential, node.Salt, node.RelyingParty, node.PinRequired, node.UserPresenceRequired, node.UserVerificationRequired, mappingName, promptPrefix)
			if err == nil {
				break
			}
			if !errors.Is(err, errFido2PinInvalid) {
				break
			}
			if attempt < maxAttempts-1 {
				promptPrefix = "FIDO2 PIN incorrect — "
			} else {
				pinExhausted = true
			}
		}

		if err != nil {
			if errors.Is(err, errFido2Skipped) || pinExhausted {
				statusMessage("FIDO2 skipped, falling back to passphrase")
				break
			}
			if isFido2PinAuthBlockedError(err) {
				statusMessage("FIDO2 PIN auth blocked (too many wrong attempts), falling back to passphrase")
				break
			}
			if isFido2PinBlockedError(err) {
				statusMessage("FIDO2 PIN is blocked (reset required), falling back to passphrase")
				break
			}
			info("%v", err)
			continue
		}
		return password, nil
	}

	return nil, errFido2FallbackToKeyboard
}

func recoverSystemdTPM2Password(t luks.Token, mappingName string) ([]byte, error) {
	var node struct {
		Blob       string `json:"tpm2-blob"` // base64
		PCRs       []int  `json:"tpm2-pcrs"`
		PCRBank    string `json:"tpm2-pcr-bank"`    // either sha1 or sha256
		PolicyHash string `json:"tpm2-policy-hash"` // hex
		Pin        bool   `json:"tpm2-pin"`
		Salt       string `json:"tpm2_salt"` // base64 random salt; systemd v255+ PIN tokens
		Srk        string `json:"tpm2_srk"`  // base64 IESYS bytes; systemd v252+ tokens
	}
	if err := json.Unmarshal(t.Payload, &node); err != nil {
		return nil, err
	}

	blob, err := base64.StdEncoding.DecodeString(node.Blob)
	if err != nil {
		return nil, err
	}
	private, public, err := parseSystemdTPM2Blob(blob)
	if err != nil {
		return nil, err
	}

	if node.PolicyHash == "" {
		return nil, fmt.Errorf("empty policy hash")
	}
	policyHash, err := hex.DecodeString(node.PolicyHash)
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
			pin, err := askPasswordWithFallback(prompt, "")
			if err != nil {
				return nil, err
			}
			if len(pin) == 0 {
				statusMessage("TPM2 PIN skipped")
				return nil, errTPM2Skipped
			}
			authValue = tpm2PINAuthValue(pin, salt)
		}

		password, err := tpm2Unseal(public, private, node.PCRs, bank, policyHash, authValue, srkHandle)
		if err == nil {
			return []byte(base64.StdEncoding.EncodeToString(password)), nil
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

func recoverTokenPassword(volumes chan *luks.Volume, done <-chan struct{}, d luks.Device, t luks.Token, mappingName string) bool {
	var password []byte
	var err error

	switch t.Type {
	case "clevis":
		password, err = recoverClevisPassword(t, d.Version())
	case "systemd-fido2":
		password, err = recoverSystemdFido2Password(t, mappingName)
	case "systemd-tpm2":
		password, err = recoverSystemdTPM2Password(t, mappingName)
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
	if err != nil {
		warning("recovering %s token #%d failed: %v", t.Type, t.ID, err)
		return false
	}

	info("recovered password from %s token #%d", t.Type, t.ID)
	return tryPassphraseAgainstSlots(volumes, done, d, t.Slots, password)
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

func recoverKeyfilePassword(volumes chan *luks.Volume, done <-chan struct{}, d luks.Device, checkSlots []int, mapping *luksMapping) {
	password, err := acquireKeyfilePassword(mapping)
	if err != nil {
		warning("reading keyfile %s: %v", mapping.keyfile, err)
	}

	if len(password) > 0 {
		if tryPassphraseAgainstSlots(volumes, done, d, checkSlots, password) {
			return
		}
	}

	warning("password in keyfile %s was unable to unseal %s", mapping.keyfile, mapping.name)

	// fall back to keyboard
	requestKeyboardPassword(volumes, done, d, checkSlots, mapping.name, mapping.tries)
}

// tryCachedPassphrases snapshots passphraseCache and tries each entry against
// checkSlots. Returns true if any unlocked the volume — caller should return
// without prompting. The snapshot avoids holding passphraseCache.Lock across
// the (potentially slow) UnsealVolume calls.
func tryCachedPassphrases(volumes chan *luks.Volume, done <-chan struct{}, d luks.Device, checkSlots []int) bool {
	passphraseCache.Lock()
	cached := make([][]byte, len(passphraseCache.passwords))
	copy(cached, passphraseCache.passwords)
	passphraseCache.Unlock()

	for _, pw := range cached {
		if tryPassphraseAgainstSlots(volumes, done, d, checkSlots, pw) {
			return true
		}
	}
	return false
}

func requestKeyboardPassword(volumes chan *luks.Volume, done <-chan struct{}, d luks.Device, checkSlots []int, mappingName string, maxTries int) {
	// Wait for plymouth initialization to complete before attempting to use
	// it. Without this, udev events can trigger LUKS password prompts while
	// plymouthd is still starting, causing the graphical prompt to fail.
	waitForPlymouthInit()

	// Bail early if the device was already unlocked by a token goroutine.
	select {
	case <-done:
		return
	default:
	}

	// Fast path: try passwords that already unlocked another volume this boot
	// (e.g. two LUKS members of a btrfs RAID1 with the same passphrase).
	if tryCachedPassphrases(volumes, done, d, checkSlots) {
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
	case <-done:
		return
	default:
	}

	if tryCachedPassphrases(volumes, done, d, checkSlots) {
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

		password, err := askPasswordWithFallback(prompt, "   Unlocking...")
		if err != nil {
			warning("reading password: %v", err)
			return
		}
		attempts++

		if tryPassphraseAgainstSlots(volumes, done, d, checkSlots, password) {
			passphraseCache.Lock()
			passphraseCache.passwords = append(passphraseCache.passwords, password)
			passphraseCache.Unlock()
			statusMessage("") // clear any error message before Plymouth quits
			return
		}

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
	done := make(chan struct{})
	var closeDone sync.Once
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

	// PIN-bearing tokens (TPM2 with PIN, FIDO2 with PIN) go into pinTokens for
	// serial dispatch by a single goroutine so prompts never interleave when
	// more than one is enrolled. Non-PIN tokens fan out as today.
	var pinTokens []luks.Token
	slotsWithTokens := make(map[int]bool)
	for _, t := range tokens {
		if t.Type == "systemd-recovery" {
			continue // skipped: entered via keyboard later
		}
		for _, s := range t.Slots {
			slotsWithTokens[s] = true
		}
		if tokenNeedsPin(t) {
			pinTokens = append(pinTokens, t)
			continue
		}
		t := t
		senderWg.Add(1)
		tokenWg.Add(1)
		go func() {
			defer senderWg.Done()
			defer tokenWg.Done()
			if recoverTokenPassword(volumes, done, d, t, mapping.name) {
				closeDone.Do(func() { close(done) })
			}
		}()
	}

	// PIN tokens: one goroutine walks them in slice order (already sorted by
	// ID above). A skipped/failed token advances to the next; a successful
	// unlock closes done and stops iteration. The done check before each
	// iteration lets a parallel non-PIN unlock cancel the loop without
	// waiting for the next prompt to time out.
	if len(pinTokens) > 0 {
		senderWg.Add(1)
		tokenWg.Add(1)
		go func() {
			defer senderWg.Done()
			defer tokenWg.Done()
			for _, t := range pinTokens {
				select {
				case <-done:
					return
				default:
				}
				if recoverTokenPassword(volumes, done, d, t, mapping.name) {
					closeDone.Do(func() { close(done) })
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

	// Start keyboard/keyfile unlock after all token goroutines finish (or tokenTimeout
	// elapses). This gives hardware tokens priority over the keyboard prompt.
	// senderWg ensures volumes is closed if this goroutine is the last sender.
	senderWg.Go(func() {
		if mapping.tokenTimeout > 0 {
			waitTimeout(&tokenWg, mapping.tokenTimeout)
		} else {
			tokenWg.Wait()
		}
		select {
		case <-done:
			return // already unlocked by a token
		default:
		}
		if len(checkSlotsWithPassword) > 0 {
			senderWg.Go(func() {
				if mapping.keyfile != "" {
					recoverKeyfilePassword(volumes, done, d, checkSlotsWithPassword, mapping)
				} else {
					requestKeyboardPassword(volumes, done, d, checkSlotsWithPassword, mapping.name, mapping.tries)
				}
			})
		}
	})

	// Watcher: when every unlock goroutine has given up, close volumes so luksOpen
	// unblocks rather than hanging forever. Check done first to avoid closing volumes
	// after a priority token already signalled success.
	go func() {
		senderWg.Wait()
		select {
		case <-done:
			// Already unlocked — volumes will drain naturally.
		default:
			close(volumes)
		}
	}()

	v, ok := <-volumes
	closeDone.Do(func() { close(done) })

	if !ok {
		return fmt.Errorf("failed to unlock %s: all unlock attempts exhausted", dev)
	}

	if err := loadRequiredCryptoModules(v.StorageEncryption); err != nil {
		return err
	}

	module.Wait()
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

func matchLuksMapping(blk *blkInfo) *luksMapping {
	for _, m := range luksMappings {
		if blk.matchesRef(m.ref) {
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
