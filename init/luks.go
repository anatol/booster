package main

import (
	"bytes"
	"crypto/sha256"
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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anatol/clevis.go"
	"github.com/anatol/luks.go"
	"golang.org/x/sys/unix"
)

// specifies information needed to process/open a LUKS device
// often these mappings specified by a user via command-line
type luksMapping struct {
	ref          *deviceRef
	name         string
	keyfile      string
	options      []string      // dm-crypt flags for d.FlagsAdd
	tokenFido2   bool          // fido2-device=auto was set
	tokenTpm2    bool          // tpm2-device=auto was set
	tokenTimeout time.Duration // 0 = wait forever; >0 = defer keyboard until elapsed
	header        string        // detached LUKS header path (empty = embedded header)
	keySlot       int           // -1 = try all slots; >=0 restricts password checks to that slot
	tries         int           // 0 = unlimited keyboard retries; >0 = max attempts
	noFail        bool          // if true, unlock failure is non-fatal (boot continues)
	keyfileOffset    int64         // byte offset into keyfile (0 = start)
	keyfileSize      int64         // bytes to read from keyfile (0 = read to end)
	keyfileDeviceRef *deviceRef    // non-nil when keyfile lives on a separate device
	keyfileTimeout   time.Duration // 0 = use MountTimeout; >0 = per-entry device wait timeout
	headerDeviceRef  *deviceRef    // non-nil when header is a file on a separate device
}

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

func recoverFido2Password(devName string, credential string, salt string, relyingParty string, pinRequired bool, userPresenceRequired bool, userVerificationRequired bool, mappingName string) ([]byte, error) {
	usbhidWg.Wait()

	isFido2, err := isHidRawFido2(devName)
	if err != nil {
		return nil, fmt.Errorf("unable to check whether %s is a FIDO2 device", devName)
	}

	if !isFido2 {
		return nil, fmt.Errorf("HID %s is not a FIDO2 device", devName)
	}

	info("HID %s supports FIDO, trying it to recover the password", devName)

	var challenge strings.Builder
	const zeroString = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32byte zero string encoded as hex, hex.EncodeToString(make([]byte, 32))
	challenge.WriteString(zeroString)                                 // client data, an empty string
	challenge.WriteRune('\n')
	challenge.WriteString(relyingParty)
	challenge.WriteRune('\n')
	challenge.WriteString(credential)
	challenge.WriteRune('\n')
	challenge.WriteString(salt)
	challenge.WriteRune('\n')

	device := "/dev/" + devName
	args := []string{"-G", "-h", device}
	if userPresenceRequired {
		args = append(args, "-t", "up=true")
	}
	if userVerificationRequired {
		args = append(args, "-t", "uv=true")
	}
	if pinRequired {
		args = append(args, "-t", "pin=true")
	}

	cmd := exec.Command("fido2-assert", args...)
	pipeOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	pipeErr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	pipeIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	if _, err := pipeIn.Write([]byte(challenge.String())); err != nil {
		return nil, err
	}

	if pinRequired {
		// wait till the command requests the pin
		buff := make([]byte, 500)
		if _, err := pipeErr.Read(buff); err != nil {
			return nil, err
		}
		fido2Prompt := "Enter PIN for " + device + ":"
		displayPrompt := "Enter FIDO2 PIN for " + mappingName + ":"
		if strings.HasPrefix(string(buff), fido2Prompt) {
			// fido2-assert tool requests for PIN
			pin, err := readPassword(displayPrompt, "")
			if err != nil {
				return nil, err
			}
			pin = append(pin, '\n')
			if _, err := pipeIn.Write(pin); err != nil {
				return nil, err
			}
		}
	}

	content, err := io.ReadAll(pipeOut)
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(content, []byte{'\n'})
	if len(lines) < 5 {
		msg, _ := io.ReadAll(pipeErr)
		msg = bytes.TrimRight(msg, "\n")
		return nil, fmt.Errorf("%s", string(msg))
	}

	// hmac is the 5th line in the output
	return lines[4], nil
}

// isFido2PinInvalidError reports whether err indicates a wrong FIDO2 PIN.
// With fido2-assert the error text contains "PIN_INVALID" when the PIN is incorrect.
func isFido2PinInvalidError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "PIN_INVALID")
}

var hidrawDevices = make(chan string, 10) // channel that receives 'add hidraw' events

// passphraseCache stores passwords that have successfully unlocked a LUKS
// volume so they can be tried silently against other volumes before prompting.
var passphraseCache struct {
	sync.Mutex
	passwords [][]byte
}

// recoverSystemdFido2Password attempts to recover a LUKS passphrase from a
// systemd-fido2 token.  done is closed when the LUKS device has been unlocked
// by any means (keyboard, another token, etc.) — this cancels a pending FIDO2
// wait so the goroutine exits cleanly rather than blocking forever.
func recoverSystemdFido2Password(t luks.Token, mappingName string, done <-chan struct{}) ([]byte, error) {
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

	dir, err := os.ReadDir("/sys/class/hidraw/")
	if err != nil {
		return nil, err
	}
	// Seed the channel with devices already present in sysfs so they are
	// processed before any late-arriving udev events.
	go func() {
		for _, d := range dir {
			hidrawDevices <- d.Name()
		}
	}()

	seenHidrawDevices := make(set)

	for {
		var devName string
		select {
		case <-done:
			// Device unlocked by keyboard or another token — exit cleanly.
			return nil, fmt.Errorf("FIDO2 recovery cancelled")
		case devName = <-hidrawDevices:
		}

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
		for attempt := 0; attempt < maxAttempts; attempt++ {
			password, err = recoverFido2Password(devName, node.Credential, node.Salt, node.RelyingParty, node.PinRequired, node.UserPresenceRequired, node.UserVerificationRequired, mappingName)
			if err == nil {
				break
			}
			if !isFido2PinInvalidError(err) {
				break
			}
			if attempt < maxAttempts-1 {
				if plymouthEnabled {
					plymouthMessage("FIDO2 PIN incorrect, please try again")
				} else {
					warning("FIDO2 PIN incorrect, please try again")
				}
			}
		}
		if err != nil {
			info("%v", err)
			if plymouthEnabled {
				plymouthMessage("") // clear any "PIN incorrect" message
			}
			continue
		}
		return password, nil
	}
}

func recoverSystemdTPM2Password(t luks.Token) ([]byte, error) {
	var node struct {
		Blob       string `json:"tpm2-blob"` // base64
		PCRs       []int  `json:"tpm2-pcrs"`
		PCRBank    string `json:"tpm2-pcr-bank"`    // either sha1 or sha256
		PolicyHash string `json:"tpm2-policy-hash"` // base64
		Pin        bool   `json:"tpm2-pin"`
	}
	if err := json.Unmarshal(t.Payload, &node); err != nil {
		return nil, err
	}

	blob, err := base64.StdEncoding.DecodeString(node.Blob)
	if err != nil {
		return nil, err
	}

	privateSize := binary.BigEndian.Uint16(blob[:2])
	blob = blob[2:]
	private := blob[:privateSize]
	blob = blob[privateSize:]

	publcSize := binary.BigEndian.Uint16(blob[:2])
	blob = blob[2:]
	public := blob[:publcSize]
	blob = blob[publcSize:]

	if node.PolicyHash == "" {
		return nil, fmt.Errorf("empty policy hash")
	}
	policyHash, err := hex.DecodeString(node.PolicyHash)
	if err != nil {
		return nil, err
	}

	bank := parsePCRBank(node.PCRBank)

	var authValue []byte
	if node.Pin {
		prompt := fmt.Sprintf("Please enter TPM pin: ")
		pin, err := readPassword(prompt, "")
		if err != nil {
			return nil, err
		}

		hash := sha256.Sum256(pin)
		authValue = hash[:]
	}

	password, err := tpm2Unseal(public, private, node.PCRs, bank, policyHash, authValue)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(password)), nil
}

func recoverTokenPassword(volumes chan *luks.Volume, d luks.Device, t luks.Token, mappingName string, done <-chan struct{}) bool {
	var password []byte
	var err error

	switch t.Type {
	case "clevis":
		password, err = recoverClevisPassword(t, d.Version())
	case "systemd-fido2":
		password, err = recoverSystemdFido2Password(t, mappingName, done)
	case "systemd-tpm2":
		password, err = recoverSystemdTPM2Password(t)
	default:
		info("token #%d has unknown type: %s", t.ID, t.Type)
		return false
	}

	if err != nil {
		warning("recovering %s token #%d failed: %v", t.Type, t.ID, err)
		return false
	}

	info("recovered password from %s token #%d", t.Type, t.ID)

	for _, s := range t.Slots {
		v, err := d.UnsealVolume(s, password)
		if err == luks.ErrPassphraseDoesNotMatch {
			continue
		} else if err != nil {
			warning("unlocking slot %v: %v", s, err)
			continue
		}
		info("password from %s token #%d matches", t.Type, t.ID)
		volumes <- v
		return true
	}
	info("password from %s token #%d does not match", t.Type, t.ID)
	return false
}

// readKeyfile reads keyfile contents, optionally starting at keyfileOffset and
// limiting to keyfileSize bytes (0 means read to end of file).
func readKeyfile(path string, offset, size int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, 0); err != nil {
			return nil, fmt.Errorf("keyfile seek: %v", err)
		}
	}

	if size > 0 {
		buf := make([]byte, size)
		n, err := io.ReadFull(f, buf)
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("keyfile read: %v", err)
		}
		return buf[:n], nil
	}

	return io.ReadAll(f)
}

func mountKeyDevice(ref *deviceRef, mountPoint string, timeout time.Duration) (func(), error) {
	blk, err := waitForDeviceRef(ref, timeout)
	if err != nil {
		return nil, err
	}
	if !blk.isFs {
		return nil, fmt.Errorf("keyfile device %s is not a mountable filesystem", blk.path)
	}
	if err := os.MkdirAll(mountPoint, 0o700); err != nil {
		return nil, err
	}
	flags := uintptr(unix.MS_RDONLY | unix.MS_NOEXEC | unix.MS_NOSUID | unix.MS_NODEV)
	if err := unix.Mount(blk.path, mountPoint, blk.format, flags, ""); err != nil {
		return nil, fmt.Errorf("mounting keyfile device %s: %v", blk.path, err)
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
		// Header is a file on a separate filesystem device.
		mp := "/run/booster/hdrdev-" + m.name
		unmount, err := mountKeyDevice(m.headerDeviceRef, mp, timeout)
		if err != nil {
			return "", nil, err
		}
		return filepath.Join(mp, m.header), unmount, nil
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

// acquireKeyfilePassword reads the keyfile, mounting a separate device if needed.
// The device is unmounted before this function returns.
func acquireKeyfilePassword(mapping *luksMapping) ([]byte, error) {
	keyPath := mapping.keyfile
	if mapping.keyfileDeviceRef != nil {
		timeout := mapping.keyfileTimeout
		if timeout == 0 {
			timeout = time.Duration(config.MountTimeout) * time.Second
		}
		mountPoint := "/run/booster/keydev-" + mapping.name
		unmount, err := mountKeyDevice(mapping.keyfileDeviceRef, mountPoint, timeout)
		if err != nil {
			return nil, err
		}
		defer unmount()
		keyPath = filepath.Join(mountPoint, mapping.keyfile)
	}
	return readKeyfile(keyPath, mapping.keyfileOffset, mapping.keyfileSize)
}

func recoverKeyfilePassword(volumes chan *luks.Volume, d luks.Device, checkSlots []int, mapping *luksMapping) {
	password, err := acquireKeyfilePassword(mapping)
	if err != nil {
		warning("keyfile %s: %v — falling back to keyboard", mapping.keyfile, err)
	}

	if len(password) > 0 {
		for _, s := range checkSlots {
			v, err := d.UnsealVolume(s, password)
			if err == luks.ErrPassphraseDoesNotMatch {
				continue
			} else if err != nil {
				warning("unlocking slot %v: %v", s, err)
				continue
			}
			volumes <- v
			return
		}
		warning("keyfile %s does not match any slot for %s", mapping.keyfile, mapping.name)
	}

	requestKeyboardPassword(volumes, d, checkSlots, mapping.name, mapping.tries)
}

func tryPassphraseAgainstSlots(volumes chan *luks.Volume, d luks.Device, checkSlots []int, password []byte) bool {
	for _, s := range checkSlots {
		v, err := d.UnsealVolume(s, password)
		if err == luks.ErrPassphraseDoesNotMatch {
			continue
		} else if err != nil {
			warning("unlocking slot %v: %v", s, err)
			continue
		}
		volumes <- v
		return true
	}
	return false
}

func requestKeyboardPassword(volumes chan *luks.Volume, d luks.Device, checkSlots []int, mappingName string, maxTries int) {
	// Wait for plymouth initialization to complete before attempting to use
	// it. Without this, udev events can trigger LUKS password prompts while
	// plymouthd is still starting, causing the graphical prompt to fail.
	waitForPlymouthInit()

	// Fast path: try passwords already in the cache without acquiring the
	// console mutex.  These come from volumes that finished unlocking before
	// this goroutine reached this point.
	passphraseCache.Lock()
	seenCount := len(passphraseCache.passwords)
	cached := append([][]byte(nil), passphraseCache.passwords...)
	passphraseCache.Unlock()

	for _, pw := range cached {
		if tryPassphraseAgainstSlots(volumes, d, checkSlots, pw) {
			return
		}
	}

	attempts := 0
	for {
		if maxTries > 0 && attempts >= maxTries {
			warning("maximum passphrase attempts (%d) reached for %s", maxTries, mappingName)
			return
		}

		prompt := fmt.Sprintf("Enter passphrase for %s:", mappingName)

		var password []byte
		var err error
		consoleLocked := false

		if plymouthEnabled {
			password, err = plymouthAskPassword(prompt)
			if err != nil {
				warning("plymouth password prompt failed: %v, falling back to console", err)
				password, err = readPassword(prompt, "   Unlocking...")
			}
		} else {
			// Acquire the console mutex and hold it through PBKDF.  This
			// eliminates the race where two goroutines for concurrent LUKS
			// volumes both see an empty cache and start prompting before
			// either finishes key derivation: the next goroutine to acquire
			// the mutex will find the cached password and can unlock silently
			// without a second prompt.
			inputMutex.Lock()
			consoleLocked = true

			// Re-check cache for entries added while we waited for the mutex
			// (a concurrent goroutine may have finished unlocking by now).
			passphraseCache.Lock()
			newPws := append([][]byte(nil), passphraseCache.passwords[seenCount:]...)
			seenCount = len(passphraseCache.passwords)
			passphraseCache.Unlock()
			for _, pw := range newPws {
				if tryPassphraseAgainstSlots(volumes, d, checkSlots, pw) {
					inputMutex.Unlock()
					return
				}
			}

			password, err = readPasswordLocked(prompt, "   Unlocking...")
		}

		if err != nil {
			warning("reading password: %v", err)
			if consoleLocked {
				inputMutex.Unlock()
			}
			return
		}
		if len(password) == 0 {
			if consoleLocked {
				inputMutex.Unlock()
			}
			continue
		}

		attempts++
		if tryPassphraseAgainstSlots(volumes, d, checkSlots, password) {
			passphraseCache.Lock()
			passphraseCache.passwords = append(passphraseCache.passwords, password)
			seenCount = len(passphraseCache.passwords)
			passphraseCache.Unlock()
			if consoleLocked {
				inputMutex.Unlock()
			}
			return
		}

		if consoleLocked {
			inputMutex.Unlock()
		}

		// retry password
		if plymouthEnabled {
			plymouthMessage("Incorrect passphrase, please try again")
		} else {
			console("   Incorrect passphrase, please try again\n")
		}
	}
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

	// availableSlots is d.Slots() optionally filtered to a single key slot (crypttab key-slot=).
	availableSlots := d.Slots()
	if mapping.keySlot >= 0 {
		filtered := make([]int, 0, 1)
		for _, s := range availableSlots {
			if s == mapping.keySlot {
				filtered = append(filtered, s)
				break
			}
		}
		availableSlots = filtered
	}

	if len(availableSlots) == 0 {
		if mapping.keySlot >= 0 {
			return fmt.Errorf("device %s: key slot %d not found or not active", dev, mapping.keySlot)
		}
		return fmt.Errorf("device %s has no slots to unlock", dev)
	}

	if err := d.FlagsAdd(mapping.options...); err != nil {
		return err
	}

	volumes := make(chan *luks.Volume)

	// done is closed when a token has successfully unlocked the device,
	// signalling fallback goroutines not to start the keyboard prompt.
	done := make(chan struct{})
	var closeDone sync.Once

	// priorityTypes holds token types that should delay the keyboard prompt.
	priorityTypes := make(map[string]bool)
	if mapping.tokenFido2 {
		priorityTypes["systemd-fido2"] = true
	}
	if mapping.tokenTpm2 {
		priorityTypes["systemd-tpm2"] = true
	}
	hasPriority := len(priorityTypes) > 0

	var tokenWg sync.WaitGroup
	// senderWg tracks every goroutine that may send to volumes.  When it
	// reaches zero all unlock paths have given up; the watcher closes volumes
	// so luksOpen can unblock instead of hanging forever.
	var senderWg sync.WaitGroup
	var keyboardOnce sync.Once

	startKeyboard := func(checkSlots []int) {
		keyboardOnce.Do(func() {
			senderWg.Add(1)
			if len(mapping.keyfile) > 0 {
				go func() {
					defer senderWg.Done()
					recoverKeyfilePassword(volumes, d, checkSlots, mapping)
				}()
			} else {
				go func() {
					defer senderWg.Done()
					requestKeyboardPassword(volumes, d, checkSlots, mapping.name, mapping.tries)
				}()
			}
		})
	}

	slotsWithTokens := make(map[int]bool)
	tokens, err := d.Tokens()
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.Type == "systemd-recovery" {
			continue // skip systemd-recovery tokens as they are supposed to be entered by a keyboard later
		}
		// systemd-fido2 and systemd-tpm2 require explicit opt-in via fido2-device= / tpm2-device=,
		// matching systemd-cryptsetup behaviour.
		if t.Type == "systemd-fido2" && !mapping.tokenFido2 {
			continue
		}
		if t.Type == "systemd-tpm2" && !mapping.tokenTpm2 {
			continue
		}
		if hasPriority && priorityTypes[t.Type] {
			tokenWg.Add(1)
			senderWg.Add(1)
			go func(tok luks.Token) {
				defer tokenWg.Done()
				defer senderWg.Done()
				if recoverTokenPassword(volumes, d, tok, mapping.name, done) {
					closeDone.Do(func() { close(done) })
				}
			}(t)
		} else {
			senderWg.Add(1)
			go func(tok luks.Token) {
				defer senderWg.Done()
				recoverTokenPassword(volumes, d, tok, mapping.name, done)
			}(t)
		}
		for _, s := range t.Slots {
			slotsWithTokens[s] = true
		}
	}

	var checkSlotsWithPassword []int
	for _, s := range availableSlots {
		if !slotsWithTokens[s] {
			// only slots that do not have tokens will be checked with keyboard password
			checkSlotsWithPassword = append(checkSlotsWithPassword, s)
		}
	}

	if len(checkSlotsWithPassword) > 0 {
		if hasPriority {
			// Launch a fallback goroutine: wait for priority tokens to finish
			// (or for tokenTimeout to elapse), then start keyboard if not done.
			go func() {
				if mapping.tokenTimeout > 0 {
					waitTimeout(&tokenWg, mapping.tokenTimeout)
				} else {
					tokenWg.Wait()
				}
				select {
				case <-done:
					// token already succeeded, skip keyboard
				default:
					startKeyboard(checkSlotsWithPassword)
				}
			}()
		} else {
			startKeyboard(checkSlotsWithPassword)
		}
	}

	// Watcher: when every unlock goroutine has given up without success,
	// close volumes so luksOpen unblocks rather than hanging forever.
	go func() {
		senderWg.Wait()
		select {
		case <-done:
			// Already unlocked — leave volumes alone.
		default:
			close(volumes)
		}
	}()

	v, ok := <-volumes
	closeDone.Do(func() { close(done) })
	if !ok {
		// All unlock paths exhausted without success.
		if mapping.noFail {
			warning("nofail: all unlock attempts for %s exhausted, skipping", mapping.name)
			return nil
		}
		return fmt.Errorf("all unlock paths for LUKS device %s exhausted", dev)
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
			ref:     cmdRoot,
			name:    "root",
			keySlot: -1,
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
		warning("nofail: unable to open LUKS device %s (%s), skipping: %v", blk.path, m.name, err)
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
		ref:     &deviceRef{refFsUUID, uuid},
		name:    "luks-" + uuid.toString(),
		keySlot: -1,
	}
	luksMappings = append(luksMappings, m)

	return m
}
