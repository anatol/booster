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
	ref             *deviceRef
	name            string
	keyfile         string
	options         []string
	header          string     // detached LUKS header path (empty = embedded header)
	headerDeviceRef *deviceRef // non-nil when header is a file on a separate device

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

func recoverFido2Password(devName string, credential string, salt string, relyingParty string, pinRequired bool, userPresenceRequired bool, userVerificationRequired bool) ([]byte, error) {
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
		// Dealing with Yubikey using command-line tools is getting out of control
		// TODO: find a way to do the same using libfido2
		prompt := "Enter PIN for " + device + ":"
		if strings.HasPrefix(string(buff), prompt) {
			// fido2-assert tool requests for PIN
			pin, err := readPassword(prompt, "")
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

var hidrawDevices = make(chan string, 10) // channel that receives 'add hidraw' events

func recoverSystemdFido2Password(t luks.Token) ([]byte, error) {
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

	go func() {
		for _, d := range dir {
			// run it in a separate goroutine to avoid blocking on channel
			hidrawDevices <- d.Name()
		}
	}()

	seenHidrawDevices := make(set)

	for devName := range hidrawDevices {
		if seenHidrawDevices[devName] {
			continue
		}
		seenHidrawDevices[devName] = true

		password, err := recoverFido2Password(devName, node.Credential, node.Salt, node.RelyingParty, node.PinRequired, node.UserPresenceRequired, node.UserVerificationRequired)
		if err != nil {
			if err != io.EOF {
				info("%v", err)
			}
			continue
		}
		return password, nil
	}

	return nil, fmt.Errorf("no matching fido2 devices available")
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

// acquireKeyfilePassword reads the keyfile referenced by mapping, applying any
// configured offset and size restrictions.
func acquireKeyfilePassword(mapping *luksMapping) ([]byte, error) {
	return readKeyfile(mapping.keyfile, mapping.keyfileOffset, mapping.keyfileSize)
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

func requestKeyboardPassword(volumes chan *luks.Volume, done <-chan struct{}, d luks.Device, checkSlots []int, mappingName string, maxTries int) {
	// Wait for plymouth initialization to complete before attempting to use
	// it. Without this, udev events can trigger LUKS password prompts while
	// plymouthd is still starting, causing the graphical prompt to fail.
	waitForPlymouthInit()

	attempts := 0
	for {
		if maxTries > 0 && attempts >= maxTries {
			warning("maximum passphrase attempts (%d) reached for %s", maxTries, mappingName)
			return
		}

		prompt := fmt.Sprintf("Enter passphrase for %s:", mappingName)

		var password []byte
		var err error

		if plymouthEnabled {
			password, err = plymouthAskPassword(prompt)
			if err != nil {
				warning("plymouth password prompt failed: %v, falling back to console", err)
				password, err = readPassword(prompt, "   Unlocking...")
			}
		} else {
			password, err = readPassword(prompt, "   Unlocking...")
		}

		if err != nil {
			warning("reading password: %v", err)
			return
		}
		if len(password) == 0 {
			continue
		}
		attempts++

		if tryPassphraseAgainstSlots(volumes, done, d, checkSlots, password) {
			return
		}

		// retry password
		if plymouthEnabled {
			plymouthMessage("Incorrect passphrase, please try again")
		} else {
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
		// Header is a file on a separate filesystem device.
		mp := "/run/booster/hdrdev-" + m.name
		unmount, err := mountDeviceReadOnly(m.headerDeviceRef, mp, timeout)
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
	var senderWg sync.WaitGroup
	var keyboardOnce sync.Once

	// startKeyboard launches the keyboard (or keyfile) unlock goroutine at most once.
	startKeyboard := func() {
		senderWg.Add(1)
		go func() {
			defer senderWg.Done()
			if mapping.keyfile != "" {
				recoverKeyfilePassword(volumes, done, d, availableSlots, mapping)
			} else {
				requestKeyboardPassword(volumes, done, d, availableSlots, mapping.name, mapping.tries)
			}
		}()
	}

	// Watcher: close volumes once all senders are done so the receiver unblocks.
	go func() {
		senderWg.Wait()
		close(volumes)
	}()

	slotsWithTokens := make(map[int]bool)
	tokens, err := d.Tokens()
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.Type == "systemd-recovery" {
			continue // skipped: entered via keyboard later
		}
		t := t
		senderWg.Add(1)
		go func() {
			defer senderWg.Done()
			var password []byte
			var err error
			switch t.Type {
			case "clevis":
				password, err = recoverClevisPassword(t, d.Version())
			case "systemd-fido2":
				password, err = recoverSystemdFido2Password(t)
			case "systemd-tpm2":
				password, err = recoverSystemdTPM2Password(t)
			default:
				info("token #%d has unknown type: %s", t.ID, t.Type)
				keyboardOnce.Do(startKeyboard)
				return
			}
			if err != nil {
				warning("recovering %s token #%d failed: %v", t.Type, t.ID, err)
				keyboardOnce.Do(startKeyboard)
				return
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
				select {
				case volumes <- v:
				case <-done:
				}
				return
			}
			info("password from %s token #%d does not match", t.Type, t.ID)
			keyboardOnce.Do(startKeyboard)
		}()
		for _, s := range t.Slots {
			slotsWithTokens[s] = true
		}
	}

	// Start keyboard/keyfile unlock for any slots that have no tokens.
	var passwordSlots []int
	for _, s := range availableSlots {
		if !slotsWithTokens[s] {
			passwordSlots = append(passwordSlots, s)
		}
	}
	if len(passwordSlots) > 0 {
		keyboardOnce.Do(startKeyboard)
	}

	v, ok := <-volumes
	close(done)

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
		ref:     &deviceRef{refFsUUID, uuid},
		name:    "luks-" + uuid.toString(),
		keySlot: -1,
	}
	luksMappings = append(luksMappings, m)

	return m
}
