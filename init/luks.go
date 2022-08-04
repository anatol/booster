package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/anatol/clevis.go"
	"github.com/anatol/luks.go"
)

// specifies information needed to process/open a LUKS device
// often these mappings specified by a user via command-line
type luksMapping struct {
	ref     *deviceRef
	name    string
	options []string
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
	for {
		password, err := clevis.Decrypt(payload)
		if err != nil {
			var netError *net.OpError
			if !errors.As(err, &netError) {
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

func recoverFido2Password(devName string, credential string, salt string, relyingParty string, pinRequired bool, userPresenceRequired bool, userVerificationRequired bool) ([]byte, error) {
	ueventContent, err := os.ReadFile("/sys/class/hidraw/" + devName + "/device/uevent")
	if err != nil {
		return nil, fmt.Errorf("unable to read uevent file for %s", devName)
	}

	// TODO: find better way to identify devices that support FIDO2
	if !strings.Contains(string(ueventContent), "FIDO") {
		return nil, fmt.Errorf("HID %s does not support FIDO", devName)
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

	password, err := tpm2Unseal(public, private, node.PCRs, bank, policyHash)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(password)), nil
}

func recoverTokenPassword(volumes chan *luks.Volume, d luks.Device, t luks.Token) {
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
		return
	}

	if err != nil {
		warning("recovering %s token #%d failed: %v", t.Type, t.ID, err)
		return
	}

	info("recovered password from %s token #%d", t.Type, t.ID)

	for _, s := range t.Slots {
		v, err := d.UnsealVolume(s, password)
		if err == luks.ErrPassphraseDoesNotMatch {
			continue
		}
		info("password from %s token #%d matches", t.Type, t.ID)
		volumes <- v
		return
	}
	info("password from %s token #%d does not match", t.Type, t.ID)
}

func requestKeyboardPassword(volumes chan *luks.Volume, d luks.Device, checkSlots []int, mappingName string) {
	for {
		prompt := fmt.Sprintf("Enter passphrase for %s:", mappingName)
		password, err := readPassword(prompt, "   Unlocking...")
		if err != nil {
			warning("reading password: %v", err)
			return
		}
		if len(password) == 0 {
			continue
		}

		for _, s := range checkSlots {
			v, err := d.UnsealVolume(s, password)
			if err == luks.ErrPassphraseDoesNotMatch {
				continue
			}
			volumes <- v
			return
		}

		// retry password
		console("   Incorrect passphrase, please try again\n")
	}
}

func luksOpen(dev string, mapping *luksMapping) error {
	module, err := loadModules("dm_crypt")
	if err != nil {
		return err
	}

	d, err := luks.Open(dev)
	if err != nil {
		return err
	}
	defer d.Close()

	if len(d.Slots()) == 0 {
		return fmt.Errorf("device %s has no slots to unlock", dev)
	}

	if err := d.FlagsAdd(mapping.options...); err != nil {
		return err
	}

	volumes := make(chan *luks.Volume)

	slotsWithTokens := make(map[int]bool)
	tokens, err := d.Tokens()
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.Type == "systemd-recovery" {
			continue // skip systemd-recovery tokens as they are supposed to be entered by a keyboard later
		}
		go recoverTokenPassword(volumes, d, t)
		for _, s := range t.Slots {
			slotsWithTokens[s] = true
		}
	}

	var checkSlotsWithPassword []int
	for _, s := range d.Slots() {
		if !slotsWithTokens[s] {
			// only slots that do not have tokens will be checked with keyboard password
			checkSlotsWithPassword = append(checkSlotsWithPassword, s)
		}
	}
	if len(checkSlotsWithPassword) > 0 {
		go requestKeyboardPassword(volumes, d, checkSlotsWithPassword, mapping.name)
	}

	v := <-volumes

	module.Wait()
	return v.SetupMapper(mapping.name)
}

func matchLuksMapping(blk *blkInfo) *luksMapping {
	for _, m := range luksMappings {
		if blk.matchesRef(m.ref) {
			return &m
		}
	}

	// a special case coming from autodiscoverable partitions https://systemd.io/DISCOVERABLE_PARTITIONS/
	// is to check whether this partition was specified as a 'root' and if yes - mount it and re-point root to the new location under /dev/mapper/xxx)
	if blk.matchesRef(cmdRoot) {
		info("LUKS device %s matches root=, unlock this device", blk.path)
		m := &luksMapping{
			ref:  cmdRoot,
			name: "root",
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

	return luksOpen(blk.path, m)
}
