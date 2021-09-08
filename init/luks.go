package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/anatol/clevis.go"
	"github.com/anatol/luks.go"
)

// rd luks options match systemd naming https://www.freedesktop.org/software/systemd/man/crypttab.html
var rdLuksOptions = map[string]string{
	"discard":                luks.FlagAllowDiscards,
	"same-cpu-crypt":         luks.FlagSameCPUCrypt,
	"submit-from-crypt-cpus": luks.FlagSubmitFromCryptCPUs,
	"no-read-workqueue":      luks.FlagNoReadWorkqueue,
	"no-write-workqueue":     luks.FlagNoWriteWorkqueue,
}

func luksApplyFlags(d luks.Device) error {
	param, ok := cmdline["rd.luks.options"]
	if !ok {
		return nil
	}

	for _, o := range strings.Split(param, ",") {
		flag, ok := rdLuksOptions[o]
		if !ok {
			return fmt.Errorf("Unknown value in rd.luks.options: %v", o)
		}
		if err := d.FlagsAdd(flag); err != nil {
			return err
		}
	}
	return nil
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

	const retryNum = 40
	// in case of a (network) error retry it several times. or maybe retry logic needs to be inside the clevis itself?
	for i := 0; i < retryNum; i++ {
		password, err := clevis.Decrypt(payload)
		if err != nil {
			debug("%v", err)
			time.Sleep(time.Second)
			continue
		}

		return password, nil
	}

	return nil, fmt.Errorf("unable to recover the password due to clevis failures")
}

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

	// Temporary workaround for a race condition when LUKS is detected faster than kernel is able to detect Yubikey
	// TODO: replace it with proper synchronization
	time.Sleep(2 * time.Second)

	dir, err := os.ReadDir("/sys/class/hidraw/")
	if err != nil {
		return nil, err
	}

	for _, d := range dir {
		devName := d.Name()

		content, err := os.ReadFile("/sys/class/hidraw/" + devName + "/device/uevent")
		if err != nil {
			warning("unable to read uevent file for %s", devName)
			continue
		}

		// TODO: find better way to identify devices that support FIDO2
		if !strings.Contains(string(content), "FIDO") {
			debug("HID %s does not support FIDO", devName)
			continue
		}

		debug("HID %s supports FIDO, trying it to recover the password", devName)

		var challenge strings.Builder
		const zeroString = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32byte zero string encoded as hex, hex.EncodeToString(make([]byte, 32))
		challenge.WriteString(zeroString)                                 // client data, an empty string
		challenge.WriteRune('\n')
		challenge.WriteString(node.RelyingParty)
		challenge.WriteRune('\n')
		challenge.WriteString(node.Credential)
		challenge.WriteRune('\n')
		challenge.WriteString(node.Salt)
		challenge.WriteRune('\n')

		device := "/dev/" + devName
		args := []string{"-G", "-h", device}
		if node.UserPresenceRequired {
			args = append(args, "-t", "up=true")
		}
		if node.UserVerificationRequired {
			args = append(args, "-t", "uv=true")
		}
		if node.PinRequired {
			args = append(args, "-t", "pin=true")
		}

		cmd := exec.Command("fido2-assert", args...)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			debug("%v", err)
			continue
		}
		stdoutReader := bufio.NewReader(stdout)

		stderr, err := cmd.StderrPipe()
		if err != nil {
			debug("%v", err)
			continue
		}

		stdin, err := cmd.StdinPipe()
		if err != nil {
			debug("%v", err)
			continue
		}

		if err := cmd.Start(); err != nil {
			debug("%v", err)
			continue
		}

		if _, err := stdin.Write([]byte(challenge.String())); err != nil {
			debug("%v", err)
			continue
		}

		if node.PinRequired {
			// wait till the command requests the pin
			buff := make([]byte, 500)
			if _, err := stderr.Read(buff); err != nil {
				debug("%v", err)
				continue
			}
			// Dealing with Yubikey using command-line tools is getting out of control
			// TODO: find a way to do the same using libfido2
			prompt := "Enter PIN for " + device + ":"
			if strings.HasPrefix(string(buff), prompt) {
				// fido2-assert tool requests for PIN
				fmt.Print(prompt)
				pin, err := readPassword()
				if err != nil {
					debug("%v", err)
					continue
				}
				pin = append(pin, '\n')
				if _, err := stdin.Write(pin); err != nil {
					debug("%v", err)
					continue
				}
			}
		}

		// hmac is the 5th element in output, skip 4 first lines
		var hmac string
		for i := 0; i < 4; i++ {
			_, _ = stdoutReader.ReadString('\n')
		}
		hmac, err = stdoutReader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				debug("%v", err)
			}
			continue
		}

		hmac = strings.TrimRight(hmac, "\n")
		if err := cmd.Wait(); err != nil {
			buff := make([]byte, 500)
			_, _ = io.ReadFull(stderr, buff)
			debug("%v: %v", err, string(buff))
			continue
		}
		return []byte(hmac), nil
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

func luksOpen(dev string, name string) error {
	wg := loadModules("dm_crypt")
	wg.Wait()

	d, err := luks.Open(dev)
	if err != nil {
		return err
	}
	defer d.Close()

	if len(d.Slots()) == 0 {
		return fmt.Errorf("device %s has no slots to unlock", dev)
	}

	if err := luksApplyFlags(d); err != nil {
		return err
	}

	// first try to unlock with tokens
	tokens, err := d.Tokens()
	if err != nil {
		return err
	}
	for tokenNum, t := range tokens {
		var password []byte

		switch t.Type {
		case "clevis":
			password, err = recoverClevisPassword(t, d.Version())
		case "systemd-fido2":
			password, err = recoverSystemdFido2Password(t)
		case "systemd-tpm2":
			password, err = recoverSystemdTPM2Password(t)
		default:
			debug("token #%d has unknown type: %s", tokenNum, t.Type)
			continue
		}

		if err != nil {
			warning("recovering %s token #%d failed: %v", t.Type, t.ID, err)
			continue // continue trying other tokens
		}

		debug("recovered password from %s token #%d", t.Type, t.ID)

		for _, s := range t.Slots {
			err = d.Unlock(s, password, name)
			if err == luks.ErrPassphraseDoesNotMatch {
				continue
			}
			MemZeroBytes(password)
			if err == nil {
				debug("password from %s token #%d matches", t.Type, tokenNum)
			}
			return err
		}
		MemZeroBytes(password)
		debug("password from %s token #%d does not match", t.Type, tokenNum)
	}

	// tokens did not work, let's unlock with a password
	for {
		fmt.Print("Enter passphrase for ", name, ":")
		password, err := readPassword()
		if err != nil {
			return err
		}
		if len(password) == 0 {
			fmt.Println("")
			continue
		}

		fmt.Println("   Unlocking...")
		for _, s := range d.Slots() {
			err = d.Unlock(s, password, name)
			if err == luks.ErrPassphraseDoesNotMatch {
				continue
			}
			MemZeroBytes(password)
			return err
		}

		// zeroify the password so we do not keep the sensitive data in the memory
		MemZeroBytes(password)

		// retry password
		fmt.Println("   Incorrect passphrase, please try again")
	}
}

func handleLuksBlockDevice(info *blkInfo, devpath string) error {
	var name string
	var matches bool

	if param, ok := cmdline["rd.luks.name"]; ok {
		parts := strings.Split(param, "=")
		if len(parts) != 2 {
			return fmt.Errorf("invalid rd.luks.name kernel parameter %s, expected format rd.luks.name=<UUID>=<name>", cmdline["rd.luks.name"])
		}
		uuid, err := parseUUID(stripQuotes(parts[0]))
		if err != nil {
			return fmt.Errorf("invalid UUID %s %v", parts[0], err)
		}
		if bytes.Equal(uuid, info.uuid) {
			matches = true
			name = parts[1]
		}
	} else if uuid, ok := cmdline["rd.luks.uuid"]; ok {
		stripped := stripQuotes(uuid)
		u, err := parseUUID(stripped)
		if err != nil {
			return fmt.Errorf("invalid UUID %s in rd.luks.uuid boot param: %v", uuid, err)
		}
		if bytes.Equal(u, info.uuid) {
			matches = true
			name = "luks-" + stripped
		}
	}
	if matches {
		go func() {
			// opening a luks device is a slow operation, run it in a separate goroutine
			if err := luksOpen(devpath, name); err != nil {
				severe("%v", err)
			}
		}()
	} else {
		debug("luks device %s does not match rd.luks.xx param", devpath)
	}
	return nil
}
