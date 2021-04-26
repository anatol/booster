package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

	// first try to unlock with token
	tokens, err := d.Tokens()
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.Type != luks.ClevisTokenType {
			continue
		}

		var payload []byte
		// Note that token metadata stored differently in LUKS v1 and v2
		if d.Version() == 1 {
			payload = t.Payload
		} else {
			var node struct {
				Jwe json.RawMessage
			}
			if err := json.Unmarshal(t.Payload, &node); err != nil {
				warning("%v", err)
				continue
			}
			payload = node.Jwe
		}

		// in case of a (network) error retry it several times. or maybe retry logic needs to be inside the clevis itself?
		var password []byte
		for i := 0; i < 40; i++ {
			password, err = clevis.Decrypt(payload)
			if err == nil {
				break
			} else {
				warning("%v", err)
				time.Sleep(time.Second)
			}
		}

		for _, s := range t.Slots {
			err = d.Unlock(s, password, name)
			if err == luks.ErrPassphraseDoesNotMatch {
				continue
			}
			MemZeroBytes(password)
			return err
		}
		MemZeroBytes(password)
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
