package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anatol/clevis.go"
	"github.com/anatol/luks.go"
	"golang.org/x/crypto/ssh/terminal"
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
				fmt.Println(err)
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
				fmt.Println(err)
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
		password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		if len(password) == 0 {
			fmt.Println("")
			continue
		}

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
		fmt.Println("   incorrect passphrase, please try again")
	}
}
