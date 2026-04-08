package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// parseCrypttab reads /etc/crypttab from the image and returns LUKS mappings.
// Silently succeeds if the file is absent.
func parseCrypttab() ([]*luksMapping, error) {
	f, err := os.Open("/etc/crypttab")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseCrypttabReader(f)
}

// parseCrypttabReader is the testable core of parseCrypttab.
func parseCrypttabReader(r io.Reader) ([]*luksMapping, error) {
	var mappings []*luksMapping
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		name := fields[0]
		deviceStr := fields[1]
		var keyfile, optStr string
		if len(fields) >= 3 {
			keyfile = fields[2]
		}
		if len(fields) >= 4 {
			optStr = fields[3]
		}

		ref, err := parseDeviceRef(deviceStr)
		if err != nil {
			return nil, fmt.Errorf("crypttab: entry %q: invalid device %q: %v", name, deviceStr, err)
		}

		m := &luksMapping{
			ref:     ref,
			name:    name,
			keySlot: -1,
		}

		// none/- means interactive passphrase
		if keyfile != "" && keyfile != "none" && keyfile != "-" {
			kfPath, kfRef, err := parsePathWithDeviceRef(keyfile, "keyfile")
			if err != nil {
				return nil, fmt.Errorf("crypttab: entry %q: %v", name, err)
			}
			m.keyfile = kfPath
			m.keyfileDeviceRef = kfRef
		}

		skip := false
		for opt := range strings.SplitSeq(optStr, ",") {
			opt = strings.TrimSpace(opt)
			if opt == "" {
				continue
			}
			switch opt {
			case "x-initrd.attach":
				// silently ignored — filtering was done by generator
			case "noauto":
				skip = true
			case "nofail":
				m.noFail = true
			case "swap", "tmp", "plain", "bitlk", "tcrypt":
				// unsupported modes — skip at boot
				skip = true
			case "luks":
				// explicit LUKS marker — booster detects LUKS via blkinfo, nothing to do
			case "discard", "same-cpu-crypt", "submit-from-crypt-cpus",
				"no-read-workqueue", "no-write-workqueue":
				if flag, ok := rdLuksOptions[opt]; ok {
					m.options = append(m.options, flag)
				}
			default:
				switch {
				case strings.HasPrefix(opt, "tries="):
					v, err := strconv.Atoi(opt[6:])
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid tries= value %q", name, opt[6:])
					}
					m.tries = v
				case strings.HasPrefix(opt, "key-slot="):
					v, err := strconv.Atoi(opt[9:])
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid key-slot= value %q", name, opt[9:])
					}
					m.keySlot = v
				case strings.HasPrefix(opt, "keyfile-offset="):
					v, err := strconv.ParseInt(opt[15:], 10, 64)
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid keyfile-offset= value %q", name, opt[15:])
					}
					m.keyfileOffset = v
				case strings.HasPrefix(opt, "keyfile-size="):
					v, err := strconv.ParseInt(opt[13:], 10, 64)
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid keyfile-size= value %q", name, opt[13:])
					}
					m.keyfileSize = v
				case strings.HasPrefix(opt, "keyfile-timeout="):
					d, err := parseCrypttabDuration(opt[16:])
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid keyfile-timeout= value %q", name, opt[16:])
					}
					m.keyfileTimeout = d
				case strings.HasPrefix(opt, "fido2-device="),
					strings.HasPrefix(opt, "tpm2-device="),
					strings.HasPrefix(opt, "token-timeout="),
					strings.HasPrefix(opt, "header="):
					// silently ignored — deferred to follow-up PRs
				default:
					debug("crypttab: entry %q: unknown option %q, ignoring", name, opt)
				}
			}
		}

		if skip {
			continue
		}

		mappings = append(mappings, m)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return mappings, nil
}

// parseCrypttabDuration parses a duration string for crypttab options such as
// keyfile-timeout=. Accepts a bare integer (treated as seconds) or any string
// accepted by time.ParseDuration (e.g. "30s", "2m").
func parseCrypttabDuration(s string) (time.Duration, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(s)
}

// luksMatchExists reports whether luksMappings already contains an entry for ref,
// allowing rd.luks.* kernel parameters to take precedence over crypttab.
func luksMatchExists(ref *deviceRef) bool {
	for _, m := range luksMappings {
		if deviceRefEqual(m.ref, ref) {
			return true
		}
	}
	return false
}

// deviceRefEqual reports whether two deviceRefs refer to the same device.
func deviceRefEqual(a, b *deviceRef) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.format != b.format {
		return false
	}
	switch a.format {
	case refFsUUID, refGptType, refGptUUID:
		return bytes.Equal(a.data.(UUID), b.data.(UUID))
	case refPath, refFsLabel, refGptLabel, refHwPath, refWwID:
		return a.data.(string) == b.data.(string)
	default:
		return false
	}
}
