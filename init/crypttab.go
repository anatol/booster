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

// parsePathWithDeviceRef parses a "path:SPECIFIER=value" string where the
// right side of the colon is a device specifier (UUID=, LABEL=, PARTUUID=,
// PARTLABEL=).  If matched, path is the left side and ref is the parsed device
// ref.  Otherwise path == raw and ref == nil.
// fieldName is used only in error messages (e.g. "keyfile", "header").
func parsePathWithDeviceRef(raw, fieldName string) (path string, ref *deviceRef, err error) {
	if idx := strings.Index(raw, ":"); idx >= 0 {
		right := raw[idx+1:]
		if strings.HasPrefix(right, "UUID=") || strings.HasPrefix(right, "LABEL=") ||
			strings.HasPrefix(right, "PARTUUID=") || strings.HasPrefix(right, "PARTLABEL=") {
			ref, err = parseDeviceRef(right)
			if err != nil {
				return "", nil, fmt.Errorf("%s device ref %q: %v", fieldName, right, err)
			}
			return raw[:idx], ref, nil
		}
	}
	return raw, nil, nil
}

// parseKeyfileField parses the keyfile field from a crypttab or rd.luks.key
// value.  If the right-hand side of a colon is a device specifier, the device
// ref is returned and path contains only the left-hand side (path on that
// device).  Otherwise path == raw and ref == nil.
func parseKeyfileField(raw string) (path string, ref *deviceRef, err error) {
	return parsePathWithDeviceRef(raw, "keyfile")
}

// parseHeaderField is the header= analogue of parseKeyfileField.
// Used by rd.luks.header= (cmdline); crypttab header= stores the value verbatim.
func parseHeaderField(raw string) (path string, ref *deviceRef, err error) {
	return parsePathWithDeviceRef(raw, "header")
}

// parseCrypttab reads /etc/crypttab (bundled by the generator from the host's
// /etc/crypttab, filtered to x-initrd.attach entries) and returns a slice of
// LUKS mappings to unlock at boot.
// Returns nil without error if /etc/crypttab is absent.
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

// parseCrypttabReader is the testable core: it parses crypttab lines from r.
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

		var keyfile string
		if len(fields) >= 3 {
			keyfile = fields[2]
			if keyfile == "none" || keyfile == "-" {
				keyfile = ""
			}
		}

		var optStr string
		if len(fields) >= 4 {
			optStr = fields[3]
		}

		var (
			noauto          bool
			noFail          bool
			options         []string
			header          string
			keySlot         = -1
			tries           int
			keyfileOffset   int64
			keyfileSize     int64
			keyfileTimeout  time.Duration
			fido2           bool
			tpm2            bool
			timeout         time.Duration
			timeoutExplicit bool
		)

		for _, opt := range strings.Split(optStr, ",") {
			opt = strings.TrimSpace(opt)
			switch {
			case opt == "":
				continue
			case opt == "noauto":
				noauto = true
			case opt == "swap" || opt == "tmp" || opt == "plain" || opt == "bitlk" || opt == "tcrypt":
				// non-LUKS modes — skip this entry
				noauto = true
			case strings.HasPrefix(opt, "fido2-device="):
				fido2 = true
			case strings.HasPrefix(opt, "tpm2-device="):
				tpm2 = true
			case strings.HasPrefix(opt, "token-timeout="):
				d, err := parseTokenTimeout(strings.TrimPrefix(opt, "token-timeout="))
				if err != nil {
					return nil, fmt.Errorf("crypttab entry %q: invalid token-timeout: %v", name, err)
				}
				timeout = d
				timeoutExplicit = true
			case strings.HasPrefix(opt, "keyfile-timeout="):
				d, err := parseTokenTimeout(strings.TrimPrefix(opt, "keyfile-timeout="))
				if err != nil {
					return nil, fmt.Errorf("crypttab entry %q: invalid keyfile-timeout: %v", name, err)
				}
				keyfileTimeout = d
			case strings.HasPrefix(opt, "header="):
				header = strings.TrimPrefix(opt, "header=")
			case strings.HasPrefix(opt, "key-slot="):
				n, err := strconv.Atoi(strings.TrimPrefix(opt, "key-slot="))
				if err != nil {
					return nil, fmt.Errorf("crypttab entry %q: invalid key-slot: %v", name, err)
				}
				keySlot = n
			case opt == "nofail":
				noFail = true
			case strings.HasPrefix(opt, "keyfile-offset="):
				n, err := strconv.ParseInt(strings.TrimPrefix(opt, "keyfile-offset="), 10, 64)
				if err != nil || n < 0 {
					return nil, fmt.Errorf("crypttab entry %q: invalid keyfile-offset: %q", name, strings.TrimPrefix(opt, "keyfile-offset="))
				}
				keyfileOffset = n
			case strings.HasPrefix(opt, "keyfile-size="):
				n, err := strconv.ParseInt(strings.TrimPrefix(opt, "keyfile-size="), 10, 64)
				if err != nil || n < 0 {
					return nil, fmt.Errorf("crypttab entry %q: invalid keyfile-size: %q", name, strings.TrimPrefix(opt, "keyfile-size="))
				}
				keyfileSize = n
			case strings.HasPrefix(opt, "tries="):
				n, err := strconv.Atoi(strings.TrimPrefix(opt, "tries="))
				if err != nil || n < 0 {
					return nil, fmt.Errorf("crypttab entry %q: invalid tries value: %q", name, strings.TrimPrefix(opt, "tries="))
				}
				tries = n
			default:
				if flag, ok := rdLuksOptions[opt]; ok {
					options = append(options, flag)
				}
				// unknown options are silently ignored, matching systemd behaviour
			}
		}

		if noauto {
			continue
		}

		ref, err := parseDeviceRef(deviceStr)
		if err != nil {
			return nil, fmt.Errorf("crypttab entry %q: invalid device %q: %v", name, deviceStr, err)
		}

		keyfilePath, keyfileRef, err := parseKeyfileField(keyfile)
		if err != nil {
			return nil, fmt.Errorf("crypttab entry %q: %v", name, err)
		}

		if keyfileRef != nil && deviceRefEqual(ref, keyfileRef) {
			return nil, fmt.Errorf("crypttab entry %q: keyfile device must not be the LUKS device", name)
		}

		m := &luksMapping{
			ref:              ref,
			name:             name,
			keyfile:          keyfilePath,
			options:          options,
			header:           header,
			keySlot:          keySlot,
			tries:            tries,
			noFail:           noFail,
			keyfileOffset:    keyfileOffset,
			keyfileSize:      keyfileSize,
			keyfileDeviceRef: keyfileRef,
			keyfileTimeout:   keyfileTimeout,
		}
		m.tokenFido2 = fido2
		m.tokenTpm2 = tpm2
		// Apply default 30 s token timeout when a token option is set without an
		// explicit token-timeout=, matching the rd.luks.options behaviour in cmdline.go.
		if (fido2 || tpm2) && !timeoutExplicit {
			m.tokenTimeout = 30 * time.Second
		} else {
			m.tokenTimeout = timeout
		}

		mappings = append(mappings, m)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return mappings, nil
}

// luksMatchExists reports whether luksMappings already contains an entry whose
// device reference matches ref.  Used to let kernel cmdline take precedence over
// /etc/crypttab entries.
func luksMatchExists(ref *deviceRef) bool {
	for _, m := range luksMappings {
		if deviceRefEqual(m.ref, ref) {
			return true
		}
	}
	return false
}

// deviceRefEqual returns true when a and b describe the same device.
func deviceRefEqual(a, b *deviceRef) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.format != b.format {
		return false
	}
	switch a.format {
	case refFsUUID, refGptUUID:
		return bytes.Equal(a.data.(UUID), b.data.(UUID))
	case refGptUUIDPartoff:
		ad, bd := a.data.(gptPartoffData), b.data.(gptPartoffData)
		return bytes.Equal(ad.uuid, bd.uuid) && ad.offset == bd.offset
	case refFsLabel, refGptLabel, refPath, refHwPath, refWwID:
		return a.data.(string) == b.data.(string)
	default:
		return false
	}
}
