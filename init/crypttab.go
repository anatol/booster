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

		m := newLuksMapping(ref, name)

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
			key, value, hasValue := strings.Cut(opt, "=")

			// Splitting on the first '=' keeps a value that contains one intact,
			// as header=/luks.hdr:LABEL=hdrdev does.
			if hasValue {
				switch key {
				case "tries":
					v, err := strconv.Atoi(value)
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid tries= value %q", name, value)
					}
					m.tries = v
				case "key-slot":
					v, err := strconv.Atoi(value)
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid key-slot= value %q", name, value)
					}
					m.keySlot = v
				case "keyfile-offset":
					v, err := strconv.ParseInt(value, 10, 64)
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid keyfile-offset= value %q", name, value)
					}
					m.keyfileOffset = v
				case "keyfile-size":
					v, err := strconv.ParseInt(value, 10, 64)
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid keyfile-size= value %q", name, value)
					}
					m.keyfileSize = v
				case "keyfile-timeout":
					d, err := parseCrypttabDuration(value)
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid keyfile-timeout= value %q", name, value)
					}
					m.keyfileTimeout = d
					m.keyfileTimeoutExplicit = true
				case "token-timeout":
					d, err := parseTokenTimeout(value)
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: invalid token-timeout= value %q", name, value)
					}
					m.tokenTimeout = d
					m.tokenTimeoutExplicit = true
				case "header":
					hdrPath, hdrRef, err := parsePathWithDeviceRef(value, "header")
					if err != nil {
						return nil, fmt.Errorf("crypttab: entry %q: %v", name, err)
					}
					m.header = hdrPath
					m.headerDeviceRef = hdrRef
				case "tpm2-measure-pcr":
					// yes forces the volume-key measurement, no suppresses it;
					// unset = auto (extend iff a token binds PCR15).
					s, valid := parseMeasurePCR(value)
					if !valid {
						return nil, fmt.Errorf("crypttab: entry %q: invalid tpm2-measure-pcr= value %q", name, value)
					}
					m.measurePCR = s
				case "tpm2-signature":
					// signed PCR policy: path to a systemd PCR signature JSON,
					// "false" to disable, unset to auto-discover.
					m.tpm2Signature = value
				case "fido2-device", "tpm2-device":
					// accepted for compatibility; token detection uses LUKS2 header
				default:
					debug("crypttab: entry %q: unknown option %q, ignoring", name, opt)
				}
				continue
			}

			switch key {
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
			default:
				if flag, ok := rdLuksOptions[key]; ok {
					m.options = append(m.options, flag)
					continue
				}
				debug("crypttab: entry %q: unknown option %q, ignoring", name, opt)
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

// findLuksMapping returns the existing luksMapping for ref, or nil if not found.
func findLuksMapping(ref *deviceRef) *luksMapping {
	for _, m := range luksMappings {
		if deviceRefEqual(m.ref, ref) {
			return m
		}
	}
	return nil
}

// mergeCrypttabOptions merges security-relevant options from a crypttab entry (src)
// into a cmdline-derived mapping (dst). dst's ref and name are preserved; crypttab
// supplies keyfile, header, and other unlock options that rd.luks.* params cannot express.
func mergeCrypttabOptions(dst, src *luksMapping) {
	// Adopt crypttab's token-timeout only when the cmdline mapping did not
	// carry an explicit token-timeout= of its own. Mirrors the keyfile/
	// header/tries merges below: an explicit cmdline value always wins;
	// crypttab fills in only what the cmdline left unset. (src.tokenTimeout
	// is always >0 here — the crypttab parser fills a 30 s implicit default
	// — so the gate must be the explicit flags, not the values.)
	if !dst.tokenTimeoutExplicit && src.tokenTimeoutExplicit {
		dst.tokenTimeout = src.tokenTimeout
		dst.tokenTimeoutExplicit = true
	}
	if dst.keyfile == "" && src.keyfile != "" {
		dst.keyfile = src.keyfile
		dst.keyfileDeviceRef = src.keyfileDeviceRef
		dst.keyfileOffset = src.keyfileOffset
		dst.keyfileSize = src.keyfileSize
		dst.keyfileTimeout = src.keyfileTimeout
		dst.keyfileTimeoutExplicit = src.keyfileTimeoutExplicit
	}
	if dst.keySlot == -1 && src.keySlot != -1 {
		dst.keySlot = src.keySlot
	}
	if dst.tries == 0 && src.tries != 0 {
		dst.tries = src.tries
	}
	if dst.header == "" && src.header != "" {
		dst.header = src.header
		dst.headerDeviceRef = src.headerDeviceRef
	}
	if dst.measurePCR == measurePCRAuto && src.measurePCR != measurePCRAuto {
		dst.measurePCR = src.measurePCR
	}
	if dst.tpm2Signature == "" && src.tpm2Signature != "" {
		dst.tpm2Signature = src.tpm2Signature
	}
	dst.options = append(dst.options, src.options...)
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
