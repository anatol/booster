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

// parseLuksOptions applies crypttab-syntax options to m. ctx prefixes messages
// to name the source; skip reports an option that opts the entry out entirely.
func parseLuksOptions(m *luksOptions, optStr, ctx string) (skip bool, err error) {
	var netdev bool
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
					return false, fmt.Errorf("%s: invalid tries= value %q", ctx, value)
				}
				m.tries = v
			case "key-slot":
				v, err := strconv.Atoi(value)
				if err != nil {
					return false, fmt.Errorf("%s: invalid key-slot= value %q", ctx, value)
				}
				m.keySlot = v
			case "keyfile-offset":
				v, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					return false, fmt.Errorf("%s: invalid keyfile-offset= value %q", ctx, value)
				}
				m.keyfileOffset = v
			case "keyfile-size":
				v, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					return false, fmt.Errorf("%s: invalid keyfile-size= value %q", ctx, value)
				}
				m.keyfileSize = v
			case "keyfile-timeout":
				d, err := parseCrypttabDuration(value)
				if err != nil {
					return false, fmt.Errorf("%s: invalid keyfile-timeout= value %q", ctx, value)
				}
				m.keyfileTimeout = d
			case "token-timeout":
				d, err := parseTokenTimeout(value)
				if err != nil {
					return false, fmt.Errorf("%s: invalid token-timeout= value %q", ctx, value)
				}
				m.tokenTimeout = d
			case "header":
				hdrPath, hdrRef, err := parsePathWithDeviceRef(value, "header")
				if err != nil {
					return false, fmt.Errorf("%s: %v", ctx, err)
				}
				m.header = hdrPath
				m.headerDeviceRef = hdrRef
			case "tpm2-measure-pcr":
				// yes forces the volume-key measurement, no suppresses it;
				// unset = auto (extend iff a token binds PCR15).
				s, valid := parseMeasurePCR(value)
				if !valid {
					return false, fmt.Errorf("%s: invalid tpm2-measure-pcr= value %q", ctx, value)
				}
				m.measurePCR = s
			case "tpm2-signature":
				// signed PCR policy: path to a systemd PCR signature JSON,
				// "false" to disable, unset to auto-discover.
				m.tpm2Signature = value
			case "fido2-device", "tpm2-device":
				// accepted for compatibility; token detection uses LUKS2 header
			default:
				warning("%s: unknown option %q, ignoring", ctx, opt)
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
		case "_netdev":
			// booster has no unit graph to order; the network assertion is
			// checked after the loop, so a discarded entry stays quiet
			netdev = true
		default:
			if flag, ok := rdLuksOptions[key]; ok {
				m.options = addFlag(m.options, flag)
				continue
			}
			warning("%s: unknown option %q, ignoring", ctx, opt)
		}
	}
	if !skip && netdev && config.Network == nil {
		warning("%s: _netdev needs the network, but none is configured; unlock will be attempted without it", ctx)
	}
	return skip, nil
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

		skip, err := parseLuksOptions(&m.luksOptions, optStr, fmt.Sprintf("crypttab: entry %q", name))
		if err != nil {
			return nil, err
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

// resolveLuksOptions composes the fourth crypttab field for every device,
// lowest priority first, so the order of these calls is the precedence rule:
//
//	crypttab  ->  rd.luks.options=  ->  rd.luks.header=  ->  rd.luks.options=$UUID=
func resolveLuksOptions(ctMappings []*luksMapping) {
	for _, cm := range ctMappings {
		opts := cm.luksOptions
		existing := findLuksMapping(cm.ref)
		if existing == nil {
			// a device nothing else names: its own entry is its only source,
			// and it is composed below like any other
			cm.crypttabOptions = &opts
			luksMappings = append(luksMappings, cm)
			continue
		}
		existing.crypttabOptions = &opts
		switch {
		case existing.keyfile == "" && cm.keyfile != "":
			existing.keyfile = cm.keyfile
			existing.keyfileDeviceRef = cm.keyfileDeviceRef
		case cm.keyfile != "":
			// rd.luks.key= won field 3, so the entry's keyfile-* bounds describe
			// a file booster is not going to read
			opts.keyfileOffset, opts.keyfileSize = 0, 0
			opts.keyfileTimeout = luksOptionUnset
		}
	}

	for _, m := range luksMappings {
		merged := newLuksOptions()

		if ct := m.crypttabOptions; ct != nil {
			overlay(&merged, ct)
		}
		applyGlobalOptions(&merged)
		if h := m.deprecatedHeader; h != nil {
			overlay(&merged, h)
		}
		if pd := m.cmdlineOptions; pd != nil {
			overlay(&merged, pd)
		}

		m.luksOptions = merged
	}
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

// applyGlobalOptions overlays the rd.luks.options= list that carried no UUID.
// A global header= was warned about while parsing; it is dropped here so it
// cannot reach a device.
func applyGlobalOptions(dst *luksOptions) {
	global := globalLuksOptions
	global.header, global.headerDeviceRef = "", nil
	overlay(dst, &global)
}
