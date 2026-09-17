package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
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
// to name the source; skip names the option that opts the entry out entirely.
func parseLuksOptions(m *luksOptions, optStr, ctx string) (skip string, err error) {
	var unknown []string
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
				if err != nil || v < 0 {
					return "", fmt.Errorf("%s: invalid tries= value %q", ctx, value)
				}
				m.tries = v
				m.appliedOptions = append(m.appliedOptions, opt)
			case "key-slot":
				v, err := strconv.Atoi(value)
				if err != nil || v < 0 {
					return "", fmt.Errorf("%s: invalid key-slot= value %q", ctx, value)
				}
				m.keySlot = v
				m.appliedOptions = append(m.appliedOptions, opt)
			case "keyfile-offset":
				v, err := strconv.ParseInt(value, 10, 64)
				if err != nil || v < 0 {
					return "", fmt.Errorf("%s: invalid keyfile-offset= value %q", ctx, value)
				}
				m.keyfileOffset = v
				m.appliedOptions = append(m.appliedOptions, opt)
			case "keyfile-size":
				v, err := strconv.ParseInt(value, 10, 64)
				if err != nil || v < 0 {
					return "", fmt.Errorf("%s: invalid keyfile-size= value %q", ctx, value)
				}
				m.keyfileSize = v
				m.appliedOptions = append(m.appliedOptions, opt)
			case "keyfile-timeout":
				d, err := parseCrypttabDuration(value)
				if err != nil {
					return "", fmt.Errorf("%s: invalid keyfile-timeout= value %q", ctx, value)
				}
				m.keyfileTimeout = d
				m.appliedOptions = append(m.appliedOptions, opt)
			case "token-timeout":
				d, err := parseTokenTimeout(value)
				if err != nil {
					return "", fmt.Errorf("%s: invalid token-timeout= value %q", ctx, value)
				}
				m.tokenTimeout = d
				m.appliedOptions = append(m.appliedOptions, opt)
			case "header":
				hdrPath, hdrRef, err := parsePathWithDeviceRef(value, "header")
				if err != nil {
					return "", fmt.Errorf("%s: %v", ctx, err)
				}
				m.header = hdrPath
				m.headerDeviceRef = hdrRef
				m.appliedOptions = append(m.appliedOptions, opt)
			case "tpm2-measure-pcr":
				// yes forces the volume-key measurement, no suppresses it;
				// unset = auto (extend iff a token binds PCR15).
				s, valid := parseMeasurePCR(value)
				if !valid {
					return "", fmt.Errorf("%s: invalid tpm2-measure-pcr= value %q", ctx, value)
				}
				m.measurePCR = s
				m.appliedOptions = append(m.appliedOptions, opt)
			case "tpm2-signature":
				// signed PCR policy: path to a systemd PCR signature JSON,
				// "false" to disable, unset to auto-discover.
				m.tpm2Signature = value
				m.appliedOptions = append(m.appliedOptions, opt)
			case "fido2-device", "tpm2-device":
				// accepted for compatibility; token detection uses LUKS2 header
			default:
				unknown = append(unknown, opt)
			}
			continue
		}

		switch key {
		case "x-initrd.attach":
			// silently ignored — filtering was done by generator
		case "noauto":
			skip = opt
		case "nofail":
			m.noFail = true
			m.appliedOptions = append(m.appliedOptions, opt)
		case "swap", "tmp", "plain", "bitlk", "tcrypt":
			// booster unlocks LUKS volumes only
			skip = opt
		case "luks":
			// explicit LUKS marker — booster detects LUKS via blkinfo, nothing to do
		case "_netdev":
			// booster has no unit graph to order; the network assertion is
			// checked after the loop, so a discarded entry stays quiet
			netdev = true
		default:
			if flag, ok := rdLuksOptions[key]; ok {
				m.options = addFlag(m.options, flag)
				m.appliedOptions = append(m.appliedOptions, opt)
				continue
			}
			unknown = append(unknown, opt)
		}
	}
	if skip == "" {
		for _, opt := range unknown {
			warning("%s: unknown option %q, ignoring", ctx, opt)
		}
		if netdev && config.Network == nil {
			warning("%s: _netdev needs the network, but none is configured; unlock will be attempted without it", ctx)
		}
	}
	return skip, nil
}

// joinOptions renders an option list for a message. appliedOptions records
// what was parsed, repeats included -- a flag named twice, two lists naming
// the same one -- and echoing a repeat back as something to paste is noise.
func joinOptions(opts []string) string {
	seen := make(map[string]bool, len(opts))
	unique := make([]string, 0, len(opts))
	for _, o := range opts {
		if !seen[o] {
			seen[o] = true
			unique = append(unique, o)
		}
	}
	return strings.Join(unique, ",")
}

// reportSkippedEntry explains why ctx's device will not be unlocked.
func reportSkippedEntry(ctx, skip string) {
	if skip == "noauto" {
		info("%s: noauto is set, not unlocking it", ctx)
	} else {
		warning("%s: cannot unlock a %q volume", ctx, skip)
	}
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

		if skip != "" {
			reportSkippedEntry(fmt.Sprintf("crypttab: entry %q", name), skip)
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
	d, err := parseCrypttabDurationValue(s)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		// a negative duration would collide with luksOptionUnset and read as
		// "nothing set it"
		return 0, fmt.Errorf("negative duration %q", s)
	}
	return d, nil
}

func parseCrypttabDurationValue(s string) (time.Duration, error) {
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

// resolveLuksOptions pairs each crypttab entry with the command-line record
// using the same device reference, then composes every record. It returns the
// messages it logged.
func resolveLuksOptions(ctMappings []*luksMapping) []string {
	if globalLuksKeyfile != "" {
		// the command line's own default, so it fills before crypttab does
		for _, m := range luksMappings {
			if m.keyfile == "" {
				m.keyfile = globalLuksKeyfile
			}
		}
	}

	for _, cm := range ctMappings {
		opts := cm.luksOptions
		cm.crypttabOptions = &opts
		cm.fromCrypttab = true

		existing := findLuksMapping(cm.ref)
		if existing == nil {
			// a device nothing else names: its own entry is its only source,
			// and it is composed below like any other
			luksMappings = append(luksMappings, cm)
			continue
		}
		existing.pairingConflicts = append(existing.pairingConflicts, pairCrypttabEntry(existing, cm)...)
	}

	var logged []string
	for _, m := range luksMappings {
		m.luksOptions, m.optionConflicts, m.setAside = composedOptions(m)
		// logged now, not on arrival, so a device that never shows up still reports it
		logged = append(logged, reportSetAside(m.setAside)...)
	}
	return logged
}

// pairCrypttabEntry hands m the entry's fourth field and key file. Booster's
// rule today is that the command line owns fields 1 and 2 and outranks the
// entry on field 3, where systemd's generator and dracut both give all three
// to the entry.
//
// A device answering to two entries is paired twice, so the field is overlaid
// rather than assigned: the later entry wins what it names and the earlier one
// keeps the rest.
func pairCrypttabEntry(m, entry *luksMapping) []luksConflict {
	opts := *entry.crypttabOptions
	from := sourceLabel(entry)
	var conflicts []luksConflict

	if entry.name != m.name {
		conflicts = append(conflicts, luksConflict{
			field: "volume name", kept: m.name, keptFrom: sourceLabel(m),
			dropped: entry.name, droppedFrom: from,
		})
	}

	switch {
	case m.keyfile == "" && entry.keyfile != "":
		m.keyfile = entry.keyfile
		m.keyfileDeviceRef = entry.keyfileDeviceRef
		m.keyfileFrom = from
	case entry.keyfile != "":
		kept := keyfileLabel(m)
		if entry.keyfile != m.keyfile {
			conflicts = append(conflicts, luksConflict{
				field: "key file", kept: withDeviceRef(m.keyfile, m.keyfileDeviceRef), keptFrom: kept,
				dropped: withDeviceRef(entry.keyfile, entry.keyfileDeviceRef), droppedFrom: keyfileLabel(entry),
			})
		}
		// another source won field 3, so the entry's keyfile-* bounds describe
		// a file booster is not going to read
		conflicts = append(conflicts, keyfileBoundConflicts(&opts, from, kept)...)
		opts.keyfileOffset, opts.keyfileSize = 0, 0
		opts.keyfileTimeout = luksOptionUnset
	}

	earlier := crypttabLabel(m)
	m.crypttabNames = append(slices.Clone(entryNames(m)), entry.name)

	if m.crypttabOptions == nil {
		m.crypttabOptions = &opts
		return conflicts
	}

	for _, c := range conflictingFields(m.crypttabOptions, &opts) {
		c.keptFrom, c.droppedFrom = from, earlier
		conflicts = append(conflicts, c)
	}

	// The entry record is shared by every device goroutine that pairs with it,
	// and appending to its slices in place would race. Merge into copies.
	merged := *m.crypttabOptions
	merged.options = slices.Clone(merged.options)
	merged.appliedOptions = slices.Clone(merged.appliedOptions)
	overlay(&merged, &opts)
	m.crypttabOptions = &merged

	return conflicts
}

func sourceLabel(m *luksMapping) string {
	if !m.fromCrypttab {
		return "the command line"
	}
	return crypttabLabel(m)
}

// entryNames lists the volume name (field 1) of every entry merged into m, m's
// own first when m is an entry.
func entryNames(m *luksMapping) []string {
	if len(m.crypttabNames) == 0 && m.fromCrypttab {
		return []string{m.name}
	}
	return m.crypttabNames
}

// crypttabLabel names the entries a record's crypttab half came from.
func crypttabLabel(m *luksMapping) string {
	names := entryNames(m)
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = strconv.Quote(n)
	}
	if len(quoted) == 1 {
		return "crypttab entry " + quoted[0]
	}
	return "crypttab entries " + strings.Join(quoted, ", ")
}

func keyfileLabel(m *luksMapping) string {
	switch {
	case m.keyfileFrom != "":
		return m.keyfileFrom
	case m.fromCrypttab:
		// entries merged into this record share its options, not its key file
		return fmt.Sprintf("crypttab entry %q", m.name)
	}
	return sourceLabel(m)
}

func keyfileBoundConflicts(opts *luksOptions, from, replacedBy string) []luksConflict {
	displaced := func(field string, v any) luksConflict {
		return luksConflict{
			field: field, dropped: fmt.Sprint(v), droppedFrom: from,
			note: fmt.Sprintf("It bounds a key file %s replaced", replacedBy),
		}
	}
	var out []luksConflict
	if opts.keyfileOffset != 0 {
		out = append(out, displaced("keyfile-offset", opts.keyfileOffset))
	}
	if opts.keyfileSize != 0 {
		out = append(out, displaced("keyfile-size", opts.keyfileSize))
	}
	if opts.keyfileTimeout != luksOptionUnset {
		out = append(out, displaced("keyfile-timeout", opts.keyfileTimeout))
	}
	return out
}

// composedOptions folds a device's sources into the options it is unlocked
// with, lowest priority first, so the order of these overlays is the precedence
// rule:
//
//	crypttab  ->  rd.luks.options=  ->  rd.luks.header=  ->  rd.luks.options=$UUID=
//
// It reports nothing: a device with two records is composed a second time.
func composedOptions(m *luksMapping) (opts luksOptions, conflicts []luksConflict, setAside []string) {
	merged := newLuksOptions()

	// owner records which source set each field's current value
	owner := make(map[string]string, len(luksOptionFields))
	apply := func(src *luksOptions, label string) {
		for _, c := range conflictingFields(&merged, src) {
			c.keptFrom, c.droppedFrom = label, owner[c.field]
			conflicts = append(conflicts, c)
		}
		overlay(&merged, src)
		for _, f := range luksOptionFields {
			if f.set(src) {
				owner[f.name] = label
			}
		}
	}

	if ct := m.crypttabOptions; ct != nil {
		if m.cmdlineOptions != nil {
			// A per-device rd.luks.options= replaces the entry's option
			// field, so the entry contributes none of it.
			if len(ct.appliedOptions) > 0 {
				setAside = append(setAside, fmt.Sprintf("crypttab: %s: options %q dropped. A per-device rd.luks.options= replaces a crypttab entry's options rather than adding to them. Repeat on the command line any that are still needed.",
					strings.TrimPrefix(crypttabLabel(m), "crypttab "), joinOptions(ct.appliedOptions)))
			}
		} else {
			apply(ct, crypttabLabel(m))
		}
	}

	global := globalLuksOptions
	global.header, global.headerDeviceRef = "", nil
	apply(&global, "rd.luks.options= carrying no UUID")

	if h := m.deprecatedHeader; h != nil {
		apply(h, "rd.luks.header=")
	}
	if pd := m.cmdlineOptions; pd != nil {
		apply(pd, "rd.luks.options=$UUID=")
	}

	return merged, conflicts, setAside
}

// reportedSetAside keeps a set-aside warning from repeating when a device
// is composed again on arrival.
var reportedSetAside sync.Map

func reportSetAside(msgs []string) []string {
	var logged []string
	for _, msg := range msgs {
		if _, seen := reportedSetAside.LoadOrStore(msg, true); seen {
			continue
		}
		info("%s", msg)
		logged = append(logged, msg)
	}
	return logged
}

// reportedConflicts keeps a parked headerless device, dispatched again for every
// header device that shows up (retryPendingDevices), from repeating itself.
var reportedConflicts sync.Map

// reportLuksConflicts logs once per device and returns the messages, since
// warning() reaches only /dev/kmsg and the console.
func reportLuksConflicts(device string, conflicts []luksConflict) []string {
	if len(conflicts) == 0 {
		return nil
	}
	if _, seen := reportedConflicts.LoadOrStore(device, true); seen {
		return nil
	}
	msgs := conflictMessages(conflicts)
	for _, msg := range msgs {
		info("LUKS device %s: %s", device, msg)
	}
	// a lost volume name is only a problem when root= waits for it
	if root, ok := rootMapperName(); ok {
		for _, c := range conflicts {
			if c.field == "volume name" && c.dropped == root {
				msg := fmt.Sprintf("root=/dev/mapper/%s will not appear: LUKS device %s is unlocked as %q", root, device, c.kept)
				warning("%s", msg)
				msgs = append(msgs, msg)
			}
		}
	}
	return msgs
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
