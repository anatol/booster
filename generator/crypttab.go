package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// isKeyfileOnDevice reports whether kf is a keyfile-on-device specifier of the
// form "/path:UUID=xxx", "/path:LABEL=xxx", "/path:PARTUUID=xxx", or "/path:PARTLABEL=xxx".
func isKeyfileOnDevice(kf string) bool {
	idx := strings.Index(kf, ":")
	if idx < 0 {
		return false
	}
	r := kf[idx+1:]
	return strings.HasPrefix(r, "UUID=") || strings.HasPrefix(r, "LABEL=") ||
		strings.HasPrefix(r, "PARTUUID=") || strings.HasPrefix(r, "PARTLABEL=")
}

// appendCrypttab reads path, filters entries marked with x-initrd.attach,
// and bundles the filtered content plus any referenced keyfiles into the image as
// /etc/crypttab.  Returns hasFido2=true if any kept entry has fido2-device= set
// (so the caller can auto-enable the fido2 plugin).  Returns nil error if path
// does not exist.
func (img *Image) appendCrypttab(path string) (hasFido2 bool, err error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	type entry struct {
		line    string // original line with x-initrd.attach stripped from options
		keyfile string
		optStr  string
	}

	var kept []entry

	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}

		var keyfile, optStr string
		if len(fields) >= 3 {
			keyfile = fields[2]
		}
		if len(fields) >= 4 {
			optStr = fields[3]
		}

		// check for x-initrd.attach and build a cleaned options string
		hasXInitrd := false
		var cleanOpts []string
		for _, opt := range strings.Split(optStr, ",") {
			opt = strings.TrimSpace(opt)
			if opt == "" {
				continue
			}
			if opt == "x-initrd.attach" {
				hasXInitrd = true
			} else {
				cleanOpts = append(cleanOpts, opt)
			}
		}

		if !hasXInitrd {
			continue
		}

		// rebuild the line with x-initrd.attach stripped
		cleanOptStr := strings.Join(cleanOpts, ",")
		var outFields []string
		outFields = append(outFields, fields[0], fields[1])
		if len(fields) >= 3 {
			outFields = append(outFields, fields[2])
		}
		if cleanOptStr != "" {
			outFields = append(outFields, cleanOptStr)
		}

		kept = append(kept, entry{
			line:    strings.Join(outFields, "\t"),
			keyfile: keyfile,
			optStr:  cleanOptStr,
		})
	}

	if len(kept) == 0 {
		return false, nil
	}

	// write filtered crypttab into image
	var buf strings.Builder
	for _, e := range kept {
		buf.WriteString(e.line)
		buf.WriteByte('\n')
	}
	if err := img.AppendContent("/etc/crypttab", 0o600, []byte(buf.String())); err != nil {
		return false, err
	}

	// bundle referenced assets for each kept entry
	for _, e := range kept {
		// skip asset bundling for entries that won't be processed as LUKS
		skip := false
		for _, opt := range strings.Split(e.optStr, ",") {
			opt = strings.TrimSpace(opt)
			if opt == "noauto" || opt == "swap" || opt == "tmp" || opt == "plain" || opt == "bitlk" || opt == "tcrypt" {
				skip = true
				break
			}
			if strings.HasPrefix(opt, "fido2-device=") {
				hasFido2 = true
			}
		}
		if skip {
			continue
		}

		// bundle keyfile if it is an absolute path and not on a runtime device
		kf := e.keyfile
		if kf != "" && kf != "none" && kf != "-" && filepath.IsAbs(kf) {
			if isKeyfileOnDevice(kf) {
				// keyfile lives on a separate runtime device — nothing to bundle
			} else if err := img.AppendFile(kf); err != nil {
				return false, fmt.Errorf("crypttab: keyfile %s: %v", kf, err)
			}
		}

		// bundle header file if specified as an absolute path and not on a runtime device
		for _, opt := range strings.Split(e.optStr, ",") {
			opt = strings.TrimSpace(opt)
			if !strings.HasPrefix(opt, "header=") {
				continue
			}
			hdr := opt[7:]
			if hdr == "" || !filepath.IsAbs(hdr) {
				break
			}
			if isKeyfileOnDevice(hdr) {
				// header lives on a separate runtime device — nothing to bundle
				break
			}
			if strings.HasPrefix(hdr, "/dev/") {
				// raw block device — runtime, nothing to bundle
				break
			}
			if err := img.AppendFile(hdr); err != nil {
				return false, fmt.Errorf("crypttab: header %s: %v", hdr, err)
			}
			break
		}
	}

	return hasFido2, nil
}
