package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// isKeyfileOnDevice reports whether kf is a keyfile-on-device specifier of the
// form "/path:UUID=xxx", "/path:LABEL=xxx", etc.
func isKeyfileOnDevice(kf string) bool {
	idx := strings.Index(kf, ":")
	if idx < 0 {
		return false
	}
	r := kf[idx+1:]
	return strings.HasPrefix(r, "UUID=") || strings.HasPrefix(r, "LABEL=") ||
		strings.HasPrefix(r, "PARTUUID=") || strings.HasPrefix(r, "PARTLABEL=")
}

// appendCrypttab bundles /etc/crypttab.initramfs (if present on the host) into
// the image as /etc/crypttab, and pre-bundles any referenced keyfiles or
// detached LUKS headers.  Silently skips if the file does not exist — opting in
// is as simple as creating the file.
func (img *Image) appendCrypttab() error {
	return img.appendCrypttabFrom("/etc/crypttab.initramfs")
}

// appendCrypttabFrom is the testable implementation; hostPath can be overridden in tests.
func (img *Image) appendCrypttabFrom(hostPath string) error {
	content, err := os.ReadFile(hostPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	if err := img.AppendContent("/etc/crypttab", 0o600, content); err != nil {
		return err
	}

	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
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

		// skip entries that won't be processed at boot
		noauto := false
		for _, opt := range strings.Split(optStr, ",") {
			opt = strings.TrimSpace(opt)
			if opt == "noauto" || opt == "swap" || opt == "tmp" || opt == "plain" || opt == "bitlk" || opt == "tcrypt" {
				noauto = true
				break
			}
		}
		if noauto {
			continue
		}

		// bundle keyfile if it is an absolute path (not none/-)
		if keyfile != "" && keyfile != "none" && keyfile != "-" && filepath.IsAbs(keyfile) {
			if isKeyfileOnDevice(keyfile) {
				// key lives on a separate runtime device — nothing to bundle
			} else if err := img.AppendFile(keyfile); err != nil {
				return fmt.Errorf("crypttab.initramfs: keyfile %s: %v", keyfile, err)
			}
		}

		// bundle detached header if header=PATH is in options
		for _, opt := range strings.Split(optStr, ",") {
			opt = strings.TrimSpace(opt)
			if strings.HasPrefix(opt, "header=") {
				headerPath := strings.TrimPrefix(opt, "header=")
				if !filepath.IsAbs(headerPath) {
					return fmt.Errorf("crypttab.initramfs: header= path must be absolute: %s", headerPath)
				}
				if err := img.AppendFile(headerPath); err != nil {
					return fmt.Errorf("crypttab.initramfs: header %s: %v", headerPath, err)
				}
			}
		}
	}

	return nil
}
