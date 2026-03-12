package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// isHeaderOnDevice reports whether h is a raw block device path ("/dev/sdb").
// In that case the header lives on a runtime device and must not be bundled.
func isHeaderOnDevice(h string) bool {
	return strings.HasPrefix(h, "/dev/")
}

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

// hasXInitrdAttach reports whether optStr (the 4th field of a crypttab line)
// contains the x-initrd.attach option.
func hasXInitrdAttach(optStr string) bool {
	for _, opt := range strings.Split(optStr, ",") {
		if strings.TrimSpace(opt) == "x-initrd.attach" {
			return true
		}
	}
	return false
}

// bundleCrypttabAssets bundles keyfiles and detached LUKS headers referenced
// by active (non-noauto) entries in content into the image.
func (img *Image) bundleCrypttabAssets(content []byte) error {
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
				return fmt.Errorf("crypttab: keyfile %s: %v", keyfile, err)
			}
		}

		// bundle detached header if header=PATH is in options and PATH is a
		// local file (not a runtime device)
		for _, opt := range strings.Split(optStr, ",") {
			opt = strings.TrimSpace(opt)
			if strings.HasPrefix(opt, "header=") {
				headerPath := strings.TrimPrefix(opt, "header=")
				if isHeaderOnDevice(headerPath) {
					continue
				}
				if !filepath.IsAbs(headerPath) {
					return fmt.Errorf("crypttab: header= path must be absolute: %s", headerPath)
				}
				if err := img.AppendFile(headerPath); err != nil {
					return fmt.Errorf("crypttab: header %s: %v", headerPath, err)
				}
			}
		}
	}
	return nil
}

// systemCrypttabPath returns the host's /etc/crypttab path, which may be
// overridden by the BOOSTER_SYSTEM_CRYPTTAB environment variable for testing.
func systemCrypttabPath() string {
	if p := os.Getenv("BOOSTER_SYSTEM_CRYPTTAB"); p != "" {
		return p
	}
	return "/etc/crypttab"
}

// appendCrypttab reads the host's /etc/crypttab and bundles entries marked
// with x-initrd.attach into the image as /etc/crypttab.  Silently succeeds
// if the file is absent or contains no x-initrd.attach entries.
func (img *Image) appendCrypttab() error {
	return img.appendCrypttabFiltered(systemCrypttabPath())
}

// appendCrypttabFiltered is the testable implementation of appendCrypttab.
func (img *Image) appendCrypttabFiltered(hostPath string) error {
	content, err := os.ReadFile(hostPath)
	if os.IsNotExist(err) || os.IsPermission(err) {
		return nil
	}
	if err != nil {
		return err
	}

	var filtered []byte
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 4 && hasXInitrdAttach(fields[3]) {
			filtered = append(filtered, []byte(line+"\n")...)
		}
	}

	if len(filtered) == 0 {
		return nil
	}

	if err := img.AppendContent("/etc/crypttab", 0o600, filtered); err != nil {
		return err
	}
	return img.bundleCrypttabAssets(filtered)
}

// appendCrypttabFrom bundles all entries from hostPath into the image as
// /etc/crypttab.  Used when an explicit --crypttab path is provided.
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
	return img.bundleCrypttabAssets(content)
}
