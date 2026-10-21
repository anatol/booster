package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// nvpcrDirs are systemd's CONF_PATHS("nvpcr") without /run, highest
// precedence first.
var nvpcrDirs = []string{"/etc/nvpcr", "/usr/local/lib/nvpcr", "/usr/lib/nvpcr"}

// libsystemdSharedGlobs covers /usr/lib (Arch), /usr/lib64 (Fedora) and the
// Debian multiarch dirs.
var libsystemdSharedGlobs = []string{
	"/usr/lib/systemd/libsystemd-shared-*.so",
	"/usr/lib64/systemd/libsystemd-shared-*.so",
	"/usr/lib/*/systemd/libsystemd-shared-*.so",
}

// hostSystemdVersion reads the newest major version from the libsystemd-shared
// filename, e.g. libsystemd-shared-262-1.so.
func hostSystemdVersion() (int, bool) {
	newest, found := 0, false
	for _, g := range libsystemdSharedGlobs {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			v := strings.TrimPrefix(filepath.Base(m), "libsystemd-shared-")
			end := strings.IndexFunc(v, func(r rune) bool { return r < '0' || r > '9' })
			if end == -1 {
				end = len(v)
			}
			if n, err := strconv.Atoi(v[:end]); err == nil && n >= newest {
				newest, found = n, true
			}
		}
	}
	return newest, found
}

// appendNvPCRDefinitions bundles the effective NvPCR definitions, resolved as
// systemd's conf_files_list does, into /usr/lib/nvpcr.
//
// Only for systemd v262 and later: systemd 259 to 261 initialize NvPCRs on
// the host with an anchor secret and refuse an index defined in v262.
func (img *Image) appendNvPCRDefinitions(dirs []string) error {
	if v, ok := hostSystemdVersion(); !ok || v < 262 {
		return nil
	}
	seen := make(map[string]bool)
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".nvpcr") || seen[name] {
				continue
			}
			seen[name] = true
			path := filepath.Join(dir, name)
			st, err := os.Stat(path)
			if err != nil {
				return err
			}
			if !st.Mode().IsRegular() || st.Size() == 0 {
				continue
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err := img.AppendContent(filepath.Join("/usr/lib/nvpcr", name), 0o644, content); err != nil {
				return err
			}
		}
	}
	return nil
}
