package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// kbdBaseDir is the root of the kbd data tree. Arch/Debian/openSUSE/Alpine use
// /usr/share/kbd; Fedora/RHEL use /usr/lib/kbd. Probe at startup so the generator
// works on any distro without configuration.
var kbdBaseDir = func() string {
	for _, d := range []string{"/usr/share/kbd", "/usr/lib/kbd"} {
		if _, err := os.Stat(filepath.Join(d, "consolefonts")); err == nil {
			return d
		}
	}
	return "/usr/share/kbd"
}()

var (
	consolefontsDir = filepath.Join(kbdBaseDir, "consolefonts")
	consoletransDir = filepath.Join(kbdBaseDir, "consoletrans")
	unimapsDir      = filepath.Join(kbdBaseDir, "unimaps")
)

// Suffix lists mirror kbd's kfont_context defaults (src/libkfont/context.c).
// kbdfile_find resolves a name by trying name+suffix for each suffix in order.
var (
	consolefontsSuffixes = []string{"", ".psfu", ".psf", ".cp", ".fnt"}
	consoletransSuffixes = []string{"", ".trans", "_to_uni.trans", ".acm"}
	unimapsSuffixes      = []string{"", ".uni", ".sfm"}
)

func (img *Image) enableVirtualConsole(vConsolePath, localePath string) (*VirtualConsole, error) {
	debug("enabling virtual console")

	var conf VirtualConsole

	vconf, err := os.ReadFile(vConsolePath)
	if err != nil {
		return nil, err
	}
	vprop := parseProperties(string(vconf), true)

	// adding keymap
	if keymap, ok := vprop["KEYMAP"]; ok {
		lconf, err := os.ReadFile(localePath)
		if errors.Is(err, fs.ErrNotExist) {
			// musl-based Linux distributions (e.g. Alpine Linux) don't use /etc/locale.conf since musl supports UTF-8 by default
			// and doesn't require any external locale files.
			conf.Utf = true
		} else if err != nil {
			return nil, err
		} else {
			lprop := parseProperties(string(lconf), true)
			lang := lprop["LANG"]
			debug("detected language - '%s'", lang)
			conf.Utf = strings.HasSuffix(strings.ToLower(lang), "utf-8")
		}

		conf.KeymapFile = "/console/keymap"

		blob, err := loadKeymap(keymap, vprop["KEYMAP_TOGGLE"], conf.Utf)
		if err != nil {
			return nil, err
		}
		if err := img.AppendContent(conf.KeymapFile, 0o644, blob); err != nil {
			return nil, err
		}
	} else {
		warning("vconsole is enabled but %s does not contain KEYMAP property", vConsolePath)
	}

	// adding fonts
	if font, ok := vprop["FONT"]; ok {
		if err := img.appendExtraFiles("setfont"); err != nil {
			return nil, err
		}

		blob, err := findKbdFile(consolefontsDir, font, consolefontsSuffixes)
		if err != nil {
			return nil, err
		}
		conf.FontFile = "/console/font"
		if err := img.AppendContent(conf.FontFile, 0o644, blob); err != nil {
			return nil, err
		}

		if m, ok := vprop["FONT_MAP"]; ok {
			blob, err := findKbdFile(consoletransDir, m, consoletransSuffixes)
			if err != nil {
				return nil, err
			}
			conf.FontMapFile = "/console/font.map"
			if err := img.AppendContent(conf.FontMapFile, 0o644, blob); err != nil {
				return nil, err
			}
		}

		if u, ok := vprop["FONT_UNIMAP"]; ok {
			blob, err := findKbdFile(unimapsDir, u, unimapsSuffixes)
			if err != nil {
				return nil, err
			}
			conf.FontUnicodeFile = "/console/font.unimap"
			if err := img.AppendContent(conf.FontUnicodeFile, 0o644, blob); err != nil {
				return nil, err
			}
		}
	} else {
		debug("%s does not provide FONT settings, skip vconsole font configuration", vConsolePath)
	}

	return &conf, nil
}

func loadKeymap(keymap, keymapToggle string, isUtf bool) ([]byte, error) {
	// adding keymap
	args := []string{"-q", "-b"}
	if isUtf {
		args = append(args, "-u")
	}
	args = append(args, keymap)

	if keymapToggle != "" {
		args = append(args, keymapToggle)
	}

	blob, err := exec.Command("loadkeys", args...).Output()
	err = unwrapExitError(err)
	return blob, err
}

func readFontFile(font string) ([]byte, error) {
	return findKbdFile(consolefontsDir, font, consolefontsSuffixes)
}

// findKbdFile locates a kbd data file by trying name+suffix combinations in dir,
// mirroring how setfont's kbdfile_find resolves files. Gzip-compressed variants
// are transparently decompressed.
func findKbdFile(dir, name string, suffixes []string) ([]byte, error) {
	for _, suffix := range suffixes {
		for _, comp := range []string{"", ".gz"} {
			path := filepath.Join(dir, name+suffix+comp)
			blob, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			debug("kbd file '%s' matched to %s", name, path)
			if comp != ".gz" {
				return blob, nil
			}
			gz, err := gzip.NewReader(bytes.NewReader(blob))
			if err != nil {
				return nil, err
			}
			blob, err = io.ReadAll(gz)
			gz.Close()
			if err != nil {
				return nil, err
			}
			return blob, nil
		}
	}
	return nil, fmt.Errorf("unable to find file for specified font '%s'", name)
}
