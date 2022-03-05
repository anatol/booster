package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
)

// path to console fonts, adjust it to your distro (e.g. Fedora uses /usr/lib/kbd/consolefonts path for it)
const consolefontsDir = "/usr/share/kbd/consolefonts/"

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
		if err != nil {
			return nil, err
		}
		lprop := parseProperties(string(lconf), true)

		lang := lprop["LANG"]
		debug("detected language - '%s'", lang)
		conf.Utf = strings.HasSuffix(strings.ToLower(lang), "utf-8")
		conf.KeymapFile = "/console/keymap"

		blob, err := loadKeymap(keymap, vprop["KEYMAP_TOGGLE"], conf.Utf)
		if err != nil {
			return nil, err
		}
		if err := img.AppendContent(conf.KeymapFile, 0644, blob); err != nil {
			return nil, err
		}
	} else {
		warning("vconsole is enabled but %s does not contain KEYMAP property", vConsolePath)
	}

	// adding fonts
	if font, ok := vprop["FONT"]; ok {
		if err := img.appendExtraFiles([]string{"setfont"}); err != nil {
			return nil, err
		}

		blob, err := readFontFile(font)
		if err != nil {
			return nil, err
		}
		conf.FontFile = "/console/font"
		if err := img.AppendContent(conf.FontFile, 0644, blob); err != nil {
			return nil, err
		}

		if m, ok := vprop["FONT_MAP"]; ok {
			blob, err := readFontFile(m)
			if err != nil {
				return nil, err
			}
			conf.FontFile = "/console/font.map"
			if err := img.AppendContent(conf.FontFile, 0644, blob); err != nil {
				return nil, err
			}
		}

		if u, ok := vprop["FONT_UNIMAP"]; ok {
			blob, err := readFontFile(u)
			if err != nil {
				return nil, err
			}
			conf.FontFile = "/console/font.unimap"
			if err := img.AppendContent(conf.FontFile, 0644, blob); err != nil {
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

func readFontFile(font string) (blob []byte, err error) {
	entries, err := os.ReadDir(consolefontsDir)
	if err != nil {
		return nil, err
	}
	for _, d := range entries {
		name := d.Name()
		if strings.HasPrefix(name, font+".") {
			fileName := path.Join(consolefontsDir, name)
			debug("font %s matched to file %s", font, fileName)
			blob, err := os.ReadFile(fileName)
			if err != nil {
				return nil, err
			}

			if strings.HasSuffix(name, ".gz") {
				// unpack the archive
				gz, err := gzip.NewReader(bytes.NewReader(blob))
				if err != nil {
					return nil, err
				}
				defer gz.Close()

				blob, err = io.ReadAll(gz)
				if err != nil {
					return nil, err
				}
				name = name[:len(name)-3] // remove .gz suffix from the name
			}

			return blob, nil
		}
	}
	return nil, fmt.Errorf("unable to find file for specified font '%s'", font)
}
