package main

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractFontFamily(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Inter Bold 16", "Inter"},
		{"Sans 12", "Sans"},
		{"Cantarell Light 11", "Cantarell"},
		{"Noto Sans SemiBold 14", "Noto Sans"},
		{"DejaVu Sans Condensed Bold Oblique 10", "DejaVu Sans"},
		{"Monospace 10", "Monospace"},
		{"Ubuntu Mono Regular 13", "Ubuntu Mono"},
		// size only
		{"Inter 16", "Inter"},
		// no size
		{"Inter Bold", "Inter"},
		// family only
		{"Inter", "Inter"},
		// empty
		{"", ""},
		// multiple trailing numbers stripped
		{"Inter 16 12", "Inter"},
		// style then size
		{"Inter Bold Italic 10", "Inter"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := extractFontFamily(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParseThemeLogo(t *testing.T) {
	t.Run("logo present", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.plymouth")
		require.NoError(t, os.WriteFile(f, []byte("[space-flares]\nLogo=/usr/share/pixmaps/archlinux-logo.png\n"), 0o644))
		require.Equal(t, "/usr/share/pixmaps/archlinux-logo.png", parseThemeLogo(f))
	})
	t.Run("no logo key", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.plymouth")
		require.NoError(t, os.WriteFile(f, []byte("[Plymouth Theme]\nName=Solar\n"), 0o644))
		require.Equal(t, "", parseThemeLogo(f))
	})
	t.Run("nonexistent file", func(t *testing.T) {
		require.Equal(t, "", parseThemeLogo("/nonexistent/theme.plymouth"))
	})
}

// makeMinimalELF writes a tiny but valid ELF64 shared library with a single
// .rodata section containing the given byte slice.  This lets elfLogoPath unit
// tests run without requiring Plymouth to be installed.
func makeMinimalELF(t *testing.T, rodata []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.so")

	// We build a minimal ELF64 LSB shared object by hand:
	//   ELF header  (64 bytes)
	//   .rodata     (len(rodata) bytes, at file offset 64)
	//   Section header table: NULL + .rodata + .shstrtab  (3 × 64 bytes)
	//   .shstrtab section (names: "\0.rodata\0.shstrtab\0")
	shstrtab := []byte("\x00.rodata\x00.shstrtab\x00")
	rodataOff := uint64(64)
	rodataSize := uint64(len(rodata))
	shstrtabOff := rodataOff + rodataSize
	shstrtabSize := uint64(len(shstrtab))
	shOff := shstrtabOff + shstrtabSize
	// align shOff to 8
	if shOff%8 != 0 {
		shOff += 8 - shOff%8
	}

	le := binary.LittleEndian
	buf := make([]byte, shOff+3*64)

	// ELF ident
	copy(buf[0:], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = 2                 // ELFCLASS64
	buf[5] = 1                 // ELFDATA2LSB
	buf[6] = 1                 // EV_CURRENT
	buf[7] = 0                 // ELFOSABI_NONE
	le.PutUint16(buf[16:], 3)  // ET_DYN (shared object)
	le.PutUint16(buf[18:], 62) // EM_X86_64
	le.PutUint32(buf[20:], 1)  // EV_CURRENT
	// e_entry, e_phoff = 0
	le.PutUint64(buf[40:], shOff) // e_shoff
	le.PutUint16(buf[52:], 64)    // e_ehsize
	le.PutUint16(buf[54:], 56)    // e_phentsize
	le.PutUint16(buf[56:], 0)     // e_phnum
	le.PutUint16(buf[58:], 64)    // e_shentsize
	le.PutUint16(buf[60:], 3)     // e_shnum (NULL + .rodata + .shstrtab)
	le.PutUint16(buf[62:], 2)     // e_shstrndx = 2

	// Section header 0: NULL (all zeros, already zero)

	// Section header 1: .rodata
	sh1 := buf[shOff+64:]
	le.PutUint32(sh1[0:], 1)                        // sh_name = offset of ".rodata" in shstrtab = 1
	le.PutUint32(sh1[4:], uint32(elf.SHT_PROGBITS)) // sh_type
	le.PutUint64(sh1[8:], uint64(elf.SHF_ALLOC))    // sh_flags
	le.PutUint64(sh1[24:], rodataOff)               // sh_offset
	le.PutUint64(sh1[32:], rodataSize)              // sh_size
	le.PutUint64(sh1[48:], 1)                       // sh_addralign

	// Section header 2: .shstrtab
	sh2 := buf[shOff+128:]
	le.PutUint32(sh2[0:], 9) // sh_name = offset of ".shstrtab" in shstrtab = 9
	le.PutUint32(sh2[4:], uint32(elf.SHT_STRTAB))
	le.PutUint64(sh2[24:], shstrtabOff)  // sh_offset
	le.PutUint64(sh2[32:], shstrtabSize) // sh_size
	le.PutUint64(sh2[48:], 1)            // sh_addralign

	// Write .rodata and .shstrtab into buf
	copy(buf[rodataOff:], rodata)
	copy(buf[shstrtabOff:], shstrtab)

	require.NoError(t, os.WriteFile(path, buf, 0o644))
	return path
}

func TestElfLogoPath(t *testing.T) {
	t.Run("nonexistent file returns empty", func(t *testing.T) {
		require.Equal(t, "", elfLogoPath("/nonexistent/space-flares.so"))
	})

	t.Run("non-ELF file returns empty", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "fake.so")
		require.NoError(t, os.WriteFile(f, []byte("not an ELF file at all"), 0o644))
		require.Equal(t, "", elfLogoPath(f))
	})

	t.Run("ELF with no .rodata section returns empty", func(t *testing.T) {
		// Build an ELF with an empty rodata so the section exists but has no logo.
		path := makeMinimalELF(t, []byte{})
		require.Equal(t, "", elfLogoPath(path))
	})

	t.Run("ELF with logo path in rodata", func(t *testing.T) {
		// Simulate PLYMOUTH_LOGO_FILE = "/usr/share/pixmaps/archlinux-logo.png"
		// packed as a null-terminated string among other .rodata content.
		var rodata []byte
		rodata = append(rodata, []byte("some other string\x00")...)
		rodata = append(rodata, []byte("/usr/share/pixmaps/archlinux-logo.png\x00")...)
		rodata = append(rodata, []byte("another string\x00")...)

		path := makeMinimalELF(t, rodata)
		result := elfLogoPath(path)
		require.Equal(t, "/usr/share/pixmaps/archlinux-logo.png", result)
	})

	t.Run("ELF with svg logo path in rodata", func(t *testing.T) {
		var rodata []byte
		rodata = append(rodata, []byte("/usr/share/pixmaps/fedora-logo.svg\x00")...)
		path := makeMinimalELF(t, rodata)
		require.Equal(t, "/usr/share/pixmaps/fedora-logo.svg", elfLogoPath(path))
	})

	t.Run("ELF without logo path returns empty", func(t *testing.T) {
		// Absolute path but doesn't contain "logo".
		var rodata []byte
		rodata = append(rodata, []byte("/usr/share/pixmaps/archlinux.png\x00")...)
		path := makeMinimalELF(t, rodata)
		require.Equal(t, "", elfLogoPath(path))
	})

	t.Run("ELF with relative path ignored", func(t *testing.T) {
		// Relative path should not be returned (must start with '/').
		var rodata []byte
		rodata = append(rodata, []byte("share/pixmaps/logo.png\x00")...)
		path := makeMinimalELF(t, rodata)
		require.Equal(t, "", elfLogoPath(path))
	})

	// Integration sub-test: runs only when space-flares.so is installed.
	t.Run("real space-flares.so", func(t *testing.T) {
		pluginsDir := plymouthPkgConfig("pluginsdir")
		if pluginsDir == "" {
			pluginsDir = "/usr/lib/plymouth"
		}
		soPath := filepath.Join(pluginsDir, "space-flares.so")
		if _, err := os.Stat(soPath); err != nil {
			t.Skip("space-flares.so not installed")
		}
		result := elfLogoPath(soPath)
		t.Logf("elfLogoPath(%s) = %q", soPath, result)
		if result != "" {
			require.True(t, filepath.IsAbs(result), "logo path must be absolute: %q", result)
			require.True(t,
				len(result) > 4,
				"logo path must be non-trivial: %q", result)
		}
		// result == "" is also acceptable on distros that patched out the constant.
	})
}

// writeFakePlugin writes a minimal ELF .so at <dir>/<name> whose read-only
// data contains the given logo path string (plus some decoy strings).
func writeFakePlugin(t *testing.T, dir, name, logoPath string) {
	t.Helper()
	var rodata []byte
	rodata = append(rodata, []byte("%-75.75s: loading logo image\x00")...) // trace decoy
	rodata = append(rodata, []byte("plugin->logo_image != NULL\x00")...)   // assert decoy
	if logoPath != "" {
		rodata = append(rodata, []byte(logoPath+"\x00")...)
	}
	soData, err := os.ReadFile(makeMinimalELF(t, rodata))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), soData, 0o644))
}

func TestFindPlymouthLogoFile(t *testing.T) {
	// pkg-config exposing logofile would short-circuit the ELF scan and make
	// these assertions about the fallback meaningless, so skip if it is set.
	skipIfPkgConfigLogo := func(t *testing.T) {
		if plymouthPkgConfig("logofile") != "" {
			t.Skip("pkg-config logofile is set on this host; ELF fallback not exercised")
		}
	}

	t.Run("returns empty for empty plugin dir", func(t *testing.T) {
		skipIfPkgConfigLogo(t)
		require.Equal(t, "", findPlymouthLogoFile(t.TempDir(), "space-flares"))
	})

	t.Run("reads logo from the active theme's plugin", func(t *testing.T) {
		skipIfPkgConfigLogo(t)
		dir := t.TempDir()
		writeFakePlugin(t, dir, "space-flares.so", "/usr/share/pixmaps/test-logo.png")
		require.Equal(t, "/usr/share/pixmaps/test-logo.png",
			findPlymouthLogoFile(dir, "space-flares"))
	})

	t.Run("works for a script-based theme", func(t *testing.T) {
		skipIfPkgConfigLogo(t)
		dir := t.TempDir()
		// The old implementation only scanned space-flares/two-step and would
		// have missed this entirely.
		writeFakePlugin(t, dir, "script.so", "/usr/share/plymouth/distro-logo.png")
		require.Equal(t, "/usr/share/plymouth/distro-logo.png",
			findPlymouthLogoFile(dir, "script"))
	})

	t.Run("active text/details plugin without a logo bundles nothing", func(t *testing.T) {
		skipIfPkgConfigLogo(t)
		dir := t.TempDir()
		// text.so carries no logo; a graphical plugin in the same dir does.
		// We must NOT pull in the unrelated plugin's logo.
		writeFakePlugin(t, dir, "text.so", "")
		writeFakePlugin(t, dir, "space-flares.so", "/usr/share/pixmaps/test-logo.png")
		require.Equal(t, "", findPlymouthLogoFile(dir, "text"))
	})

	t.Run("falls back to known plugins when module is unknown", func(t *testing.T) {
		skipIfPkgConfigLogo(t)
		dir := t.TempDir()
		writeFakePlugin(t, dir, "two-step.so", "/usr/share/pixmaps/distro-logo.png")
		require.Equal(t, "/usr/share/pixmaps/distro-logo.png",
			findPlymouthLogoFile(dir, ""))
	})
}

func TestParseThemeModule(t *testing.T) {
	t.Run("module present", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.plymouth")
		require.NoError(t, os.WriteFile(f, []byte("[Plymouth Theme]\nName=Solar\nModuleName=space-flares\n"), 0o644))
		require.Equal(t, "space-flares", parseThemeModule(f))
	})
	t.Run("no module key", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "test.plymouth")
		require.NoError(t, os.WriteFile(f, []byte("[Plymouth Theme]\nName=Solar\n"), 0o644))
		require.Equal(t, "", parseThemeModule(f))
	})
	t.Run("nonexistent file", func(t *testing.T) {
		require.Equal(t, "", parseThemeModule("/nonexistent/theme.plymouth"))
	})
}

func TestParseThemeFonts(t *testing.T) {
	t.Run("typical theme file", func(t *testing.T) {
		dir := t.TempDir()
		themeFile := filepath.Join(dir, "test.plymouth")
		content := `[Plymouth Theme]
Name=BGRT
ModuleName=two-step

[two-step]
Font=Cantarell Light 12
TitleFont=Cantarell Bold 18
ImageDir=/usr/share/plymouth/themes/bgrt
`
		require.NoError(t, os.WriteFile(themeFile, []byte(content), 0o644))

		families := parseThemeFonts(themeFile)
		require.Equal(t, []string{"Cantarell"}, families)
	})

	t.Run("multiple distinct fonts", func(t *testing.T) {
		dir := t.TempDir()
		themeFile := filepath.Join(dir, "test.plymouth")
		content := `[two-step]
Font=Inter Light 12
TitleFont=Noto Sans Bold 18
`
		require.NoError(t, os.WriteFile(themeFile, []byte(content), 0o644))

		families := parseThemeFonts(themeFile)
		require.Equal(t, []string{"Inter", "Noto Sans"}, families)
	})

	t.Run("no font directives", func(t *testing.T) {
		dir := t.TempDir()
		themeFile := filepath.Join(dir, "test.plymouth")
		content := `[Plymouth Theme]
Name=Details
ModuleName=details
`
		require.NoError(t, os.WriteFile(themeFile, []byte(content), 0o644))

		families := parseThemeFonts(themeFile)
		require.Nil(t, families)
	})

	t.Run("nonexistent file", func(t *testing.T) {
		families := parseThemeFonts("/nonexistent/path/theme.plymouth")
		require.Nil(t, families)
	})

	t.Run("duplicate fonts deduplicated", func(t *testing.T) {
		dir := t.TempDir()
		themeFile := filepath.Join(dir, "test.plymouth")
		content := `[two-step]
Font=Inter 12
TitleFont=Inter Bold 18
`
		require.NoError(t, os.WriteFile(themeFile, []byte(content), 0o644))

		families := parseThemeFonts(themeFile)
		require.Equal(t, []string{"Inter"}, families)
	})
}

func TestParseThemeImageDir(t *testing.T) {
	t.Run("same directory", func(t *testing.T) {
		dir := t.TempDir()
		themeFile := filepath.Join(dir, "bgrt.plymouth")
		content := `[Plymouth Theme]
Name=BGRT
ModuleName=two-step

[two-step]
ImageDir=/usr/share/plymouth/themes/bgrt
Font=Cantarell Light 12
`
		require.NoError(t, os.WriteFile(themeFile, []byte(content), 0o644))
		result := parseThemeImageDir(themeFile)
		require.Equal(t, "/usr/share/plymouth/themes/bgrt", result)
	})

	t.Run("cross-directory reference", func(t *testing.T) {
		dir := t.TempDir()
		themeFile := filepath.Join(dir, "bgrt.plymouth")
		content := `[Plymouth Theme]
Name=BGRT
ModuleName=two-step

[two-step]
ImageDir=/usr/share/plymouth/themes//spinner
Font=Cantarell Light 12
`
		require.NoError(t, os.WriteFile(themeFile, []byte(content), 0o644))
		result := parseThemeImageDir(themeFile)
		require.Equal(t, "/usr/share/plymouth/themes//spinner", result)
	})

	t.Run("no ImageDir", func(t *testing.T) {
		dir := t.TempDir()
		themeFile := filepath.Join(dir, "details.plymouth")
		content := `[Plymouth Theme]
Name=Details
ModuleName=details
`
		require.NoError(t, os.WriteFile(themeFile, []byte(content), 0o644))
		result := parseThemeImageDir(themeFile)
		require.Equal(t, "", result)
	})

	t.Run("nonexistent file", func(t *testing.T) {
		result := parseThemeImageDir("/nonexistent/path/theme.plymouth")
		require.Equal(t, "", result)
	})
}

func TestPlymouthPkgConfig(t *testing.T) {
	// pkg-config may or may not be available; just verify it doesn't panic
	// and returns empty string on failure
	result := plymouthPkgConfig("nonexistent_variable_xyz")
	// Either empty (pkg-config not installed or variable not found) or a path
	t.Logf("plymouthPkgConfig(nonexistent_variable_xyz) = %q", result)

	// Test with a real variable if ply-splash-core is available
	pluginsDir := plymouthPkgConfig("pluginsdir")
	t.Logf("plymouthPkgConfig(pluginsdir) = %q", pluginsDir)
	if pluginsDir != "" {
		require.True(t, filepath.IsAbs(pluginsDir), "pluginsdir should be an absolute path")
	}
}

func TestFcMatch(t *testing.T) {
	// fc-match may or may not be available; verify it doesn't panic
	result := fcMatch("nonexistent_font_family_xyz")
	t.Logf("fcMatch(nonexistent_font_family_xyz) = %q", result)

	// Test with a common font pattern — should resolve on most systems
	sans := fcMatch("Sans")
	t.Logf("fcMatch(Sans) = %q", sans)
	if sans != "" {
		require.True(t, filepath.IsAbs(sans), "fc-match result should be an absolute path")
	}

	mono := fcMatch("monospace")
	t.Logf("fcMatch(monospace) = %q", mono)
	if mono != "" {
		require.True(t, filepath.IsAbs(mono), "fc-match result should be an absolute path")
	}
}
