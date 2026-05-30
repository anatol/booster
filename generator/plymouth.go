package main

import (
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cavaliergopher/cpio"
)

func (img *Image) addPlymouthSupport(conf *generatorConfig) error {
	debug("adding plymouth support to the image")

	// Detect Plymouth paths via pkg-config, falling back to common defaults
	pluginDir := plymouthPkgConfig("pluginsdir")
	if pluginDir == "" {
		// pkg-config unavailable; try common distro locations in order:
		// Arch/Alpine: /usr/lib/plymouth
		// Fedora/RHEL: /usr/lib64/plymouth
		// Debian/Ubuntu (multiarch): /usr/lib/<tuple>/plymouth
		for _, candidate := range []string{
			"/usr/lib/plymouth",
			"/usr/lib64/plymouth",
		} {
			if _, err := os.Stat(candidate); err == nil {
				pluginDir = candidate
				break
			}
		}
		if pluginDir == "" {
			// Try multiarch paths (Debian/Ubuntu)
			if entries, err := filepath.Glob("/usr/lib/*-linux-*/plymouth"); err == nil && len(entries) > 0 {
				pluginDir = entries[0]
			}
		}
	}
	themesDir := plymouthPkgConfig("themesdir")
	if themesDir == "" {
		themesDir = "/usr/share/plymouth/themes"
	}
	confDir := plymouthPkgConfig("confdir")
	if confDir == "" {
		confDir = "/etc/plymouth"
	}
	policyDir := plymouthPkgConfig("policydir")
	if policyDir == "" {
		policyDir = "/usr/share/plymouth"
	}
	debug("plymouth paths: plugins=%s themes=%s conf=%s policy=%s", pluginDir, themesDir, confDir, policyDir)

	// Add plymouthd — the init process speaks to it directly via socket.
	// The plymouth CLI client is no longer bundled.
	if err := img.appendExtraFiles("plymouthd"); err != nil {
		return fmt.Errorf("plymouth binaries: %v", err)
	}

	// Add plymouthd-fd-escrow helper
	fdEscrow := filepath.Join(pluginDir, "plymouthd-fd-escrow")
	if _, err := os.Stat(fdEscrow); err == nil {
		if err := img.AppendFile(fdEscrow); err != nil {
			return fmt.Errorf("plymouth fd-escrow: %v", err)
		}
	}

	// Add all .so plugins
	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		return fmt.Errorf("reading plymouth plugin dir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".so" {
			if err := img.AppendFile(filepath.Join(pluginDir, e.Name())); err != nil {
				return fmt.Errorf("plymouth plugin %s: %v", e.Name(), err)
			}
		}
	}

	// Add renderers
	rendererDir := filepath.Join(pluginDir, "renderers")
	if err := img.AppendFile(rendererDir); err != nil {
		return fmt.Errorf("plymouth renderers: %v", err)
	}

	// Add plymouth config files
	for _, f := range []string{
		filepath.Join(confDir, "plymouthd.conf"),
		filepath.Join(policyDir, "plymouthd.defaults"),
	} {
		if err := img.AppendFile(f); err != nil {
			if os.IsNotExist(err) {
				debug("plymouth config %s not found, skipping", f)
			} else {
				return fmt.Errorf("plymouth config %s: %v", f, err)
			}
		}
	}

	// Add /etc/os-release (needed by plymouth for branding)
	if err := img.AppendFile("/etc/os-release"); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("os-release: %v", err)
		}
	}

	// Detect and add default theme
	defaultTheme := detectPlymouthTheme()
	debug("plymouth default theme: %s", defaultTheme)

	// Add the default theme + fallback themes
	for _, theme := range []string{defaultTheme, "details", "text"} {
		themeDir := filepath.Join(themesDir, theme)
		if _, err := os.Stat(themeDir); err == nil {
			if err := img.AppendFile(themeDir); err != nil {
				return fmt.Errorf("plymouth theme %s: %v", theme, err)
			}
		} else {
			debug("plymouth theme %s not found, skipping", theme)
		}
	}

	// Bundle ImageDir target if the default theme references images from another directory
	themePlymouthFile := filepath.Join(themesDir, defaultTheme, defaultTheme+".plymouth")
	if imageDir := parseThemeImageDir(themePlymouthFile); imageDir != "" {
		themeOwnDir := filepath.Join(themesDir, defaultTheme)
		// Clean both paths so trailing slashes or double slashes don't cause false mismatches
		if filepath.Clean(imageDir) != filepath.Clean(themeOwnDir) {
			debug("plymouth theme %s references images from %s", defaultTheme, imageDir)
			if _, err := os.Stat(imageDir); err == nil {
				if err := img.AppendFile(imageDir); err != nil {
					return fmt.Errorf("plymouth theme image dir %s: %v", imageDir, err)
				}
			} else {
				debug("plymouth ImageDir %s not found, skipping", imageDir)
			}
		}
	}

	// Add default.plymouth symlink — copy from host or synthesize one
	defaultPlymouth := filepath.Join(themesDir, "default.plymouth")
	if _, err := os.Lstat(defaultPlymouth); err == nil {
		if err := img.AppendFile(defaultPlymouth); err != nil {
			return fmt.Errorf("default.plymouth: %v", err)
		}
	} else if os.IsNotExist(err) {
		// No default.plymouth symlink on host; create a synthetic one
		// pointing to the detected theme's .plymouth file.
		target := filepath.Join(defaultTheme, defaultTheme+".plymouth")
		debug("synthesizing default.plymouth -> %s", target)
		mode := cpio.FileMode(0o777) | cpio.TypeSymlink
		if err := img.AppendEntry(defaultPlymouth, mode, []byte(target)); err != nil {
			return fmt.Errorf("default.plymouth symlink: %v", err)
		}
	}

	// Bundle the system-wide Plymouth logo file. Some plugins (space-flares,
	// two-step) unconditionally load it outside the theme directory.
	//
	// Discovery order (first non-empty path wins):
	//   1. Logo= key in the theme's .plymouth file (theme-specific override)
	//   2. pkg-config --variable=logofile ply-splash-core (works on some distros)
	//   3. ELF .rodata scan of the plugin .so files (distro-agnostic fallback;
	//      PLYMOUTH_LOGO_FILE is a compiled-in string literal in each plugin)
	logoFile := parseThemeLogo(themePlymouthFile)
	if logoFile == "" {
		logoFile = findPlymouthLogoFile(pluginDir)
	}
	if logoFile != "" {
		if _, err := os.Stat(logoFile); err == nil {
			if err := img.AppendFile(logoFile); err != nil {
				return fmt.Errorf("plymouth logo file %s: %v", logoFile, err)
			}
			debug("plymouth: bundled logo file %s", logoFile)
		} else {
			debug("plymouth: logo file %s configured but not found, skipping", logoFile)
		}
	}

	// Resolve and install fonts to Plymouth's hardcoded lookup paths.
	// Plymouth's label-freetype plugin looks for fonts at fixed paths:
	//   /usr/share/fonts/Plymouth.ttf              (regular)
	//   /usr/share/fonts/Plymouth-bold.ttf         (bold)
	//   /usr/share/fonts/Plymouth-monospace.ttf    (monospace)
	//   /usr/share/fonts/Plymouth-monospace-bold.ttf (monospace bold)
	// Following mkinitcpio's approach, we use fc-match to resolve the
	// theme's font on the host and copy it to these fixed paths.
	fontFamily := "Sans" // Plymouth's own default
	themeFonts := parseThemeFonts(themePlymouthFile)
	if len(themeFonts) > 0 {
		fontFamily = themeFonts[0]
		debug("plymouth theme font family: %s", fontFamily)
	}

	plymouthFonts := []struct {
		pattern string
		dest    string
	}{
		{fontFamily, "/usr/share/fonts/Plymouth.ttf"},
		{fontFamily + ":style=Bold", "/usr/share/fonts/Plymouth-bold.ttf"},
		{"monospace", "/usr/share/fonts/Plymouth-monospace.ttf"},
		{"monospace:style=Bold", "/usr/share/fonts/Plymouth-monospace-bold.ttf"},
	}

	for _, pf := range plymouthFonts {
		fontPath := fcMatch(pf.pattern)
		if fontPath == "" {
			debug("plymouth: fc-match could not resolve %q, skipping %s", pf.pattern, pf.dest)
			continue
		}
		content, err := os.ReadFile(fontPath)
		if err != nil {
			debug("plymouth: failed to read font %s: %v", fontPath, err)
			continue
		}
		if err := img.AppendContent(pf.dest, 0o644, content); err != nil {
			debug("plymouth: failed to add font %s: %v", pf.dest, err)
		} else {
			debug("plymouth: %s -> %s (from %q)", fontPath, pf.dest, pf.pattern)
		}
	}

	// Add /etc/vconsole.conf for keyboard layout configuration.
	// Plymouth reads this file to get KEYMAP, XKBLAYOUT, XKBMODEL, etc.
	// Without it, Plymouth skips input device creation entirely.
	if err := img.AppendFile("/etc/vconsole.conf"); err != nil {
		if os.IsNotExist(err) {
			debug("plymouth: /etc/vconsole.conf not found, skipping")
		} else {
			return fmt.Errorf("vconsole.conf: %v", err)
		}
	}

	// Add XKB data files needed by libxkbcommon for keyboard input handling.
	// Without these, plymouthd cannot translate keycodes to characters and
	// the password prompt won't accept keyboard input.
	xkbDir := ""
	for _, candidate := range []string{"/usr/share/X11/xkb", "/usr/share/xkb"} {
		if _, err := os.Stat(candidate); err == nil {
			xkbDir = candidate
			break
		}
	}
	if xkbDir != "" {
		if err := img.AppendFile(xkbDir); err != nil {
			return fmt.Errorf("xkb data: %v", err)
		}
	} else {
		warning("plymouth: XKB data directory not found (/usr/share/X11/xkb or /usr/share/xkb) — keyboard input may not work")
	}

	return nil
}

func detectPlymouthTheme() string {
	out, err := exec.Command("plymouth-set-default-theme").Output()
	if err != nil {
		return "details" // safe fallback
	}
	theme := strings.TrimSpace(string(out))
	if theme == "" {
		return "details"
	}
	return theme
}

// plymouthPkgConfig queries pkg-config for a Plymouth variable.
// Returns empty string if pkg-config is unavailable or the variable is not set.
func plymouthPkgConfig(variable string) string {
	out, err := exec.Command("pkg-config", "--variable="+variable, "ply-splash-core").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// findPlymouthLogoFile returns the system-wide Plymouth logo file path.
// It tries in order:
//  1. pkg-config --variable=logofile ply-splash-core (works on some distros)
//  2. ELF .rodata scan of space-flares.so and two-step.so (distro-agnostic)
//
// The Logo= theme-file key (highest priority) is handled by the caller via
// parseThemeLogo before this function is called.
func findPlymouthLogoFile(pluginDir string) string {
	if path := plymouthPkgConfig("logofile"); path != "" {
		return path
	}
	// PLYMOUTH_LOGO_FILE is compiled in as a string literal in the plugins
	// that require it. Scan each plugin's .rodata to find the path without
	// relying on pkg-config exposing it (Arch Linux does not).
	for _, plugin := range []string{"space-flares.so", "two-step.so"} {
		if path := elfLogoPath(filepath.Join(pluginDir, plugin)); path != "" {
			return path
		}
	}
	return ""
}

// elfLogoPath scans the .rodata section of a Plymouth plugin shared library
// for the compiled-in PLYMOUTH_LOGO_FILE path. It returns the first
// null-terminated string in .rodata that looks like an absolute logo path
// (starts with '/', contains "logo", ends with .png or .svg), or "" if none
// is found or the file cannot be read.
func elfLogoPath(soPath string) string {
	f, err := elf.Open(soPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	sec := f.Section(".rodata")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		return ""
	}

	// Walk the null-terminated C strings packed in .rodata.
	start := 0
	for i, b := range data {
		if b == 0 {
			if i > start {
				s := string(data[start:i])
				if s[0] == '/' &&
					strings.Contains(s, "logo") &&
					(strings.HasSuffix(s, ".png") || strings.HasSuffix(s, ".svg")) {
					return s
				}
			}
			start = i + 1
		}
	}
	return ""
}

// parseThemeImageDir reads a .plymouth theme file and extracts the ImageDir= value.
// Returns empty string if the file cannot be read or has no ImageDir directive.
func parseThemeImageDir(plymouthFile string) string {
	data, err := os.ReadFile(plymouthFile)
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "ImageDir="); ok {
			return after
		}
	}
	return ""
}

// fcMatch resolves a fontconfig pattern to a font file path using fc-match.
// Returns empty string if fc-match is unavailable or the pattern cannot be resolved.
func fcMatch(pattern string) string {
	out, err := exec.Command("fc-match", "-f", "%{file}", pattern).Output()
	if err != nil {
		return ""
	}
	path := strings.TrimSpace(string(out))
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	return path
}

// parseThemeLogo reads a .plymouth theme file and extracts the Logo= value.
// Returns empty string if absent.
func parseThemeLogo(plymouthFile string) string {
	data, err := os.ReadFile(plymouthFile)
	if err != nil {
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "Logo="); ok {
			return after
		}
	}
	return ""
}

// parseThemeFonts reads a .plymouth theme file and extracts font family names
// from Font= and TitleFont= directives (Pango font descriptions).
func parseThemeFonts(plymouthFile string) []string {
	data, err := os.ReadFile(plymouthFile)
	if err != nil {
		debug("plymouth: failed to read theme file %s: %v", plymouthFile, err)
		return nil
	}
	seen := make(set)
	var families []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		var val string
		if after, ok := strings.CutPrefix(line, "Font="); ok {
			val = after
		} else if after, ok := strings.CutPrefix(line, "TitleFont="); ok {
			val = after
		} else {
			continue
		}
		family := extractFontFamily(val)
		if family != "" && !seen[family] {
			seen[family] = true
			families = append(families, family)
		}
	}
	return families
}

// extractFontFamily extracts the font family name from a Pango font
// description like "Inter Bold 16" or "Sans 12". It strips trailing
// numeric size and style keywords.
func extractFontFamily(pangoDesc string) string {
	pangoDesc = strings.TrimSpace(pangoDesc)
	if pangoDesc == "" {
		return ""
	}

	styleWords := set{
		"Bold": true, "Italic": true, "Light": true, "Medium": true,
		"Thin": true, "Black": true, "ExtraBold": true, "SemiBold": true,
		"ExtraLight": true, "Regular": true, "Condensed": true, "Heavy": true,
		"Oblique": true, "Ultra-Bold": true, "Semi-Bold": true,
	}

	parts := strings.Fields(pangoDesc)
	// Strip trailing size (numeric)
	for len(parts) > 1 {
		if _, err := fmt.Sscanf(parts[len(parts)-1], "%f", new(float64)); err == nil {
			parts = parts[:len(parts)-1]
		} else {
			break
		}
	}
	// Strip trailing style keywords
	for len(parts) > 1 {
		if styleWords[parts[len(parts)-1]] {
			parts = parts[:len(parts)-1]
		} else {
			break
		}
	}
	return strings.Join(parts, " ")
}

// detectHostGPUModules returns the names of loadable (non-built-in) GPU kernel
// modules backing real DRM devices on this host, excluding simpledrm.
// Returns nil on a simpledrm-only or GPU-less system.
func detectHostGPUModules() []string {
	var modules []string
	cards, _ := filepath.Glob("/sys/class/drm/card[0-9]*")
	for _, card := range cards {
		// Skip connector entries (e.g. card1-DP-1, card1-eDP-1)
		if strings.Contains(filepath.Base(card), "-") {
			continue
		}
		driverLink, err := os.Readlink(filepath.Join(card, "device", "driver"))
		if err != nil {
			continue
		}
		// simpledrm registers as platform driver "simple-framebuffer"
		if filepath.Base(driverLink) == "simple-framebuffer" {
			continue
		}
		// driver/module symlink is absent for built-in drivers; skip those
		moduleLink, err := os.Readlink(filepath.Join(card, "device", "driver", "module"))
		if err != nil {
			continue
		}
		modules = append(modules, filepath.Base(moduleLink))
	}
	return modules
}
