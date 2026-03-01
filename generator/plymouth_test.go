package main

import (
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
