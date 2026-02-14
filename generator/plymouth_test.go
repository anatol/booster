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

func TestFindFontFiles(t *testing.T) {
	// Create a temp font directory structure
	dir := t.TempDir()

	fonts := map[string]string{
		"TTF/DejaVuSans.ttf":         "",
		"TTF/DejaVuSans-Bold.ttf":    "",
		"TTF/DejaVuSerif.ttf":        "",
		"TTF/Inter-Regular.otf":      "",
		"TTF/Inter-Bold.otf":         "",
		"TTF/NotoSans-Regular.ttc":   "",
		"TTF/Cantarell-Regular.otf":  "",
		"TTF/Cantarell-Bold.otf":     "",
		"truetype/ubuntu/Ubuntu.ttf": "",
		"misc/README.txt":            "",
	}

	for path, content := range fonts {
		full := filepath.Join(dir, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}

	dirs := []string{dir}

	t.Run("exact match", func(t *testing.T) {
		results := findFontFiles(dirs, "Inter")
		require.Len(t, results, 2)
	})

	t.Run("match with hyphen normalization", func(t *testing.T) {
		// "DejaVu Sans" normalized = "dejavusans", matches "DejaVuSans*.ttf"
		results := findFontFiles(dirs, "DejaVu Sans")
		require.Len(t, results, 2) // DejaVuSans.ttf + DejaVuSans-Bold.ttf
	})

	t.Run("no match", func(t *testing.T) {
		results := findFontFiles(dirs, "Roboto")
		require.Len(t, results, 0)
	})

	t.Run("match across subdirs", func(t *testing.T) {
		results := findFontFiles(dirs, "Ubuntu")
		require.Len(t, results, 1)
	})

	t.Run("does not match non-font files", func(t *testing.T) {
		results := findFontFiles(dirs, "README")
		require.Len(t, results, 0)
	})

	t.Run("cantarell with space normalization", func(t *testing.T) {
		results := findFontFiles(dirs, "Cantarell")
		require.Len(t, results, 2)
	})

	t.Run("empty dir list", func(t *testing.T) {
		results := findFontFiles(nil, "Inter")
		require.Len(t, results, 0)
	})
}
