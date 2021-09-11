package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadFontFile(t *testing.T) {
	check := func(font string) {
		blob, err := readFontFile(font)
		require.NoError(t, err)

		require.Greaterf(t, len(blob), 1024, "font size is too small")
		require.Lessf(t, len(blob), 16384, "font size is too big")
	}

	check("lat0-16")
	check("pancyrillic.f16")
	check("165")
	check("t")
	check("Lat2-Terminus16")
}

func TestLoadKeymap(t *testing.T) {
	check := func(keymap, keymapToggle string, isUtf bool) {
		blob, err := loadKeymap(keymap, keymapToggle, isUtf)
		require.NoError(t, err)

		require.Greaterf(t, len(blob), 30, "keymap size is too small")
		require.Lessf(t, len(blob), 3000, "keymap size is too big")
	}

	check("us", "de", true)
	check("us", "", false)
}
