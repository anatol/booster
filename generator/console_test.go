package main

import "testing"

func TestReadFontFile(t *testing.T) {
	check := func(font string) {
		blob, err := readFontFile(font)
		if err != nil {
			t.Fatal(err)
		}

		if len(blob) < 1024 {
			t.Fatalf("%s: expected font file size bigger than 1K, got %d", font, len(blob))
		}
		if len(blob) > 16384 {
			t.Fatalf("%s: expected font file size smaller than 16K, got %d", font, len(blob))
		}
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
		if err != nil {
			t.Fatal(err)
		}

		l := len(blob)
		if l < 30 {
			t.Fatal("keymap file is too small")
		}
		if l > 3000 {
			t.Fatal("keymap file is too big")
		}
	}

	check("us", "de", true)
	check("us", "", false)
}
