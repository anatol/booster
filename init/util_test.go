package main

import (
	"bytes"
	"testing"
)

func TestMemZeroBytes(t *testing.T) {
	t.Parallel()

	data := []byte{10, 40, 50, 33}
	MemZeroBytes(data)
	for i, e := range data {
		if e != 0 {
			t.Fatalf("MemZeroBytes() did not clear element # %v", i)
		}
	}
}

func TestFixedArrayToString(t *testing.T) {
	t.Parallel()

	check := func(input []byte, expected string) {
		str := fixedArrayToString(input)
		if str != expected {
			t.Fatalf("Expected string %v, got %v", expected, str)
		}
	}

	check([]byte{}, "")
	check([]byte{'r'}, "r")
	check([]byte{'h', 'e', 'l', 'l', 'o', ',', ' '}, "hello, ")
	check([]byte{'h', '\x00', 'l', 'l', 'o', ',', ' '}, "h")
	check([]byte{'\x00'}, "")
}

func TestParseUUID(t *testing.T) {
	check := func(uuid string, expected []byte) {
		u, err := parseUUID(uuid)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(u, expected) {
			t.Fatalf("uuid %s does not match expected result", uuid)
		}
	}

	check("123e4567-e89b-12d3-a456-426614174000", []byte{0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00})
	check("17878fe4-616e-4256-b198-2aa90b53603e", []byte{0x17, 0x87, 0x8f, 0xe4, 0x61, 0x6e, 0x42, 0x56, 0xb1, 0x98, 0x2a, 0xa9, 0x0b, 0x53, 0x60, 0x3e})
	check("1705d91e-bf54-4a1a-878d-721d7233eba4", []byte{0x17, 0x05, 0xd9, 0x1e, 0xbf, 0x54, 0x4a, 0x1a, 0x87, 0x8d, 0x72, 0x1d, 0x72, 0x33, 0xeb, 0xa4})

	// invalid uuid
	invalid := func(uuid string) {
		u, err := parseUUID(uuid)
		if err == nil {
			t.Fatalf("uuid %s expected to fail but it did not", uuid)
		}
		if u != nil {
			t.Fatal("expected to return nil uuid")
		}
	}
	invalid(`"1705d91e-bf54-4a1a-878d-721d7233eba4"`)
	invalid("1705d91e-bf54-4a1a-878d-721d7233eb4")
	invalid("1705d91e-bf54-4a1a-878d-721d7233eba42")
	invalid("1705d91ebf544a1a878d721d7233eba4")
	invalid("1705d91-ebf54-4a1a-878d-721d7233eba4")
}

func TestFormatUUID(t *testing.T) {
	// uuid v4
	str := "1705d91e-bf54-4a1a-878d-721d7233eba4"
	uuid, err := parseUUID(str)
	if err != nil {
		t.Fatal(err)
	}
	if uuid.toString() != str {
		t.Fatalf("incorrect uuid formatting: expected %s, got %s", str, uuid.toString())
	}

	// msdos uuid
	uuid = []byte{0x45, 0x22, 0x67, 0x77}
	expected := "45226777"
	if uuid.toString() != expected {
		t.Fatalf("incorrect uuid formatting: expected %s, got %s", expected, uuid.toString())
	}
}

func TestStripQuotes(t *testing.T) {
	check := func(in, out string) {
		str := stripQuotes(in)
		if str != out {
			t.Fatalf("Stripping failed: expected out is %s, got %s", out, str)
		}
	}

	check("Hello", "Hello")
	check("He\"llo", "He\"llo")
	check("Hell o", "Hell o")
	check("\"Hello", "\"Hello")
	check("Hello\"", "Hello\"")
	check("\"Hello\"", "Hello")
	check("\"\"He   llo\"", "\"He   llo")
}
