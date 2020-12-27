package main

import (
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
