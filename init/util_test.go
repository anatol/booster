package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestMemZeroBytes(t *testing.T) {
	t.Parallel()

	data := []byte{10, 40, 50, 33}
	memZeroBytes(data)
	for i, e := range data {
		require.Equalf(t, byte(0), e, "%d element is not wiped", i)
	}
}

func TestFixedArrayToString(t *testing.T) {
	t.Parallel()

	check := func(input []byte, expected string) {
		str := fixedArrayToString(input)
		require.Equal(t, expected, str)
	}

	check([]byte{}, "")
	check([]byte{'r'}, "r")
	check([]byte{'h', 'e', 'l', 'l', 'o', ',', ' '}, "hello, ")
	check([]byte{'h', '\x00', 'l', 'l', 'o', ',', ' '}, "h")
	check([]byte{'\x00'}, "")
}

func TestParseUUID(t *testing.T) {
	check := func(uuid string, expected UUID) {
		u, err := parseUUID(uuid)
		require.NoError(t, err)
		require.Equal(t, expected, u)
	}

	check("123e4567-e89b-12d3-a456-426614174000", []byte{0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17, 0x40, 0x00})
	check("17878fe4-616e-4256-b198-2aa90b53603e", []byte{0x17, 0x87, 0x8f, 0xe4, 0x61, 0x6e, 0x42, 0x56, 0xb1, 0x98, 0x2a, 0xa9, 0x0b, 0x53, 0x60, 0x3e})
	check("1705d91e-bf54-4a1a-878d-721d7233eba4", []byte{0x17, 0x05, 0xd9, 0x1e, 0xbf, 0x54, 0x4a, 0x1a, 0x87, 0x8d, 0x72, 0x1d, 0x72, 0x33, 0xeb, 0xa4})

	// invalid uuid
	invalid := func(uuid string) {
		u, err := parseUUID(uuid)
		require.Error(t, err)
		require.Nil(t, u)
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
	require.NoError(t, err)
	require.Equal(t, str, uuid.toString())

	// ms-dos uuid
	uuid = []byte{0x45, 0x22, 0x67, 0x77}
	expected := "45226777"
	require.Equal(t, expected, uuid.toString())
}

func TestStripQuotes(t *testing.T) {
	check := func(in, out string) {
		str := stripQuotes(in)
		require.Equal(t, out, str)
	}

	check("Hello", "Hello")
	check("He\"llo", "He\"llo")
	check("Hell o", "Hell o")
	check("\"Hello", "\"Hello")
	check("Hello\"", "Hello\"")
	check("\"Hello\"", "Hello")
	check("\"\"He   llo\"", "\"He   llo")
}

func TestDeviceNo(t *testing.T) {
	dir, err := os.ReadDir("/sys/block")
	require.NoError(t, err)
	for _, d := range dir {
		dev, err := deviceNo("/dev/" + d.Name())
		require.NoError(t, err)

		expected, err := os.ReadFile("/sys/block/" + d.Name() + "/dev")
		require.NoError(t, err)

		got := fmt.Sprintf("%d:%d\n", unix.Major(dev), unix.Minor(dev))
		require.Equal(t, string(expected), got)
	}
}

func TestParseProperties(t *testing.T) {
	got := parseProperties("PROP1=VAL1\nPROP2=VAL2\nPROP3=VAL3\nFONT=cp866-8x14\n")

	expect := map[string]string{
		"PROP1": "VAL1",
		"PROP2": "VAL2",
		"PROP3": "VAL3",
		"FONT":  "cp866-8x14",
	}
	require.Equal(t, expect, got)
}

func TestFromUnicode16(t *testing.T) {
	check := func(in []byte, bo binary.ByteOrder, out string) {
		s := fromUnicode16(in, bo)
		require.Equal(t, out, s)
	}
	// examples are generated with 'iconv -f utf-8 -t utf-16le'
	check([]byte{0x31, 0x00}, binary.LittleEndian, "1")
	check([]byte{0x3f, 0x04, 0x40, 0x04, 0x38, 0x04, 0x32, 0x04, 0x35, 0x04, 0x42, 0x04, 0x0, 0x0, 0x0, 0x0}, binary.LittleEndian, "привет")
	check([]byte{0x04, 0x3f, 0x04, 0x40, 0x04, 0x38, 0x04, 0x32, 0x04, 0x35, 0x04, 0x42, 0x0, 0x0}, binary.BigEndian, "привет")
}
