package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDeviceRef(t *testing.T) {
	check := func(path string, format refFormat, data any) {
		ref, err := parseDeviceRef(path)
		require.NoError(t, err)

		require.Equal(t, format, ref.format)
		require.Equal(t, data, ref.data)
	}

	check("/dev/foobar", refPath, "/dev/foobar")
	check("UUID=cdda787d-d583-4fb8-a4ec-d242ac61db1c", refFsUUID, UUID{205, 218, 120, 125, 213, 131, 79, 184, 164, 236, 210, 66, 172, 97, 219, 28})
	check("LABEL=hello", refFsLabel, "hello")
	check("LABEL=привет", refFsLabel, "привет")

	check("PARTUUID=cdda787d-d583-4fb8-a4ec-d242ac61db1c", refGptUUID, UUID{205, 218, 120, 125, 213, 131, 79, 184, 164, 236, 210, 66, 172, 97, 219, 28})
	check("PARTLABEL=hello", refGptLabel, "hello")
	check("PARTLABEL=привет", refGptLabel, "привет")
}

// A conflict message quotes a reference back to the user, so it has to come
// out in the form it was written in.
func TestDeviceRefStringRoundTrips(t *testing.T) {
	for _, s := range []string{
		"/dev/sda2",
		"UUID=ab6d7d78-b816-4495-928d-766d6607035e",
		"LABEL=crypt",
		"PARTUUID=ab6d7d78-b816-4495-928d-766d6607035e",
		"PARTUUID=ab6d7d78-b816-4495-928d-766d6607035e/PARTNROFF=2",
		"PARTLABEL=root",
		"HWPATH=pci-0000:00:1f.2-ata-1",
		"WWID=nvme-eui.0025388b71b1c2d4",
	} {
		ref, err := parseDeviceRef(s)
		require.NoError(t, err)
		require.Equal(t, s, ref.String())
	}
}
