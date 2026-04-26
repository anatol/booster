package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"
)

func iesysBytes(handle uint32) []byte {
	b := make([]byte, 10)
	binary.BigEndian.PutUint32(b[0:4], 0x69657379) // magic
	binary.BigEndian.PutUint16(b[4:6], 1)           // version
	binary.BigEndian.PutUint32(b[6:10], handle)
	return b
}

func TestExtractSRKHandle(t *testing.T) {
	t.Parallel()

	// Well-formed bytes with standard systemd SRK handle.
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle(iesysBytes(0x81000001)))

	// Well-formed bytes with a non-standard persistent handle.
	require.Equal(t, tpmutil.Handle(0x81000002), extractSRKHandle(iesysBytes(0x81000002)))

	// Wrong magic → falls back to 0x81000001.
	bad := iesysBytes(0x81000099)
	binary.BigEndian.PutUint32(bad[0:4], 0xdeadbeef)
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle(bad))

	// Buffer too short → falls back to 0x81000001.
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle([]byte{0x69, 0x65, 0x73, 0x79}))

	// Empty → falls back to 0x81000001.
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle(nil))

	// Handle field is zero → falls back to 0x81000001.
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle(iesysBytes(0)))
}

func TestTPM2PINAuthValue(t *testing.T) {
	t.Parallel()

	// No salt: authValue = SHA256_trimmed(pin)
	noSaltAuth := tpm2PINAuthValue([]byte("foo654"), nil)
	noSaltExpected, _ := hex.DecodeString("b45f7ebd746ed390f878184a49b08d17d4fbdeccc27e226675fd81c0a94aea21")
	require.Equal(t, noSaltExpected, noSaltAuth)

	// With salt (systemd v255+ salted PIN): authValue = SHA256_trimmed(base64(PBKDF2-HMAC-SHA256(pin, salt, 10000, 32)))
	// Values from actual systemd-tpm2-withpin.img token, pin = "foo654"
	salt, _ := base64.StdEncoding.DecodeString("8/ysu/pr1gnBowEfpa7sJjtk2Yky5LC2jC7grjOrX3s=")
	saltedAuth := tpm2PINAuthValue([]byte("foo654"), salt)
	saltedExpected, _ := hex.DecodeString("9c1a75519102e847b61bebe79f9052a92cbd754e6cd9903c714614a222741761")
	require.Equal(t, saltedExpected, saltedAuth)
}

func TestParseSystemdTPM2Blob(t *testing.T) {
	t.Parallel()

	private, public, err := parseSystemdTPM2Blob([]byte{
		0x00, 0x03,
		0x01, 0x02, 0x03,
		0x00, 0x02,
		0x04, 0x05,
	})
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, private)
	require.Equal(t, []byte{0x04, 0x05}, public)
}

func TestParseSystemdTPM2BlobRejectsTruncatedData(t *testing.T) {
	t.Parallel()

	_, _, err := parseSystemdTPM2Blob([]byte{0x00})
	require.Error(t, err)

	_, _, err = parseSystemdTPM2Blob([]byte{0x00, 0x03, 0x01, 0x02})
	require.Error(t, err)

	_, _, err = parseSystemdTPM2Blob([]byte{0x00, 0x01, 0x01, 0x00, 0x02, 0x04})
	require.Error(t, err)
}
