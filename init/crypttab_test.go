package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCrypttabEmpty(t *testing.T) {
	mappings, err := parseCrypttabReader(strings.NewReader(""))
	require.NoError(t, err)
	require.Empty(t, mappings)
}

func TestParseCrypttabCommentAndBlank(t *testing.T) {
	input := `
# This is a comment

# another comment
`
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Empty(t, mappings)
}

func TestParseCrypttabBasic(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	m := mappings[0]
	require.Equal(t, "cryptroot", m.name)
	require.Equal(t, "", m.keyfile)
	require.Equal(t, -1, m.keySlot)
}

func TestParseCrypttabKeyfileDash(t *testing.T) {
	for _, kf := range []string{"none", "-"} {
		input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e " + kf + "\n"
		mappings, err := parseCrypttabReader(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, mappings, 1)
		require.Equal(t, "", mappings[0].keyfile, "keyfile for %q should be empty", kf)
	}
}

func TestParseCrypttabKeyfile(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /etc/keys/root.key\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, "/etc/keys/root.key", mappings[0].keyfile)
}

// noauto entries should be silently excluded — not auto-unlocked at boot.
func TestParseCrypttabNoauto(t *testing.T) {
	input := "cryptswap UUID=11111111-1111-1111-1111-111111111111 none noauto\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Empty(t, mappings)
}

// Non-LUKS modes (swap, tmp, plain, bitlk, tcrypt) are not processed at boot.
func TestParseCrypttabNonLuksModes(t *testing.T) {
	for _, mode := range []string{"swap", "tmp", "plain", "bitlk", "tcrypt"} {
		input := "crypt1 UUID=22222222-2222-2222-2222-222222222222 none " + mode + "\n"
		mappings, err := parseCrypttabReader(strings.NewReader(input))
		require.NoError(t, err)
		require.Empty(t, mappings, "mode %q should be skipped", mode)
	}
}

func TestParseCrypttabDmCryptFlags(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none discard,no-read-workqueue\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Contains(t, mappings[0].options, "allow-discards")
	require.Contains(t, mappings[0].options, "no-read-workqueue")
}

func TestParseCrypttabLuksOption(t *testing.T) {
	// "luks" is a standard crypttab marker for LUKS format; booster detects LUKS
	// via blkinfo so it accepts the option without error and without any action.
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none luks\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Empty(t, mappings[0].options)
}

func TestParseCrypttabKeySlot(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none key-slot=2\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, 2, mappings[0].keySlot)
}

func TestParseCrypttabKeySlotDefault(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, -1, mappings[0].keySlot)
}

func TestParseCrypttabKeySlotInvalid(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none key-slot=bad\n"
	_, err := parseCrypttabReader(strings.NewReader(input))
	require.Error(t, err)
	require.Contains(t, err.Error(), "key-slot=")
}

func TestParseCrypttabNofail(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none nofail\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.True(t, mappings[0].noFail)
}

func TestParseCrypttabNofailDefault(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.False(t, mappings[0].noFail)
}

func TestParseCrypttabTries(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none tries=5\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, 5, mappings[0].tries)
}

// tries=0 means unlimited attempts.
func TestParseCrypttabTriesZero(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none tries=0\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, 0, mappings[0].tries)
}

func TestParseCrypttabTriesInvalid(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none tries=bad\n"
	_, err := parseCrypttabReader(strings.NewReader(input))
	require.Error(t, err)
	require.Contains(t, err.Error(), "tries=")
}

func TestParseCrypttabKeyfileOffset(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /key.bin keyfile-offset=512\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, int64(512), mappings[0].keyfileOffset)
}

func TestParseCrypttabKeyfileSize(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /key.bin keyfile-size=64\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, int64(64), mappings[0].keyfileSize)
}

func TestParseCrypttabKeyfileOffsetAndSize(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /key.bin keyfile-offset=128,keyfile-size=32\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, int64(128), mappings[0].keyfileOffset)
	require.Equal(t, int64(32), mappings[0].keyfileSize)
}

func TestParseCrypttabKeyfileOffsetInvalid(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /key.bin keyfile-offset=bad\n"
	_, err := parseCrypttabReader(strings.NewReader(input))
	require.Error(t, err)
	require.Contains(t, err.Error(), "keyfile-offset=")
}

func TestParseCrypttabKeyfileSizeInvalid(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /key.bin keyfile-size=bad\n"
	_, err := parseCrypttabReader(strings.NewReader(input))
	require.Error(t, err)
	require.Contains(t, err.Error(), "keyfile-size=")
}

func TestParseCrypttabDevicePath(t *testing.T) {
	input := "cryptroot /dev/sda2 none\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, refPath, mappings[0].ref.format)
}

func TestParseCrypttabLabelDevice(t *testing.T) {
	input := "cryptroot LABEL=cryptdisk none\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, refFsLabel, mappings[0].ref.format)
	require.Equal(t, "cryptdisk", mappings[0].ref.data.(string))
}

func TestParseCrypttabMultipleEntries(t *testing.T) {
	input := strings.Join([]string{
		"cryptroot UUID=11111111-1111-1111-1111-111111111111 none",
		"cryptdata UUID=22222222-2222-2222-2222-222222222222 /etc/keys/data.key",
		"cryptswap UUID=33333333-3333-3333-3333-333333333333 none noauto",
	}, "\n") + "\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 2) // noauto entry excluded
	require.Equal(t, "cryptroot", mappings[0].name)
	require.Equal(t, "cryptdata", mappings[1].name)
}

func TestParseCrypttabUnknownOptionsIgnored(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none future-option=value\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
}

// x-initrd.attach is silently ignored by init (generator already filtered to only
// bundle entries with this option; init processes everything in the bundled crypttab).
func TestParseCrypttabXInitrdAttachIgnored(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none x-initrd.attach,discard\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	// x-initrd.attach must not appear in options
	for _, o := range mappings[0].options {
		require.NotEqual(t, "x-initrd.attach", o)
	}
}

// fido2-device= is silently ignored — deferred to pr/crypttab-fido2.
func TestParseCrypttabFido2DeviceIgnored(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none fido2-device=auto\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
}

// header= is silently ignored — deferred to pr/crypttab-header.
func TestParseCrypttabHeaderIgnored(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none header=/etc/headers/root.img\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
}

func TestDeviceRefEqualUUID(t *testing.T) {
	a := &deviceRef{format: refFsUUID, data: UUID{0xab, 0x6d, 0x7d, 0x78}}
	b := &deviceRef{format: refFsUUID, data: UUID{0xab, 0x6d, 0x7d, 0x78}}
	c := &deviceRef{format: refFsUUID, data: UUID{0x00, 0x00, 0x00, 0x00}}
	require.True(t, deviceRefEqual(a, b))
	require.False(t, deviceRefEqual(a, c))
}

func TestDeviceRefEqualLabel(t *testing.T) {
	a := &deviceRef{format: refFsLabel, data: "myroot"}
	b := &deviceRef{format: refFsLabel, data: "myroot"}
	c := &deviceRef{format: refFsLabel, data: "other"}
	require.True(t, deviceRefEqual(a, b))
	require.False(t, deviceRefEqual(a, c))
}

func TestDeviceRefEqualDifferentFormat(t *testing.T) {
	a := &deviceRef{format: refFsLabel, data: "same"}
	b := &deviceRef{format: refPath, data: "same"}
	require.False(t, deviceRefEqual(a, b))
}

func TestDeviceRefEqualNil(t *testing.T) {
	a := &deviceRef{format: refFsLabel, data: "x"}
	require.False(t, deviceRefEqual(a, nil))
	require.False(t, deviceRefEqual(nil, a))
	require.True(t, deviceRefEqual(nil, nil))
}

func writeTestKeyfile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key.bin")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func TestReadKeyfileEntire(t *testing.T) {
	path := writeTestKeyfile(t, []byte("secretkey"))
	data, err := readKeyfile(path, 0, 0)
	require.NoError(t, err)
	require.Equal(t, []byte("secretkey"), data)
}

func TestReadKeyfileWithOffset(t *testing.T) {
	path := writeTestKeyfile(t, []byte("XXXsecretkey"))
	data, err := readKeyfile(path, 3, 0)
	require.NoError(t, err)
	require.Equal(t, []byte("secretkey"), data)
}

func TestReadKeyfileWithSize(t *testing.T) {
	path := writeTestKeyfile(t, []byte("secretkeyXXX"))
	data, err := readKeyfile(path, 0, 9)
	require.NoError(t, err)
	require.Equal(t, []byte("secretkey"), data)
}

func TestReadKeyfileWithOffsetAndSize(t *testing.T) {
	path := writeTestKeyfile(t, []byte("XXXsecretkeyXXX"))
	data, err := readKeyfile(path, 3, 9)
	require.NoError(t, err)
	require.Equal(t, []byte("secretkey"), data)
}

func TestReadKeyfileNotFound(t *testing.T) {
	_, err := readKeyfile(filepath.Join(t.TempDir(), "nonexistent.key"), 0, 0)
	require.Error(t, err)
}
