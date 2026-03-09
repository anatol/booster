package main

import (
	"strings"
	"testing"
	"time"

	"github.com/anatol/luks.go"
	"github.com/stretchr/testify/require"
)

func crypttabMappings(t *testing.T, input string) []*luksMapping {
	t.Helper()
	m, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	return m
}

func TestParseCrypttabEmpty(t *testing.T) {
	require.Empty(t, crypttabMappings(t, ""))
	require.Empty(t, crypttabMappings(t, "# just a comment\n\n"))
}

func TestParseCrypttabBasic(t *testing.T) {
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none\n")
	require.Len(t, m, 1)
	require.Equal(t, "cryptroot", m[0].name)
	require.Equal(t, refFsUUID, m[0].ref.format)
	require.Equal(t, "ab6d7d78-b816-4495-928d-766d6607035e", m[0].ref.data.(UUID).toString())
	require.Empty(t, m[0].keyfile)
	require.Empty(t, m[0].options)
	require.Equal(t, -1, m[0].keySlot)
}

func TestParseCrypttabKeyfileDash(t *testing.T) {
	// both "none" and "-" mean interactive passphrase
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e -\n")
	require.Len(t, m, 1)
	require.Empty(t, m[0].keyfile)
}

func TestParseCrypttabKeyfile(t *testing.T) {
	m := crypttabMappings(t, "cryptswap UUID=deadbeef-dead-beef-dead-beefdeadbeef /etc/keys/swap.key discard\n")
	require.Len(t, m, 1)
	require.Equal(t, "/etc/keys/swap.key", m[0].keyfile)
}

func TestParseCrypttabNoauto(t *testing.T) {
	input := `
cryptroot  UUID=ab6d7d78-b816-4495-928d-766d6607035e  none  discard
cryptswap  UUID=def-00000000-0000-0000-0000-000000456789  none  noauto
`
	m := crypttabMappings(t, input)
	require.Len(t, m, 1)
	require.Equal(t, "cryptroot", m[0].name)
}

func TestParseCrypttabNonLuksModes(t *testing.T) {
	input := `
cryptroot  UUID=ab6d7d78-b816-4495-928d-766d6607035e  none  discard
swapvol    UUID=11111111-1111-1111-1111-111111111111  /dev/urandom  swap
tmpvol     UUID=22222222-2222-2222-2222-222222222222  /dev/urandom  tmp
plainvol   UUID=33333333-3333-3333-3333-333333333333  none  plain
`
	m := crypttabMappings(t, input)
	require.Len(t, m, 1)
	require.Equal(t, "cryptroot", m[0].name)
}

func TestParseCrypttabDmCryptFlags(t *testing.T) {
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none discard,no-read-workqueue,no-write-workqueue\n")
	require.Len(t, m, 1)
	require.ElementsMatch(t, []string{luks.FlagAllowDiscards, luks.FlagNoReadWorkqueue, luks.FlagNoWriteWorkqueue}, m[0].options)
}

func TestParseCrypttabFido2(t *testing.T) {
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none fido2-device=auto\n")
	require.Len(t, m, 1)
	require.True(t, m[0].tokenFido2)
	require.False(t, m[0].tokenTpm2)
	require.Equal(t, 30*time.Second, m[0].tokenTimeout) // default timeout applied
}

func TestParseCrypttabTpm2(t *testing.T) {
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none tpm2-device=auto\n")
	require.Len(t, m, 1)
	require.True(t, m[0].tokenTpm2)
	require.False(t, m[0].tokenFido2)
	require.Equal(t, 30*time.Second, m[0].tokenTimeout)
}

func TestParseCrypttabTokenTimeout(t *testing.T) {
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none fido2-device=auto,token-timeout=60\n")
	require.Len(t, m, 1)
	require.Equal(t, 60*time.Second, m[0].tokenTimeout)
}

func TestParseCrypttabTokenTimeoutZero(t *testing.T) {
	// token-timeout=0 means wait forever
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none tpm2-device=auto,token-timeout=0\n")
	require.Len(t, m, 1)
	require.Equal(t, time.Duration(0), m[0].tokenTimeout)
}

func TestParseCrypttabHeader(t *testing.T) {
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none header=/etc/luks-headers/root.hdr\n")
	require.Len(t, m, 1)
	require.Equal(t, "/etc/luks-headers/root.hdr", m[0].header)
}

func TestParseCrypttabKeySlot(t *testing.T) {
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none key-slot=2\n")
	require.Len(t, m, 1)
	require.Equal(t, 2, m[0].keySlot)
}

func TestParseCrypttabKeySlotInvalid(t *testing.T) {
	_, err := parseCrypttabReader(strings.NewReader("cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none key-slot=notanumber\n"))
	require.Error(t, err)
}

func TestParseCrypttabTries(t *testing.T) {
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none tries=3\n")
	require.Len(t, m, 1)
	require.Equal(t, 3, m[0].tries)
}

func TestParseCrypttabTriesZero(t *testing.T) {
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none tries=0\n")
	require.Len(t, m, 1)
	require.Equal(t, 0, m[0].tries)
}

func TestParseCrypttabTriesInvalid(t *testing.T) {
	_, err := parseCrypttabReader(strings.NewReader("cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none tries=bad\n"))
	require.Error(t, err)
}

func TestParseCrypttabTokenTimeoutInvalid(t *testing.T) {
	_, err := parseCrypttabReader(strings.NewReader("cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none fido2-device=auto,token-timeout=bad\n"))
	require.Error(t, err)
}

func TestParseCrypttabDevicePath(t *testing.T) {
	m := crypttabMappings(t, "cryptroot /dev/sda2 none discard\n")
	require.Len(t, m, 1)
	require.Equal(t, refPath, m[0].ref.format)
	require.Equal(t, "/dev/sda2", m[0].ref.data.(string))
}

func TestParseCrypttabLabelDevice(t *testing.T) {
	m := crypttabMappings(t, "cryptroot LABEL=myluksroot none\n")
	require.Len(t, m, 1)
	require.Equal(t, refFsLabel, m[0].ref.format)
	require.Equal(t, "myluksroot", m[0].ref.data.(string))
}

func TestParseCrypttabMultipleEntries(t *testing.T) {
	input := `
# root volume
cryptroot  UUID=ab6d7d78-b816-4495-928d-766d6607035e  none             discard,fido2-device=auto
# data volume
cryptdata  UUID=deadbeef-dead-beef-dead-beefdeadbeef  /etc/keys/data   discard
`
	m := crypttabMappings(t, input)
	require.Len(t, m, 2)

	require.Equal(t, "cryptroot", m[0].name)
	require.True(t, m[0].tokenFido2)
	require.Empty(t, m[0].keyfile)

	require.Equal(t, "cryptdata", m[1].name)
	require.False(t, m[1].tokenFido2)
	require.Equal(t, "/etc/keys/data", m[1].keyfile)
}

func TestParseCrypttabUnknownOptionsIgnored(t *testing.T) {
	// unknown options should be silently ignored (systemd behaviour)
	m := crypttabMappings(t, "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none discard,x-some-unknown-option\n")
	require.Len(t, m, 1)
	require.Equal(t, []string{luks.FlagAllowDiscards}, m[0].options)
}

func TestDeviceRefEqual(t *testing.T) {
	uuidStr := "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(uuidStr)
	require.NoError(t, err)

	a := &deviceRef{format: refFsUUID, data: uuid}
	b := &deviceRef{format: refFsUUID, data: uuid}
	require.True(t, deviceRefEqual(a, b))

	c := &deviceRef{format: refFsLabel, data: "myroot"}
	d := &deviceRef{format: refFsLabel, data: "myroot"}
	require.True(t, deviceRefEqual(c, d))

	// different formats
	require.False(t, deviceRefEqual(a, c))

	// nil cases
	require.True(t, deviceRefEqual(nil, nil))
	require.False(t, deviceRefEqual(a, nil))
	require.False(t, deviceRefEqual(nil, a))
}

func TestLuksMatchExists(t *testing.T) {
	uuidStr := "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(uuidStr)
	require.NoError(t, err)

	ref := &deviceRef{format: refFsUUID, data: uuid}

	// save and restore global state
	saved := luksMappings
	defer func() { luksMappings = saved }()

	luksMappings = nil
	require.False(t, luksMatchExists(ref))

	luksMappings = []*luksMapping{{ref: ref, name: "cryptroot", keySlot: -1}}
	require.True(t, luksMatchExists(ref))

	other, _ := parseUUID("deadbeef-dead-beef-dead-beefdeadbeef")
	otherRef := &deviceRef{format: refFsUUID, data: other}
	require.False(t, luksMatchExists(otherRef))
}
