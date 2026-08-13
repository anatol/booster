package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anatol/luks.go"

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

func TestParseCrypttabNetdev(t *testing.T) {
	// _netdev only orders systemd units; the entry is otherwise ordinary and
	// must not be reported as an unknown option.
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none luks,_netdev,tries=2\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, 2, mappings[0].tries)
}

func TestParseCrypttabSkippedEntryOptions(t *testing.T) {
	// tcrypt volumes are not unlocked at all, so the tcrypt-specific options on
	// the line are moot -- reporting them would point at the wrong problem.
	input := "cryptdata UUID=ab6d7d78-b816-4495-928d-766d6607035e none tcrypt,tcrypt-hidden\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Empty(t, mappings)
}

func TestParseCrypttabDmCryptFlags(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none discard,no-read-workqueue\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Contains(t, mappings[0].options, "allow-discards")
	require.Contains(t, mappings[0].options, "no-read-workqueue")
}

func TestFlagsAreNotDuplicated(t *testing.T) {
	// dm-crypt flags are booleans and go straight into the kernel's optional
	// parameter list, so the same flag named twice must arrive once.
	mappings, err := parseCrypttabReader(strings.NewReader(
		"cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none luks,discard,discard\n"))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, []string{luks.FlagAllowDiscards}, mappings[0].options)

	// and once when two sources each name it
	dst := &luksMapping{luksOptions: newLuksOptions()}
	dst.options = []string{luks.FlagAllowDiscards}
	src := &luksMapping{luksOptions: newLuksOptions()}
	src.options = []string{luks.FlagAllowDiscards}
	composeSources(dst, src)
	require.Equal(t, []string{luks.FlagAllowDiscards}, dst.options)
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

func TestParseCrypttabMeasurePCR(t *testing.T) {
	const uuid = "UUID=ab6d7d78-b816-4495-928d-766d6607035e"
	cases := []struct {
		opt  string
		want measurePCRSetting
	}{
		{"", measurePCRAuto},
		{" tpm2-measure-pcr=yes", measurePCRForce},
		{" tpm2-measure-pcr=no", measurePCRDisabled},
	}
	for _, c := range cases {
		mappings, err := parseCrypttabReader(strings.NewReader("cryptroot " + uuid + " none" + c.opt + "\n"))
		require.NoError(t, err, c.opt)
		require.Len(t, mappings, 1)
		require.Equal(t, c.want, mappings[0].measurePCR, c.opt)
	}
}

func TestParseCrypttabSignature(t *testing.T) {
	const uuid = "UUID=ab6d7d78-b816-4495-928d-766d6607035e"
	cases := []struct {
		opt  string
		want string
	}{
		{"", ""},
		{" tpm2-signature=/etc/foo.json", "/etc/foo.json"},
		{" tpm2-signature=false", "false"},
	}
	for _, c := range cases {
		mappings, err := parseCrypttabReader(strings.NewReader("cryptroot " + uuid + " none" + c.opt + "\n"))
		require.NoError(t, err, c.opt)
		require.Len(t, mappings, 1)
		require.Equal(t, c.want, mappings[0].tpm2Signature, c.opt)
	}
}

func TestParseCrypttabMeasurePCRInvalid(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none tpm2-measure-pcr=maybe\n"
	_, err := parseCrypttabReader(strings.NewReader(input))
	require.Error(t, err)
	require.Contains(t, err.Error(), "tpm2-measure-pcr=")
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

func TestParseCrypttabValuedFlagIsUnknown(t *testing.T) {
	// A bare flag handed a value is not that flag. Splitting the option once on
	// '=' makes discard=yes reach the unknown arm rather than matching discard.
	mappings, err := parseCrypttabReader(strings.NewReader(
		"cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none discard=yes\n"))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Empty(t, mappings[0].options)
}

func TestParseCrypttabValueKeepsItsEquals(t *testing.T) {
	// Only the first '=' separates key from value, so a device ref inside the
	// value survives.
	mappings, err := parseCrypttabReader(strings.NewReader(
		"cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none header=/luks.hdr:LABEL=hdrdev\n"))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, "/luks.hdr", mappings[0].header)
	require.Equal(t, &deviceRef{refFsLabel, "hdrdev"}, mappings[0].headerDeviceRef)
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

// Any LUKS entry gets the 30s default token-timeout, not just those with
// fido2-device= or tpm2-device=. LUKS2 volumes may carry tokens enrolled
// via systemd-cryptenroll without crypttab flags.
func TestParseCrypttabDefaultTokenTimeout(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, luksOptionUnset, int(mappings[0].tokenTimeout), "an entry that never said token-timeout= is unset")
	require.Equal(t, defaultTokenTimeout, effectiveTokenTimeout(mappings[0], nil))
}

// Explicit token-timeout= in crypttab overrides the default.
func TestParseCrypttabExplicitTokenTimeout(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none token-timeout=60\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, 60*time.Second, mappings[0].tokenTimeout)
}

// fido2-device= and tpm2-device= are accepted for crypttab compatibility but no
// longer set any field; token detection uses the LUKS2 header payload instead.
func TestParseCrypttabFido2Device(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none fido2-device=auto\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, luksOptionUnset, int(mappings[0].tokenTimeout))
}

func TestParseCrypttabTpm2Device(t *testing.T) {
	input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none tpm2-device=auto\n"
	mappings, err := parseCrypttabReader(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, mappings, 1)
	require.Equal(t, luksOptionUnset, int(mappings[0].tokenTimeout))
}

func TestFindLuksMapping(t *testing.T) {
	uuid1, _ := parseUUID("ab6d7d78-b816-4495-928d-766d6607035e")
	uuid2, _ := parseUUID("7843d77f-cdd6-4289-a4de-a708c4aacede")
	m1 := &luksMapping{
		ref:         &deviceRef{format: refFsUUID, data: uuid1},
		name:        "one",
		luksOptions: newLuksOptions(),
	}
	m2 := &luksMapping{
		ref:         &deviceRef{format: refFsUUID, data: uuid2},
		name:        "two",
		luksOptions: newLuksOptions(),
	}
	orig := luksMappings
	defer func() { luksMappings = orig }()

	luksMappings = []*luksMapping{m1, m2}
	require.Equal(t, m1, findLuksMapping(m1.ref))
	require.Equal(t, m2, findLuksMapping(m2.ref))

	uuid3, _ := parseUUID("7f28c723-fd6b-4640-bc94-9366edd8880d")
	require.Nil(t, findLuksMapping(&deviceRef{format: refFsUUID, data: uuid3}))
}

// composeSources runs the boot-time composition over one cmdline mapping and
// one crypttab entry, so the tests drive resolveLuksOptions rather than
// restating what it does.
func composeSources(dst, src *luksMapping) {
	own := dst.luksOptions // what the command line set for this device
	dst.cmdlineOptions = &own
	luksMappings = []*luksMapping{dst}
	globalLuksOptions = newLuksOptions()
	resolveLuksOptions([]*luksMapping{src})
}

func TestMergeCrypttabOptions(t *testing.T) {
	dst := &luksMapping{
		name:        "cmdline-name",
		luksOptions: newLuksOptions(),
	}
	src := &luksMapping{luksOptions: newLuksOptions()}
	src.tries = 3
	// an explicit token-timeout=, as parseCrypttabReader records it
	src.tokenTimeout = 45 * time.Second
	composeSources(dst, src)
	require.Equal(t, 3, dst.tries)
	require.Equal(t, 45*time.Second, dst.tokenTimeout) // cmdline mapping was not explicit → crypttab's explicit value adopted
	require.Equal(t, "cmdline-name", dst.name)         // name must not be overwritten
}

func TestMergeKeepsExplicitTriesZero(t *testing.T) {
	// tries=0 means unlimited retries. While unset was also 0 it was
	// indistinguishable, so crypttab's tries= overwrote it and the user got a
	// bounded count.
	dst := &luksMapping{luksOptions: newLuksOptions()}
	dst.tries = 0
	src := &luksMapping{luksOptions: newLuksOptions()}
	src.tries = 3
	composeSources(dst, src)
	require.Equal(t, 0, dst.tries, "an explicit tries=0 outranks the crypttab entry")
}

func TestMergeCrypttabOptionsDstWins(t *testing.T) {
	dst := &luksMapping{
		luksOptions: newLuksOptions(),
	}
	dst.keyfile = "/cmdline/key"
	dst.keySlot = 2
	dst.tries = 5
	dst.header = "/cmdline/hdr"
	src := &luksMapping{
		luksOptions: newLuksOptions(),
	}
	src.keyfile = "/crypttab/key"
	src.keySlot = 1
	src.tries = 9
	src.header = "/crypttab/hdr"
	composeSources(dst, src)
	require.Equal(t, "/cmdline/key", dst.keyfile) // cmdline keyfile wins
	require.Equal(t, 2, dst.keySlot)              // cmdline key-slot wins
	require.Equal(t, 5, dst.tries)                // cmdline tries wins
	require.Equal(t, "/cmdline/hdr", dst.header)  // cmdline header wins
}

// An explicit token-timeout= on the kernel cmdline must outrank a crypttab
// entry for the same device — both when crypttab omits token-timeout (its
// parser still fills the 30s implicit default) and when crypttab sets a
// different explicit value. This mirrors the keyfile/header/tries merges:
// an explicit cmdline value always wins; crypttab fills only what the
// cmdline left unset. Regression for the pre-existing `src != dst` merge
// that let crypttab's implicit 30s clobber an explicit cmdline value.
func TestMergeCrypttabOptionsExplicitCmdlineTokenTimeoutWins(t *testing.T) {
	t.Run("crypttab omits token-timeout (implicit 30s) → cmdline 10s survives", func(t *testing.T) {
		dst := &luksMapping{
			luksOptions: newLuksOptions(),
		}
		dst.tokenTimeout = 10 * time.Second
		src := &luksMapping{
			luksOptions: newLuksOptions(),
		}
		src.tokenTimeout = luksOptionUnset
		composeSources(dst, src)
		require.Equal(t, 10*time.Second, dst.tokenTimeout)
	})

	t.Run("crypttab sets a different explicit value → cmdline still wins", func(t *testing.T) {
		dst := &luksMapping{
			luksOptions: newLuksOptions(),
		}
		dst.tokenTimeout = 10 * time.Second
		src := &luksMapping{
			luksOptions: newLuksOptions(),
		}
		src.tokenTimeout = 60 * time.Second
		composeSources(dst, src)
		require.Equal(t, 10*time.Second, dst.tokenTimeout, "explicit cmdline token-timeout outranks explicit crypttab")
	})

	t.Run("cmdline not explicit → explicit crypttab is adopted", func(t *testing.T) {
		dst := &luksMapping{
			luksOptions: newLuksOptions(),
		}
		dst.tokenTimeout = luksOptionUnset
		src := &luksMapping{
			luksOptions: newLuksOptions(),
		}
		src.tokenTimeout = 60 * time.Second
		composeSources(dst, src)
		require.Equal(t, 60*time.Second, dst.tokenTimeout)
	})
}

// rd.luks.name= on the kernel cmdline creates a mapping before crypttab is parsed.
// The crypttab merge must adopt options (token-timeout, keyfile, etc.) from the
// crypttab entry without creating a duplicate mapping or overwriting the name.
func TestRdLuksNameMergesCrypttabOptions(t *testing.T) {
	const uuidStr = "ab6d7d78-b816-4495-928d-766d6607035e"
	orig := luksMappings
	defer func() { luksMappings = orig }()

	luksMappings = nil
	require.NoError(t, parseParams(
		"rd.luks.name="+uuidStr+"=cryptroot root=/dev/mapper/cryptroot",
	))
	require.Len(t, luksMappings, 1)
	require.Equal(t, "cryptroot", luksMappings[0].name)

	// Simulate the crypttab merge loop from boost().
	ctInput := "cryptroot UUID=" + uuidStr + " none fido2-device=auto,token-timeout=60\n"
	ctMappings, err := parseCrypttabReader(strings.NewReader(ctInput))
	require.NoError(t, err)
	resolveLuksOptions(ctMappings)

	require.Len(t, luksMappings, 1, "should still be one mapping, not two")
	m := luksMappings[0]
	require.Equal(t, "cryptroot", m.name, "cmdline name must be preserved")
	require.Equal(t, 60*time.Second, m.tokenTimeout, "explicit token-timeout from crypttab must be merged")
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

func TestParseCrypttabKeyfileTimeout(t *testing.T) {
	t.Run("a value is recorded", func(t *testing.T) {
		input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /key.bin keyfile-timeout=10\n"
		mappings, err := parseCrypttabReader(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, mappings, 1)
		require.Equal(t, 10*time.Second, mappings[0].keyfileTimeout)
	})
	t.Run("absent leaves it unset, not zero", func(t *testing.T) {
		// zero would mean wait forever, so silence has to look different
		input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /key.bin\n"
		mappings, err := parseCrypttabReader(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, mappings, 1)
		require.Equal(t, luksOptionUnset, int(mappings[0].keyfileTimeout))
	})
	t.Run("an explicit zero survives as wait-forever", func(t *testing.T) {
		input := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /key.bin keyfile-timeout=0\n"
		mappings, err := parseCrypttabReader(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, mappings, 1)
		require.Equal(t, time.Duration(0), resolveKeyfileTimeout(mappings[0], 60))
	})
}

func TestMergeCopiesKeyfileTimeout(t *testing.T) {
	dst := &luksMapping{luksOptions: newLuksOptions()}
	src := &luksMapping{luksOptions: newLuksOptions()}
	src.keyfile = "/crypttab/key"
	src.keyfileTimeout = 10 * time.Second
	composeSources(dst, src)
	require.Equal(t, "/crypttab/key", dst.keyfile)
	require.Equal(t, 10*time.Second, dst.keyfileTimeout)
}
