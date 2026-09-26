package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

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
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"
	resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options=discard",
		"cryptroot UUID="+u+" none luks,discard\n")
	require.Equal(t, []string{luks.FlagAllowDiscards}, luksMappings[0].options)
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

func TestGlobalKeyfileTimeoutTakesEffect(t *testing.T) {
	// A UUID-less rd.luks.options=keyfile-timeout= must reach the resolver, not
	// just the field: unset and an explicit zero are different answers.
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"
	resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options=keyfile-timeout=7", "")
	require.Equal(t, 7*time.Second, resolveKeyfileTimeout(luksMappings[0], 60))

	resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options=keyfile-timeout=0", "")
	require.Equal(t, time.Duration(0), resolveKeyfileTimeout(luksMappings[0], 60))
}
func TestCmdlineOptionsSurviveACrypttabParseError(t *testing.T) {
	// The options are composed once, after crypttab is read. If that composition
	// were skipped when the file fails to parse, every rd.luks.* option would be
	// silently dropped and a detached-header setup would stop booting.
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"
	luksMappings = nil
	require.NoError(t, parseParams("rd.luks.name="+u+"=cryptroot rd.luks.options="+u+"=tries=9,header=/luks.hdr"))

	_, err := parseCrypttabReader(strings.NewReader("cryptroot BOGUS=notauuid none luks\n"))
	require.Error(t, err, "the entry must fail to parse")

	resolveLuksOptions(nil) // what boost() does on that error path
	m := luksMappings[0]
	require.Equal(t, 9, m.tries)
	require.Equal(t, "/luks.hdr", m.header)
}
func TestNegativeOptionValuesAreRejected(t *testing.T) {
	// A negative value would land on or near luksOptionUnset and read as
	// "nothing set it", silently discarding what the user asked for.
	for _, opt := range []string{"tries=-1", "key-slot=-1", "keyfile-offset=-1",
		"keyfile-size=-1", "keyfile-timeout=-1", "token-timeout=-5s"} {
		o := newLuksOptions()
		_, err := parseLuksOptions(&o, opt, "test")
		require.Error(t, err, "%s must be rejected", opt)
	}
}
func TestBoundsDoNotFollowALosingKeyfile(t *testing.T) {
	// keyfile-offset= describes the key file named beside it. When rd.luks.key=
	// supplies a different one, applying the entry's bounds to it would read the
	// wrong bytes and the unlock would fail.
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"
	resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.key="+u+"=/b.key",
		"cryptroot UUID="+u+" /a.key luks,keyfile-offset=4096,keyfile-size=64\n")
	m := luksMappings[0]
	require.Equal(t, "/b.key", m.keyfile)
	require.Zero(t, m.keyfileOffset)
	require.Zero(t, m.keyfileSize)
}

func TestOverlayCarriesEveryOptionField(t *testing.T) {
	// overlay lists its fields by hand, which is the one place a new option can
	// be silently dropped. Build a source with every field set to something no
	// unset value equals, overlay it onto an empty set, and require the result
	// to be identical: a field overlay forgets fails here rather than at boot.
	var src luksOptions
	v := reflect.ValueOf(&src).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		f = reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem() // fields are unexported
		switch f.Kind() {
		case reflect.Slice:
			f.Set(reflect.ValueOf([]string{"sentinel-value"}))
		case reflect.String:
			f.SetString("sentinel-value")
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int, reflect.Int64:
			f.SetInt(7) // differs from every unset value: -1, 0, measurePCRAuto
		case reflect.Ptr:
			f.Set(reflect.ValueOf(&deviceRef{refFsLabel, "sentinel"}))
		default:
			require.Failf(t, "unhandled field kind",
				"luksOptions.%s has kind %s; teach this test about it",
				v.Type().Field(i).Name, f.Kind())
		}
	}

	dst := luksOptions{}
	overlay(&dst, &src)
	require.Equal(t, src, dst, "overlay did not carry every field of luksOptions")
}

func TestOverlayCallOrderIsPrecedence(t *testing.T) {
	low, high := newLuksOptions(), newLuksOptions()
	low.tries, low.keySlot = 1, 1
	high.tries = 9

	merged := newLuksOptions()
	overlay(&merged, &low)
	overlay(&merged, &high)
	require.Equal(t, 9, merged.tries, "the later source wins where it sets a value")
	require.Equal(t, 1, merged.keySlot, "and leaves alone what it does not set")

	// swapping the calls swaps the precedence -- this is the whole mechanism
	merged = newLuksOptions()
	overlay(&merged, &high)
	overlay(&merged, &low)
	require.Equal(t, 1, merged.tries)
}

func TestOverlayCarriesKeyfileBoundsAsOptions(t *testing.T) {
	// the bounds are ordinary options; the key file itself is crypttab's third
	// field and is merged by whoever decides that field
	low, high := newLuksOptions(), newLuksOptions()
	low.keyfileOffset, low.keyfileSize = 4096, 64
	high.keyfileOffset = 512

	merged := newLuksOptions()
	overlay(&merged, &low)
	overlay(&merged, &high)
	require.Equal(t, int64(512), merged.keyfileOffset, "the later source wins")
	require.Equal(t, int64(64), merged.keyfileSize, "and leaves alone what it does not set")
}

func TestCrypttabFillsWhatTheCmdlineLeftUnset(t *testing.T) {
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"
	resolveSources(t, "rd.luks.name="+u+"=cmdline-name",
		"cryptroot UUID="+u+" none luks,tries=3,token-timeout=45\n")
	m := luksMappings[0]
	require.Equal(t, 3, m.tries)
	require.Equal(t, 45*time.Second, m.tokenTimeout)
	require.Equal(t, "cmdline-name", m.name, "the name must not be overwritten")
}

func TestCmdlineTriesZeroOutranksCrypttab(t *testing.T) {
	// tries=0 means unlimited retries. While unset was also 0 it was
	// indistinguishable, so crypttab's tries= overwrote it.
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"
	resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options=tries=0",
		"cryptroot UUID="+u+" none luks,tries=3\n")
	require.Equal(t, 0, luksMappings[0].tries, "an explicit tries=0 outranks the crypttab entry")
}

func TestCmdlineOutranksCrypttabPerField(t *testing.T) {
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"
	resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options=key-slot=2,tries=5",
		"cryptroot UUID="+u+" /crypttab/key luks,key-slot=1,tries=9,header=/crypttab/hdr\n")
	m := luksMappings[0]
	require.Equal(t, 2, m.keySlot, "cmdline key-slot wins")
	require.Equal(t, 5, m.tries, "cmdline tries wins")
	require.Equal(t, "/crypttab/key", m.keyfile, "crypttab supplies what the cmdline did not")
	require.Equal(t, "/crypttab/hdr", m.header)
}

// An explicit token-timeout= on the kernel cmdline must outrank a crypttab
// entry for the same device — both when crypttab omits token-timeout (its
// parser still fills the 30s implicit default) and when crypttab sets a
// different explicit value. This mirrors the keyfile/header/tries merges:
// an explicit cmdline value always wins; crypttab fills only what the
// cmdline left unset. Regression for the pre-existing `src != dst` merge
// that let crypttab's implicit 30s clobber an explicit cmdline value.
func TestCmdlineTokenTimeoutOutranksCrypttab(t *testing.T) {
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"

	t.Run("crypttab omits it, the cmdline value survives", func(t *testing.T) {
		resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options=token-timeout=10",
			"cryptroot UUID="+u+" none luks\n")
		require.Equal(t, 10*time.Second, luksMappings[0].tokenTimeout)
	})

	t.Run("both set it, the cmdline still wins", func(t *testing.T) {
		resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options=token-timeout=10",
			"cryptroot UUID="+u+" none luks,token-timeout=60\n")
		require.Equal(t, 10*time.Second, luksMappings[0].tokenTimeout)
	})

	t.Run("neither sets it, the resolver supplies the default", func(t *testing.T) {
		resolveSources(t, "rd.luks.name="+u+"=cryptroot", "cryptroot UUID="+u+" none luks\n")
		require.Equal(t, luksOptionUnset, int(luksMappings[0].tokenTimeout))
		require.Equal(t, defaultTokenTimeout, effectiveTokenTimeout(luksMappings[0], nil))
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

// resolveSources runs the full cmdline-then-crypttab resolution the boot does.
func resolveSources(t *testing.T, params, crypttab string) {
	t.Helper()
	luksMappings = nil
	require.NoError(t, parseParams(params))
	ct, err := parseCrypttabReader(strings.NewReader(crypttab))
	require.NoError(t, err)
	resolveLuksOptions(ct)
}

func TestOverlayAccumulatesDmCryptFlags(t *testing.T) {
	a, b := newLuksOptions(), newLuksOptions()
	a.options = []string{luks.FlagAllowDiscards}
	b.options = []string{luks.FlagSameCPUCrypt}

	merged := newLuksOptions()
	overlay(&merged, &a)
	overlay(&merged, &b)
	require.Equal(t, []string{luks.FlagAllowDiscards, luks.FlagSameCPUCrypt}, merged.options)
}

func TestParseLuksOptionsRecordsAppliedOptions(t *testing.T) {
	// An ordinary entry carries only markers booster acts on in no way, so
	// replacing its options loses nothing and must not be announced as a loss.
	for _, opts := range []string{"luks", "_netdev", "luks,_netdev", "",
		"fido2-device=auto", "tpm2-device=auto"} {
		o := newLuksOptions()
		_, err := parseLuksOptions(&o, opts, "test")
		require.NoError(t, err)
		require.Empty(t, o.appliedOptions, "options %q set nothing booster acts on", opts)
	}

	// Only the options that set something are recorded, in the order given, so
	// the dropped-options message names what a user would have to repeat.
	o := newLuksOptions()
	_, err := parseLuksOptions(&o, "luks,tries=2,_netdev,discard,key-slot=3", "test")
	require.NoError(t, err)
	require.Equal(t, []string{"tries=2", "discard", "key-slot=3"}, o.appliedOptions)
}

func TestJoinOptionsDropsRepeats(t *testing.T) {
	// appliedOptions is a record of what was parsed, so it keeps repeats; a
	// message telling the user what to paste must not echo them.
	require.Equal(t, "discard,tries=2", joinOptions([]string{"discard", "tries=2", "discard"}))
	require.Equal(t, "", joinOptions(nil))
}

func TestPerDeviceListReplacesCrypttabOptions(t *testing.T) {
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"

	// systemd-cryptsetup replaces an entry's option field when a per-device
	// rd.luks.options= names the device, so the command line can remove an
	// option and not only add one. tries= comes from the cmdline; discard and
	// key-slot= were only in crypttab and do not survive.
	resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options="+u+"=tries=9",
		"cryptroot UUID="+u+" none luks,tries=2,discard,key-slot=3\n")
	require.Len(t, luksMappings, 1)
	m := luksMappings[0]
	require.Equal(t, 9, m.tries)
	require.Empty(t, m.options)
	require.Equal(t, luksOptionUnset, m.keySlot)
}

func TestReplacedEntryKeepsItsKeyfile(t *testing.T) {
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"

	// The keyfile is crypttab's third field, not an option, so it survives the
	// replacement. keyfile-offset= and keyfile-size= are options and do not.
	resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options="+u+"=tries=9",
		"cryptroot UUID="+u+" /etc/luks.key luks,keyfile-offset=4096,keyfile-size=64\n")
	m := luksMappings[0]
	require.Equal(t, "/etc/luks.key", m.keyfile)
	require.Zero(t, m.keyfileOffset)
	require.Zero(t, m.keyfileSize)
}

func TestCrypttabMergesWhenNoPerDeviceList(t *testing.T) {
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"

	// Without a per-device list nothing about the merge changes: the command
	// line still takes precedence and crypttab still fills what it left unset.
	resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options=discard",
		"cryptroot UUID="+u+" none luks,tries=2\n")
	m := luksMappings[0]
	require.Equal(t, []string{luks.FlagAllowDiscards}, m.options)
	require.Equal(t, 2, m.tries)
}
func TestCrypttabKeyfileAndItsTimeoutSurvive(t *testing.T) {
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"
	resolveSources(t, "rd.luks.name="+u+"=cryptroot",
		"cryptroot UUID="+u+" /crypttab/key luks,keyfile-timeout=10\n")
	m := luksMappings[0]
	require.Equal(t, "/crypttab/key", m.keyfile)
	require.Equal(t, 10*time.Second, m.keyfileTimeout)
}

// A rd.luks.key= without a UUID used to be resolved the moment it was parsed,
// against however many mappings existed at that instant: it demanded exactly
// one, so it aborted the boot for two devices, for none, and whenever it was
// written before the parameter naming the device. It is a default now, applied
// where every source is known.
func TestUUIDLessKeyfileIsADefault(t *testing.T) {
	const u = "fc5197e2-df8f-43a6-9cc7-658dead3cfa4"
	const v = "ab6d7d78-b816-4495-928d-766d6607035e"

	t.Run("reaches every device the command line names", func(t *testing.T) {
		resolveSources(t, "rd.luks.name="+u+"=root rd.luks.name="+v+"=data rd.luks.key=/k.key", "")
		require.Len(t, luksMappings, 2)
		require.Equal(t, "/k.key", luksMappings[0].keyfile)
		require.Equal(t, "/k.key", luksMappings[1].keyfile)
	})

	t.Run("does not depend on where it appears", func(t *testing.T) {
		resolveSources(t, "rd.luks.key=/k.key rd.luks.name="+u+"=root", "")
		require.Equal(t, "/k.key", luksMappings[0].keyfile)
	})

	t.Run("a per-device key file outranks it", func(t *testing.T) {
		resolveSources(t, "rd.luks.name="+u+"=root rd.luks.key=/default.key rd.luks.key="+u+"=/own.key", "")
		require.Equal(t, "/own.key", luksMappings[0].keyfile)
	})

	t.Run("outranks a crypttab key file, as any cmdline one does", func(t *testing.T) {
		resolveSources(t, "rd.luks.name="+u+"=root rd.luks.key=/k.key",
			"root UUID="+u+" /entry.key luks\n")
		require.Equal(t, "/k.key", luksMappings[0].keyfile)
	})

	t.Run("leaves a device only crypttab names alone", func(t *testing.T) {
		resolveSources(t, "rd.luks.name="+u+"=root rd.luks.key=/k.key",
			"data UUID="+v+" /entry.key luks\n")
		require.Len(t, luksMappings, 2)
		for _, m := range luksMappings {
			if m.name == "data" {
				require.Equal(t, "/entry.key", m.keyfile, "the entry's own key file stands")
			}
		}
	})
}

// conflictingFields walks the same fields overlay does. A field added to
// luksOptions and to overlay but not to conflictingFields would be overwritten
// silently, which is the failure the reporter exists to prevent, so the two
// lists are pinned against the struct itself.
func TestConflictingFieldsCoversEveryOverlaidField(t *testing.T) {
	covered := []string{
		"header", "tokenTimeout", "keyfileTimeout", "keySlot", "tries",
		"keyfileOffset", "keyfileSize", "measurePCR", "tpm2Signature",
	}
	// options and noFail are additive, so a second source never displaces them.
	// appliedOptions is bookkeeping and headerDeviceRef travels with header.
	additive := []string{"options", "noFail", "appliedOptions", "headerDeviceRef"}

	var got []string
	ty := reflect.TypeOf(luksOptions{})
	for i := range ty.NumField() {
		got = append(got, ty.Field(i).Name)
	}
	require.ElementsMatch(t, append(covered, additive...), got,
		"a new luksOptions field must be added to overlay and conflictingFields, or listed as additive here")
}

func TestConflictingFieldsNamesOnlyWhatIsOverwritten(t *testing.T) {
	lower, higher := newLuksOptions(), newLuksOptions()
	lower.tries, lower.header = 2, "/from-entry.hdr"
	higher.tries, higher.keySlot = 9, 3

	got := conflictingFields(&lower, &higher)
	require.Len(t, got, 1, "header and key-slot are set by one source each")
	require.Equal(t, "tries", got[0].field)
	require.Equal(t, "9", got[0].kept)
	require.Equal(t, "2", got[0].dropped)
}

func TestConflictingFieldsIsQuietWhenSourcesAgree(t *testing.T) {
	lower, higher := newLuksOptions(), newLuksOptions()
	lower.tries, higher.tries = 4, 4
	require.Empty(t, conflictingFields(&lower, &higher))
}

// Fields 1 to 3 are decided in pairCrypttabEntry, so that is where an entry
// losing one has to be noticed.
func TestPairingReportsTheFieldsAnEntryLoses(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.name="+u+"=root rd.luks.key="+u+"=/cmdline.key",
		"cryptroot LABEL=crypt /entry.key luks\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)

	text := strings.Join(conflictMessages(m.conflicts()), "\n")
	require.Contains(t, text, "volume name")
	require.Contains(t, text, `"cryptroot"`)
	require.Contains(t, text, `"root"`)
	require.Contains(t, text, "key file")
	require.Contains(t, text, "/entry.key")
	require.Contains(t, text, "/cmdline.key")
}

// The message a per-device list displaces a whole option field with is the one
// already released, so the remedy it names has to survive being generalised.
func TestPerDeviceListKeepsTheReleasedRemedyText(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.name="+u+"=root rd.luks.options="+u+"=tries=2",
		"cryptroot LABEL=crypt none luks,tries=7,discard\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)

	text := strings.Join(m.setAside, "\n")
	require.Contains(t, text, "tries=7")
	require.Contains(t, text, "discard")
	require.Contains(t, text, "replaces a crypttab entry's options rather than adding to them")
	require.Contains(t, text, "Repeat on the command line any that are still needed")
}

// The message is logged when crypttab is read, in the wording releases have
// printed, so a device that never arrives still reports it.
func TestPerDeviceListWarnsWhenCrypttabIsRead(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	luksMappings = nil
	require.NoError(t, parseParams("rd.luks.name="+u+"=root rd.luks.options="+u+"=tries=2"))
	ct, err := parseCrypttabReader(strings.NewReader("cryptroot UUID=" + u + " none luks,key-slot=3\n"))
	require.NoError(t, err)

	logged := resolveLuksOptions(ct)
	require.Equal(t, []string{`crypttab: entry "cryptroot": options "key-slot=3" dropped. A per-device rd.luks.options= replaces a crypttab entry's options rather than adding to them. Repeat on the command line any that are still needed.`}, logged)
}

// A marker configures nothing, so losing it costs the user nothing and naming
// it would train them to ignore the message.
func TestMarkersAreNeverReportedAsLost(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.name="+u+"=cryptroot rd.luks.options="+u+"=tries=2",
		"cryptroot LABEL=crypt none luks,_netdev,fido2-device=auto\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)
	require.Empty(t, conflictMessages(m.conflicts()), "the entry set nothing booster acts on")
}

// Agreement is the common shape: a bundled entry and a command line that name
// the same volume must not warn on every boot.
func TestAgreeingSourcesProduceNoConflict(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.name="+u+"=cryptroot",
		"cryptroot LABEL=crypt none luks,tries=7\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)
	require.Empty(t, conflictMessages(m.conflicts()))
}

// A parked headerless device is dispatched again for every header device that
// arrives, and each dispatch recomposes its sources. The report is keyed on the
// device, so only the first dispatch speaks.
func TestConflictsAreReportedOncePerDevice(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.name="+u+"=root", "cryptroot LABEL=crypt none luks,tries=7\n")
	blk := &blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"}

	m := matchLuksMapping(blk)
	require.NotNil(t, m)
	require.NotEmpty(t, m.conflicts())

	// matchLuksMapping has already reported this arrival. Clearing the guard
	// lets the test watch the first report happen.
	reportedConflicts.Clear()
	require.NotEmpty(t, reportLuksConflicts(blk.path, m.conflicts()), "first arrival logs it")
	require.Empty(t, reportLuksConflicts(blk.path, m.conflicts()), "every later one is silent")
}

// A device paired on arrival is composed a second time. The first
// composition's findings must not come back with the second's, or every lost
// option is announced twice.
func TestArrivalReportsEachConflictOnce(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.uuid="+u+" rd.luks.options=tries=3",
		"a UUID="+u+" none luks,tries=5\nb LABEL=crypt none luks,key-slot=2\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)

	text := strings.Join(conflictMessages(m.conflicts()), "\n")
	require.Equal(t, 1, strings.Count(text, `tries is "3"`), text)
}

// Two entries for one device: each value is credited to the entry that wrote
// it, so the message sends the user to the right line of crypttab.
func TestEntryConflictNamesBothEntries(t *testing.T) {
	withLuksGlobals(t)

	resolveSources(t, "", "a LABEL=crypt none luks,tries=5\nb LABEL=crypt none luks,tries=6\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", label: "crypt"})
	require.NotNil(t, m)

	text := strings.Join(conflictMessages(m.conflicts()), "\n")
	require.Contains(t, text, `tries is "6" from crypttab entry "b"; "5" from crypttab entry "a" is not applied`)
}

// An option two entries disagree on is never blamed on a command line that
// did not set it.
func TestEntryConflictIsNotBlamedOnTheCommandLine(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.uuid="+u,
		"a UUID="+u+" none luks,key-slot=1\nb LABEL=crypt none luks,key-slot=2\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)

	text := strings.Join(conflictMessages(m.conflicts()), "\n")
	require.Contains(t, text, `key-slot is "2" from crypttab entry "b"; "1" from crypttab entry "a" is not applied`)
	require.NotContains(t, text, `"1" from the command line`)
}

// The command line naming the entry's own key file replaces nothing, so the
// entry's bounds still describe the file that is read. Clearing them reads the
// wrong bytes and the unlock fails.
func TestSameKeyFileKeepsTheEntrysBounds(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	resolveSources(t, "rd.luks.name="+u+"=a rd.luks.key="+u+"=/k",
		"a UUID="+u+" /k luks,keyfile-offset=512,keyfile-size=64\n")

	require.Len(t, luksMappings, 1)
	m := luksMappings[0]
	require.Equal(t, int64(512), m.keyfileOffset)
	require.Equal(t, int64(64), m.keyfileSize)
	require.Empty(t, conflictMessages(m.conflicts()))
}

// A key file an earlier entry supplied is not the command line's, and the
// bounds note names the source that replaced the file.
func TestKeyFileConflictNamesTheEntryThatWon(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.uuid="+u, "a UUID="+u+" /ka luks\nb LABEL=crypt /kb luks,keyfile-offset=16\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)

	text := strings.Join(conflictMessages(m.conflicts()), "\n")
	require.Contains(t, text, `key file is "/ka" from crypttab entry "a"; "/kb" from crypttab entry "b" is not applied`)
	require.Contains(t, text, `It bounds a key file crypttab entry "a" replaced`)
	require.NotContains(t, text, `from the command line; "/kb"`)
}

// Two headers at the same path on different devices are different headers,
// and the message has to show the devices or it reads as a value losing to
// itself.
func TestHeaderConflictNamesTheDevice(t *testing.T) {
	withLuksGlobals(t)

	const (
		u = "ab6d7d78-b816-4495-928d-766d6607035e"
		a = "11111111-1111-1111-1111-111111111111"
		b = "22222222-2222-2222-2222-222222222222"
	)
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.uuid="+u,
		"a UUID="+u+" none header=/h.img:UUID="+a+"\nb LABEL=crypt none header=/h.img:UUID="+b+"\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)

	text := strings.Join(conflictMessages(m.conflicts()), "\n")
	require.Contains(t, text, `header is "/h.img:UUID=`+b+`" from crypttab entry "b"; "/h.img:UUID=`+a+`" from crypttab entry "a" is not applied`)
}

// A lost volume name is ordinary until root= waits for it: then the boot hangs
// on a node nothing creates, and that one conflict is a warning.
func TestLostVolumeNameWarnsWhenRootWaitsForIt(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.uuid="+u+" root=/dev/mapper/cryptroot", "cryptroot LABEL=crypt none luks\n")
	blk := &blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"}
	m := matchLuksMapping(blk)
	require.NotNil(t, m)

	reportedConflicts.Clear()
	logged := reportLuksConflicts(blk.path, m.conflicts())
	require.Contains(t, logged, `root=/dev/mapper/cryptroot will not appear: LUKS device /dev/sda2 is unlocked as "luks-`+u+`"`)

	cmdRoot = &deviceRef{refPath, "/dev/mapper/luks-" + u}
	reportedConflicts.Clear()
	for _, msg := range reportLuksConflicts(blk.path, m.conflicts()) {
		require.NotContains(t, msg, "will not appear", "root= names the volume that does appear")
	}
}

// Entries merged into one record share its options but not its key file, so a
// key file conflict names the one entry that set it.
func TestKeyFileNamesTheOneEntryThatSetIt(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.name="+u+"=root rd.luks.key="+u+"=/cmdline.key",
		"cryptroot LABEL=crypt /entry.key luks\nother LABEL=crypt none luks,tries=2\n")
	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)

	text := strings.Join(conflictMessages(m.conflicts()), "\n")
	require.Contains(t, text, `"/entry.key" from crypttab entry "cryptroot" is not applied`)
}

// The same path on another device is another file: the entry's bounds go
// with it, and the message shows both devices.
func TestKeyFileOnAnotherDeviceIsAnotherFile(t *testing.T) {
	withLuksGlobals(t)

	const (
		u = "ab6d7d78-b816-4495-928d-766d6607035e"
		a = "11111111-1111-1111-1111-111111111111"
		b = "22222222-2222-2222-2222-222222222222"
	)
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.name="+u+"=a",
		"a UUID="+u+" /k:UUID="+a+" luks\nb LABEL=crypt /k:UUID="+b+" luks,keyfile-offset=512\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)
	require.Zero(t, m.keyfileOffset)

	text := strings.Join(conflictMessages(m.conflicts()), "\n")
	require.Contains(t, text, `key file is "/k:UUID=`+a+`" from crypttab entry "a"; "/k:UUID=`+b+`" from crypttab entry "b" is not applied`)
}

// An entry's second field is the device it unlocks. rd.luks.data= naming
// another one wins today, and the entry's is named as not applied.
func TestEncryptedDeviceConflictIsReported(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.name="+u+"=root rd.luks.data="+u+"=/dev/sdb", "root UUID="+u+" none luks\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sdb", format: "luks", uuid: uuid})
	require.NotNil(t, m)
	require.Equal(t, "/dev/sdb", m.dataDeviceRef.String())

	text := strings.Join(conflictMessages(m.conflicts()), "\n")
	require.Contains(t, text, `encrypted device is "/dev/sdb" from the command line; "UUID=`+u+`" from crypttab entry "root" is not applied`)
}

// Paired on arrival, the pin and the entry can reference the arrived device in
// two forms, here WWID= and a path. That is agreement, not a conflict.
func TestEncryptedDeviceReferencedTwoWaysIsNotAConflict(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.name="+u+"=root rd.luks.data="+u+"=WWID=disk0", "root /dev/sdb none luks\n")

	m := matchLuksMapping(&blkInfo{path: "/dev/sdb", format: "luks", uuid: uuid, wwid: []string{"disk0"}})
	require.NotNil(t, m)
	require.NotContains(t, strings.Join(conflictMessages(m.conflicts()), "\n"), "encrypted device")
}

// When a device falls back to a prompt or fails to unlock, a setting another
// source displaced may be why, so it is repeated as a warning. Only settings
// that take part in unlocking qualify, and each device logs them once.
func TestLostUnlockSettingsSurfaceWhenUnlockBreaks(t *testing.T) {
	withLuksGlobals(t)

	const u = "ab6d7d78-b816-4495-928d-766d6607035e"
	uuid, err := parseUUID(u)
	require.NoError(t, err)

	resolveSources(t, "rd.luks.name="+u+"=root rd.luks.key="+u+"=/cmdline.key",
		"cryptroot LABEL=crypt /entry.key luks,tries=7\nother LABEL=crypt none luks,tries=2\n")
	m := matchLuksMapping(&blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid, label: "crypt"})
	require.NotNil(t, m)

	logged := surfaceLostUnlockSettings("/dev/sda2", m)
	text := strings.Join(logged, "\n")
	require.Contains(t, text, `key file is "/cmdline.key"`)
	require.NotContains(t, text, "volume name", "a lost name does not stop an unlock")
	require.NotContains(t, text, "tries is", "nor does a retry count")
	require.Empty(t, surfaceLostUnlockSettings("/dev/sda2", m), "logged once per device")
}
