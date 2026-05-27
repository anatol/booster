package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"
)

func iesysBytes(handle uint32) []byte {
	b := make([]byte, 10)
	binary.BigEndian.PutUint32(b[0:4], 0x69657379) // magic
	binary.BigEndian.PutUint16(b[4:6], 1)          // version
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

	// Raw 4-byte big-endian handle format (no IESYS magic) → falls back to 0x81000001
	rawHandle := make([]byte, 4)
	binary.BigEndian.PutUint32(rawHandle, 0x81000003)
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle(rawHandle))

	// Invalid/malformed input → falls back to 0x81000001
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle([]byte("not a valid handle")))

	// Partial handle bytes (less than 10) → falls back to 0x81000001
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle([]byte{0x81, 0x00}))
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

// withLuksGlobals saves and restores the package-global cmdRoot and luksMappings
// so each test can mutate them in isolation.
func withLuksGlobals(t *testing.T) {
	t.Helper()
	origRoot := cmdRoot
	origMappings := luksMappings
	t.Cleanup(func() {
		cmdRoot = origRoot
		luksMappings = origMappings
	})
}

// Regular-loop match where cmdRoot identifies the same LUKS partition:
// matchLuksMapping must rewrite cmdRoot to /dev/mapper/<m.name>. This is the
// crypttab-introduced regression scenario — without the rewrite, a crypttab
// entry covering the root LUKS UUID makes `root=UUID=<luks-uuid>` boot fail.
func TestMatchLuksMappingRewritesCmdRootOnRegularLoopMatch(t *testing.T) {
	withLuksGlobals(t)

	uuid, err := parseUUID("ab6d7d78-b816-4495-928d-766d6607035e")
	require.NoError(t, err)

	m := &luksMapping{
		ref:          &deviceRef{format: refFsUUID, data: uuid},
		name:         "cryptroot",
		keySlot:      -1,
		tokenTimeout: 30 * time.Second,
	}
	luksMappings = []*luksMapping{m}
	cmdRoot = &deviceRef{format: refFsUUID, data: uuid}

	blk := &blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid}
	got := matchLuksMapping(blk)
	require.Same(t, m, got)

	require.Equal(t, refPath, cmdRoot.format, "cmdRoot must be rewritten to a path-ref")
	require.Equal(t, "/dev/mapper/cryptroot", cmdRoot.data.(string))
}

// Regular-loop match where cmdRoot points at a *different* device:
// matchLuksMapping must return the matching mapping but leave cmdRoot alone.
// (e.g. swap or data partition unlocked while root lives elsewhere.)
func TestMatchLuksMappingLeavesCmdRootAloneWhenItDoesNotMatch(t *testing.T) {
	withLuksGlobals(t)

	swapUUID, err := parseUUID("ab6d7d78-b816-4495-928d-766d6607035e")
	require.NoError(t, err)
	rootUUID, err := parseUUID("7843d77f-cdd6-4289-a4de-a708c4aacede")
	require.NoError(t, err)

	swap := &luksMapping{
		ref:          &deviceRef{format: refFsUUID, data: swapUUID},
		name:         "cryptswap",
		keySlot:      -1,
		tokenTimeout: 30 * time.Second,
	}
	luksMappings = []*luksMapping{swap}

	rootRef := &deviceRef{format: refFsUUID, data: rootUUID}
	cmdRoot = rootRef

	blk := &blkInfo{path: "/dev/sda3", format: "luks", uuid: swapUUID}
	got := matchLuksMapping(blk)
	require.Same(t, swap, got)

	require.Same(t, rootRef, cmdRoot, "cmdRoot must be untouched when the matched mapping is not the root device")
}

// Synthesis-fallback path: no entry in luksMappings, but cmdRoot points at the
// LUKS partition. matchLuksMapping must synthesise a mapping named "root" and
// rewrite cmdRoot to /dev/mapper/root (autodiscoverable-partition behaviour).
func TestMatchLuksMappingSynthesisFallbackUnchanged(t *testing.T) {
	withLuksGlobals(t)

	uuid, err := parseUUID("7f28c723-fd6b-4640-bc94-9366edd8880d")
	require.NoError(t, err)

	luksMappings = nil
	rootRef := &deviceRef{format: refFsUUID, data: uuid}
	cmdRoot = rootRef

	blk := &blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid}
	got := matchLuksMapping(blk)
	require.NotNil(t, got)
	require.Equal(t, "root", got.name)
	require.Equal(t, -1, got.keySlot)
	require.Equal(t, 30*time.Second, got.tokenTimeout)
	require.Same(t, rootRef, got.ref, "synthesised mapping must keep the original cmdRoot ref")

	require.Equal(t, refPath, cmdRoot.format)
	require.Equal(t, "/dev/mapper/root", cmdRoot.data.(string))
}

// Regression guard for the "user wrote root=/dev/mapper/cryptroot themselves"
// case. blk is the underlying LUKS partition (/dev/sda2); cmdRoot is a path-ref
// to the future mapper node. matchesRef compares paths/symlinks, so it returns
// false — the rewrite branch must not fire, and cmdRoot must be preserved.
func TestMatchLuksMappingPreservesExplicitMapperPath(t *testing.T) {
	withLuksGlobals(t)

	uuid, err := parseUUID("ab6d7d78-b816-4495-928d-766d6607035e")
	require.NoError(t, err)

	m := &luksMapping{
		ref:          &deviceRef{format: refFsUUID, data: uuid},
		name:         "cryptroot",
		keySlot:      -1,
		tokenTimeout: 30 * time.Second,
	}
	luksMappings = []*luksMapping{m}

	mapperRef := &deviceRef{format: refPath, data: "/dev/mapper/cryptroot"}
	cmdRoot = mapperRef

	blk := &blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid}
	got := matchLuksMapping(blk)
	require.Same(t, m, got)
	require.Same(t, mapperRef, cmdRoot, "explicit /dev/mapper/... cmdRoot must not be rewritten")
}

// No mapping and cmdRoot does not match the device: matchLuksMapping returns
// nil and leaves cmdRoot alone (the device is just not ours to unlock).
func TestMatchLuksMappingNoMatchReturnsNil(t *testing.T) {
	withLuksGlobals(t)

	blkUUID, err := parseUUID("ab6d7d78-b816-4495-928d-766d6607035e")
	require.NoError(t, err)
	rootUUID, err := parseUUID("7843d77f-cdd6-4289-a4de-a708c4aacede")
	require.NoError(t, err)

	luksMappings = nil
	rootRef := &deviceRef{format: refFsUUID, data: rootUUID}
	cmdRoot = rootRef

	blk := &blkInfo{path: "/dev/sdb1", format: "luks", uuid: blkUUID}
	require.Nil(t, matchLuksMapping(blk))
	require.Same(t, rootRef, cmdRoot)
}

func TestFlattenSystemdTPM2(t *testing.T) {
	t.Parallel()

	// Flat token (already flat): unchanged
	flat := map[string]any{
		"tpm2-blob":      "abc",
		"tpm2-hash-pcrs": "10+13",
	}
	require.Equal(t, flat, flattenSystemdTPM2(flat))

	// One level nesting with systemd-tpm2 wrapper
	systemdNested := map[string]any{
		"systemd-tpm2": map[string]any{
			"tpm2-blob": "xyz",
		},
	}
	result := flattenSystemdTPM2(systemdNested)
	require.Equal(t, "xyz", result["tpm2-blob"])
	require.Equal(t, map[string]any{"tpm2-blob": "xyz"}, result["systemd-tpm2"])

	// systemd_tpm2 wrapper (underscore variant)
	systemdUnderscore := map[string]any{
		"systemd_tpm2": map[string]any{
			"tpm2-pin": false,
		},
	}
	result = flattenSystemdTPM2(systemdUnderscore)
	require.Equal(t, false, result["tpm2-pin"])

	// Mixed nesting: top-level keys take precedence over flattened wrapper keys
	mixed := map[string]any{
		"systemd-tpm2": map[string]any{
			"tpm2-blob": "from-wrapper",
		},
		"tpm2-blob": "direct-value",
	}
	result = flattenSystemdTPM2(mixed)
	require.Equal(t, "direct-value", result["tpm2-blob"]) // direct value not overwritten

	// json.RawMessage handling (string containing JSON)
	jsonInString := map[string]any{
		"systemd-tpm2": json.RawMessage(`{"tpm2-blob": "nested-json"}`),
	}
	result = flattenSystemdTPM2(jsonInString)
	require.Equal(t, "nested-json", result["tpm2-blob"])

	// Array with single object (systemd sometimes wraps in array)
	arrayWrapped := map[string]any{
		"systemd-tpm2": []any{
			map[string]any{
				"tpm2-blob": "from-array",
			},
		},
	}
	result = flattenSystemdTPM2(arrayWrapped)
	require.Equal(t, "from-array", result["tpm2-blob"])

	// Two wrappers: first matching one wins (systemd-tpm2 before systemd_tpm2)
	bothWrappers := map[string]any{
		"systemd-tpm2": map[string]any{
			"tpm2-blob": "first",
		},
		"systemd_tpm2": map[string]any{
			"tpm2-blob": "second",
		},
	}
	result = flattenSystemdTPM2(bothWrappers)
	require.Equal(t, "first", result["tpm2-blob"])
}

func TestTPM2PINAuthValueEmptyCases(t *testing.T) {
	t.Parallel()

	// Empty PIN with no salt: SHA256("") path
	emptyPIN := tpm2PINAuthValue([]byte(""), nil)
	emptyPINExpected, _ := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	require.Equal(t, emptyPINExpected, emptyPIN)

	// Empty PIN with non-empty salt: PBKDF2 → base64 → SHA256 path
	emptyPINWithSalt := tpm2PINAuthValue([]byte(""), []byte("salt123"))
	// PBKDF2("", "salt123", 10000, 32) → base64 → SHA256
	require.NotEmpty(t, emptyPINWithSalt)

	// Non-empty PIN with empty salt: SHA256(pin) path
	pin := []byte("test")
	noSaltAuth := tpm2PINAuthValue(pin, nil)
	noSaltExpected := sha256.Sum256(pin)
	require.Equal(t, noSaltExpected[:], noSaltAuth)

	// PIN with empty salt (salt len 0) should use non-salted path (same as nil salt)
	emptySalt := []byte{}
	pinWithEmptySalt := tpm2PINAuthValue(pin, emptySalt)
	require.Equal(t, noSaltAuth, pinWithEmptySalt)
}

func TestPolicyHashParsing(t *testing.T) {
	t.Parallel()

	// Hex string parsing
	hexStr := "abc123"
	policyHash, err := hex.DecodeString(hexStr)
	require.NoError(t, err)
	require.Equal(t, []byte{0xab, 0xc1, 0x23}, policyHash)

	// Mixed case hex handling (hex.DecodeString handles both upper and lower)
	hexMixed := "AbC123"
	policyHash2, err := hex.DecodeString(hexMixed)
	require.NoError(t, err)
	require.Equal(t, []byte{0xab, 0xc1, 0x23}, policyHash2)

	// Base64 fallback parsing
	b64Str := "YWJjMTIz" // base64 of "abc123"
	b64Decoded, err := base64.StdEncoding.DecodeString(b64Str)
	require.NoError(t, err)
	require.Equal(t, []byte("abc123"), b64Decoded)
}

func TestPCRStringParsing(t *testing.T) {
	t.Parallel()

	// Helper to simulate PCR string parsing like in recoverSystemdTPM2Password
	parseHashPCRs := func(hashPCRs string) []int {
		var pcrs []int
		for _, s := range strings.Split(hashPCRs, "+") {
			if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v >= 0 {
				pcrs = append(pcrs, v)
			}
		}
		return pcrs
	}

	// "10+13" → []int{10, 13}
	pcrs := parseHashPCRs("10+13")
	require.Equal(t, []int{10, 13}, pcrs)

	// "0+7" → []int{0, 7}
	pcrs = parseHashPCRs("0+7")
	require.Equal(t, []int{0, 7}, pcrs)

	// Empty string → empty slice
	pcrs = parseHashPCRs("")
	require.Empty(t, pcrs)

	// Whitespace handling
	pcrs = parseHashPCRs(" 10 + 13 ")
	require.Equal(t, []int{10, 13}, pcrs)

	// Single PCR
	pcrs = parseHashPCRs("7")
	require.Equal(t, []int{7}, pcrs)
}

// unreachableMapperName fires only when cmdRoot is /dev/mapper/<name> and no
// luksMapping covers <name>. Any other shape is silent so we don't spam LVM
// or RAID setups.
func TestUnreachableMapperName(t *testing.T) {
	cases := []struct {
		desc     string
		root     *deviceRef
		mappings []*luksMapping
		wantName string
		wantOK   bool
	}{
		{
			desc:     "root=/dev/mapper/cryptroot with empty luksMappings",
			root:     &deviceRef{format: refPath, data: "/dev/mapper/cryptroot"},
			wantName: "cryptroot",
			wantOK:   true,
		},
		{
			desc:   "no cmdRoot",
			root:   nil,
			wantOK: false,
		},
		{
			desc:   "root=UUID=… is silent",
			root:   &deviceRef{format: refFsUUID, data: UUID{}},
			wantOK: false,
		},
		{
			desc:   "root=/dev/sda1 (non-mapper path) is silent",
			root:   &deviceRef{format: refPath, data: "/dev/sda1"},
			wantOK: false,
		},
		{
			desc:     "root=/dev/mapper/cryptroot WITHOUT covering mapping",
			root:     &deviceRef{format: refPath, data: "/dev/mapper/cryptroot"},
			mappings: []*luksMapping{{name: "swap"}},
			wantName: "cryptroot",
			wantOK:   true,
		},
		{
			desc:     "root=/dev/mapper/cryptroot WITH covering mapping",
			root:     &deviceRef{format: refPath, data: "/dev/mapper/cryptroot"},
			mappings: []*luksMapping{{name: "cryptroot"}},
			wantOK:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			withLuksGlobals(t)
			cmdRoot = tc.root
			luksMappings = tc.mappings
			name, ok := unreachableMapperName()
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantName, name)
		})
	}
}
