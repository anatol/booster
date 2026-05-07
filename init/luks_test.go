package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
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

