package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// newTestImage creates a minimal in-memory Image for generator unit tests.
func newTestImage(t *testing.T) *Image {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test.img")
	img, err := NewImage(f, "none", false)
	require.NoError(t, err)
	t.Cleanup(func() { img.Cleanup() })
	return img
}

func TestAppendCrypttabAbsent(t *testing.T) {
	img := newTestImage(t)
	// point at a path that doesn't exist — should silently succeed
	require.NoError(t, img.appendCrypttabFrom(filepath.Join(t.TempDir(), "no-such-file")))
	require.False(t, img.contains["/etc/crypttab"])
}

func TestAppendCrypttabBundled(t *testing.T) {
	dir := t.TempDir()
	crypttab := filepath.Join(dir, "crypttab.initramfs")
	require.NoError(t, os.WriteFile(crypttab, []byte("cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none discard\n"), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFrom(crypttab))
	require.True(t, img.contains["/etc/crypttab"])
}

func TestAppendCrypttabNoautoSkipped(t *testing.T) {
	dir := t.TempDir()

	// create a keyfile that would be bundled if the entry weren't noauto
	kf := filepath.Join(dir, "secret.key")
	require.NoError(t, os.WriteFile(kf, []byte("hunter2"), 0o600))

	crypttab := filepath.Join(dir, "crypttab.initramfs")
	content := "cryptswap UUID=11111111-1111-1111-1111-111111111111 " + kf + " noauto\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFrom(crypttab))
	// crypttab itself is bundled
	require.True(t, img.contains["/etc/crypttab"])
	// but the keyfile referenced by the noauto entry should NOT be bundled
	require.False(t, img.contains[kf])
}

func TestAppendCrypttabKeyfileBundled(t *testing.T) {
	dir := t.TempDir()

	kf := filepath.Join(dir, "swap.key")
	require.NoError(t, os.WriteFile(kf, []byte("supersecret"), 0o600))

	crypttab := filepath.Join(dir, "crypttab.initramfs")
	content := "cryptswap UUID=22222222-2222-2222-2222-222222222222 " + kf + " discard\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFrom(crypttab))
	require.True(t, img.contains[kf])
}

func TestAppendCrypttabKeyfileMissing(t *testing.T) {
	dir := t.TempDir()

	crypttab := filepath.Join(dir, "crypttab.initramfs")
	content := "cryptswap UUID=22222222-2222-2222-2222-222222222222 /nonexistent/key.file discard\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.Error(t, img.appendCrypttabFrom(crypttab))
}

func TestAppendCrypttabNoneKeyfileSkipped(t *testing.T) {
	dir := t.TempDir()

	crypttab := filepath.Join(dir, "crypttab.initramfs")
	require.NoError(t, os.WriteFile(crypttab, []byte("cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none discard\n"), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFrom(crypttab))
}

func TestAppendCrypttabHeaderBundled(t *testing.T) {
	dir := t.TempDir()

	hdr := filepath.Join(dir, "root.hdr")
	require.NoError(t, os.WriteFile(hdr, []byte("fake-luks-header"), 0o600))

	crypttab := filepath.Join(dir, "crypttab.initramfs")
	content := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none header=" + hdr + "\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFrom(crypttab))
	require.True(t, img.contains[hdr])
}

func TestAppendCrypttabHeaderRelativePathError(t *testing.T) {
	dir := t.TempDir()

	crypttab := filepath.Join(dir, "crypttab.initramfs")
	content := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none header=relative/path.hdr\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.Error(t, img.appendCrypttabFrom(crypttab))
}

func TestIsKeyfileOnDeviceUUID(t *testing.T) {
	require.True(t, isKeyfileOnDevice("/keyfile:UUID=f1e2d3c4-b5a6-4789-8abc-def123456789"))
}

func TestIsKeyfileOnDeviceLabel(t *testing.T) {
	require.True(t, isKeyfileOnDevice("/keyfile:LABEL=myusbkey"))
}

func TestIsKeyfileOnDevicePartuuid(t *testing.T) {
	require.True(t, isKeyfileOnDevice("/key:PARTUUID=f1e2d3c4-b5a6-4789-8abc-def123456789"))
}

func TestIsKeyfileOnDevicePartlabel(t *testing.T) {
	require.True(t, isKeyfileOnDevice("/key:PARTLABEL=usbkeys"))
}

func TestIsKeyfileOnDevicePlainPath(t *testing.T) {
	require.False(t, isKeyfileOnDevice("/etc/keys/root.key"))
}

func TestIsKeyfileOnDeviceColonNonDevice(t *testing.T) {
	// colon present but right side is not a device specifier
	require.False(t, isKeyfileOnDevice("/path/key:something"))
}

func TestIsKeyfileOnDeviceEmpty(t *testing.T) {
	require.False(t, isKeyfileOnDevice(""))
}

func TestAppendCrypttabKeyfileOnDeviceNotBundled(t *testing.T) {
	dir := t.TempDir()

	// The keyfile itself doesn't exist on the host — it lives on a runtime device.
	// The generator should skip bundling it without error.
	crypttab := filepath.Join(dir, "crypttab.initramfs")
	content := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /keyfile:UUID=f1e2d3c4-b5a6-4789-8abc-def123456789 discard\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFrom(crypttab))
	require.True(t, img.contains["/etc/crypttab"])
	// the device-resident keyfile path must NOT be bundled
	require.False(t, img.contains["/keyfile"])
}

func TestIsHeaderOnDeviceRawBlock(t *testing.T) {
	require.True(t, isHeaderOnDevice("/dev/sdb"))
	require.True(t, isHeaderOnDevice("/dev/vdb"))
}

func TestIsHeaderOnDevicePlainFile(t *testing.T) {
	require.False(t, isHeaderOnDevice("/etc/luks/root.hdr"))
}

func TestIsHeaderOnDeviceEmpty(t *testing.T) {
	require.False(t, isHeaderOnDevice(""))
}

func TestAppendCrypttabHeaderRawDeviceNotBundled(t *testing.T) {
	dir := t.TempDir()

	// header=/dev/vdb — lives on a runtime block device, must not be bundled.
	crypttab := filepath.Join(dir, "crypttab.initramfs")
	content := "cryptroot /dev/vda none header=/dev/vdb\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFrom(crypttab))
	require.True(t, img.contains["/etc/crypttab"])
	require.False(t, img.contains["/dev/vdb"])
}

func TestHasXInitrdAttach(t *testing.T) {
	require.True(t, hasXInitrdAttach("x-initrd.attach"))
	require.True(t, hasXInitrdAttach("discard,x-initrd.attach"))
	require.True(t, hasXInitrdAttach("x-initrd.attach,nofail"))
	require.False(t, hasXInitrdAttach("discard,nofail"))
	require.False(t, hasXInitrdAttach(""))
}

func TestAppendCrypttabFilteredAbsent(t *testing.T) {
	dir := t.TempDir()
	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFiltered(filepath.Join(dir, "no-such-file")))
	require.False(t, img.contains["/etc/crypttab"])
}

func TestAppendCrypttabFilteredNoXInitrd(t *testing.T) {
	dir := t.TempDir()
	crypttab := filepath.Join(dir, "crypttab")
	// entries without x-initrd.attach should be ignored
	content := "cryptroot UUID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa none discard\n" +
		"cryptswap UUID=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb none swap\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFiltered(crypttab))
	require.False(t, img.contains["/etc/crypttab"])
}

func TestAppendCrypttabFilteredXInitrdIncluded(t *testing.T) {
	dir := t.TempDir()
	crypttab := filepath.Join(dir, "crypttab")
	content := "cryptroot UUID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa none discard,x-initrd.attach\n" +
		"cryptdata UUID=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb none discard\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFiltered(crypttab))
	require.True(t, img.contains["/etc/crypttab"])
}

func TestAppendCrypttabFilteredKeyfileBundled(t *testing.T) {
	dir := t.TempDir()

	kf := filepath.Join(dir, "root.key")
	require.NoError(t, os.WriteFile(kf, []byte("secret"), 0o600))

	crypttab := filepath.Join(dir, "crypttab")
	content := "cryptroot UUID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa " + kf + " discard,x-initrd.attach\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFiltered(crypttab))
	require.True(t, img.contains[kf])
}

func TestAppendCrypttabFilteredKeyfileNotBundledWithoutXInitrd(t *testing.T) {
	dir := t.TempDir()

	kf := filepath.Join(dir, "root.key")
	require.NoError(t, os.WriteFile(kf, []byte("secret"), 0o600))

	crypttab := filepath.Join(dir, "crypttab")
	content := "cryptroot UUID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa " + kf + " discard\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFiltered(crypttab))
	require.False(t, img.contains["/etc/crypttab"])
	require.False(t, img.contains[kf])
}

// TestAppendCrypttabSystemPath exercises the appendCrypttab() entry point
// (i.e. the BOOSTER_SYSTEM_CRYPTTAB env var path) end-to-end: entries with
// x-initrd.attach are bundled, those without are filtered out.
func TestAppendCrypttabSystemPath(t *testing.T) {
	dir := t.TempDir()

	kfIncluded := filepath.Join(dir, "included.key")
	require.NoError(t, os.WriteFile(kfIncluded, []byte("secret1"), 0o600))

	kfExcluded := filepath.Join(dir, "excluded.key")
	require.NoError(t, os.WriteFile(kfExcluded, []byte("secret2"), 0o600))

	crypttab := filepath.Join(dir, "crypttab")
	content := "cryptroot UUID=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa " + kfIncluded + " discard,x-initrd.attach\n" +
		"cryptdata UUID=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb " + kfExcluded + " discard\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	t.Setenv("BOOSTER_SYSTEM_CRYPTTAB", crypttab)

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttab())
	require.True(t, img.contains["/etc/crypttab"])
	require.True(t, img.contains[kfIncluded])  // x-initrd.attach entry's keyfile is bundled
	require.False(t, img.contains[kfExcluded]) // non-x-initrd.attach entry's keyfile is not
}

func TestAppendCrypttabCommentAndBlankLines(t *testing.T) {
	dir := t.TempDir()

	crypttab := filepath.Join(dir, "crypttab.initramfs")
	content := `
# This is a comment

cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none discard
# another comment
`
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img := newTestImage(t)
	require.NoError(t, img.appendCrypttabFrom(crypttab))
	require.True(t, img.contains["/etc/crypttab"])
}
