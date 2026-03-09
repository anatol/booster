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
