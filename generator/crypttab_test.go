package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/stretchr/testify/require"
)

// newTestImage creates a minimal in-memory Image for generator unit tests.
func newTestImage(t *testing.T) (*Image, string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test.img")
	img, err := NewImage(f, "none", false)
	require.NoError(t, err)
	t.Cleanup(func() { img.Cleanup() })
	return img, f
}

// readImageFile closes img, then reads and returns the content of name from the
// uncompressed CPIO archive at imgPath.  Returns nil if the file is absent.
func readImageFile(t *testing.T, img *Image, imgPath, name string) []byte {
	t.Helper()
	require.NoError(t, img.Close())

	f, err := os.Open(imgPath)
	require.NoError(t, err)
	defer f.Close()

	r := cpio.NewReader(f)
	for {
		hdr, err := r.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if hdr.Name == name || hdr.Name == "./"+name || strings.TrimPrefix(hdr.Name, "/") == strings.TrimPrefix(name, "/") {
			data, err := io.ReadAll(r)
			require.NoError(t, err)
			return data
		}
	}
	return nil
}

func TestAppendCrypttabAbsent(t *testing.T) {
	img, _ := newTestImage(t)
	_, err := img.appendCrypttab(filepath.Join(t.TempDir(), "no-such-file"))
	require.Error(t, err)
}

func TestAppendCrypttabBundled(t *testing.T) {
	dir := t.TempDir()
	crypttab := filepath.Join(dir, "crypttab")
	require.NoError(t, os.WriteFile(crypttab, []byte(
		"cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none x-initrd.attach\n",
	), 0o644))

	img, _ := newTestImage(t)
	_, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.True(t, img.contains["/etc/crypttab"])
}

// Entries without x-initrd.attach must not be included in the image.
func TestAppendCrypttabXInitrdAttachRequired(t *testing.T) {
	dir := t.TempDir()
	crypttab := filepath.Join(dir, "crypttab")
	require.NoError(t, os.WriteFile(crypttab, []byte(
		"cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none discard\n",
	), 0o644))

	img, _ := newTestImage(t)
	_, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.False(t, img.contains["/etc/crypttab"])
}

// x-initrd.attach must be stripped from options in the bundled content.
func TestAppendCrypttabXInitrdAttachStripped(t *testing.T) {
	dir := t.TempDir()
	crypttab := filepath.Join(dir, "crypttab")
	require.NoError(t, os.WriteFile(crypttab, []byte(
		"cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none discard,x-initrd.attach\n",
	), 0o644))

	img, imgPath := newTestImage(t)
	_, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.True(t, img.contains["/etc/crypttab"])

	bundled := string(readImageFile(t, img, imgPath, "/etc/crypttab"))
	require.NotContains(t, bundled, "x-initrd.attach")
	require.Contains(t, bundled, "discard")
}

// noauto entries with x-initrd.attach are included in the crypttab but
// their keyfiles are NOT bundled.
func TestAppendCrypttabNoautoSkipped(t *testing.T) {
	dir := t.TempDir()

	kf := filepath.Join(dir, "secret.key")
	require.NoError(t, os.WriteFile(kf, []byte("hunter2"), 0o600))

	crypttab := filepath.Join(dir, "crypttab")
	content := "cryptswap UUID=11111111-1111-1111-1111-111111111111 " + kf + " noauto,x-initrd.attach\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img, _ := newTestImage(t)
	_, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.True(t, img.contains["/etc/crypttab"])
	require.False(t, img.contains[kf])
}

func TestAppendCrypttabKeyfileBundled(t *testing.T) {
	dir := t.TempDir()

	kf := filepath.Join(dir, "root.key")
	require.NoError(t, os.WriteFile(kf, []byte("supersecret"), 0o600))

	crypttab := filepath.Join(dir, "crypttab")
	content := "cryptroot UUID=22222222-2222-2222-2222-222222222222 " + kf + " x-initrd.attach\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img, _ := newTestImage(t)
	_, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.True(t, img.contains[kf])
}

func TestAppendCrypttabKeyfileMissing(t *testing.T) {
	dir := t.TempDir()

	crypttab := filepath.Join(dir, "crypttab")
	content := "cryptroot UUID=22222222-2222-2222-2222-222222222222 /nonexistent/key.file x-initrd.attach\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img, _ := newTestImage(t)
	_, err := img.appendCrypttab(crypttab)
	require.Error(t, err)
}

func TestAppendCrypttabNoneKeyfileSkipped(t *testing.T) {
	dir := t.TempDir()

	crypttab := filepath.Join(dir, "crypttab")
	require.NoError(t, os.WriteFile(crypttab, []byte(
		"cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none x-initrd.attach\n",
	), 0o644))

	img, _ := newTestImage(t)
	_, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.True(t, img.contains["/etc/crypttab"])
}

func TestAppendCrypttabKeyfileOnDeviceNotBundled(t *testing.T) {
	dir := t.TempDir()

	crypttab := filepath.Join(dir, "crypttab")
	content := "cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e /keyfile:UUID=f1e2d3c4-b5a6-4789-8abc-def123456789 x-initrd.attach\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img, _ := newTestImage(t)
	_, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.True(t, img.contains["/etc/crypttab"])
	require.False(t, img.contains["/keyfile"])
}

func TestAppendCrypttabCommentAndBlankLines(t *testing.T) {
	dir := t.TempDir()

	crypttab := filepath.Join(dir, "crypttab")
	content := `
# This is a comment

cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none x-initrd.attach
# another comment
`
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img, _ := newTestImage(t)
	_, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.True(t, img.contains["/etc/crypttab"])
}

// Only entries with x-initrd.attach are written; others are excluded.
func TestAppendCrypttabMixedEntries(t *testing.T) {
	dir := t.TempDir()

	crypttab := filepath.Join(dir, "crypttab")
	content := strings.Join([]string{
		"cryptroot UUID=11111111-1111-1111-1111-111111111111 none x-initrd.attach",
		"cryptdata UUID=22222222-2222-2222-2222-222222222222 none discard",
		"cryptswap UUID=33333333-3333-3333-3333-333333333333 none x-initrd.attach,discard",
	}, "\n") + "\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	img, imgPath := newTestImage(t)
	_, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.True(t, img.contains["/etc/crypttab"])

	bundled := string(readImageFile(t, img, imgPath, "/etc/crypttab"))
	require.Contains(t, bundled, "11111111")
	require.NotContains(t, bundled, "22222222") // no x-initrd.attach
	require.Contains(t, bundled, "33333333")
}

// fido2-device= in a kept entry must cause hasFido2=true.
func TestAppendCrypttabFido2Detected(t *testing.T) {
	dir := t.TempDir()
	crypttab := filepath.Join(dir, "crypttab")
	require.NoError(t, os.WriteFile(crypttab, []byte(
		"cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none fido2-device=auto,x-initrd.attach\n",
	), 0o644))

	img, _ := newTestImage(t)
	hasFido2, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.True(t, hasFido2)
}

// fido2-device= in an entry without x-initrd.attach must not set hasFido2.
func TestAppendCrypttabFido2NotDetectedWithoutXInitrd(t *testing.T) {
	dir := t.TempDir()
	crypttab := filepath.Join(dir, "crypttab")
	require.NoError(t, os.WriteFile(crypttab, []byte(
		"cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none fido2-device=auto\n",
	), 0o644))

	img, _ := newTestImage(t)
	hasFido2, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.False(t, hasFido2)
}

// An entry without fido2-device= must leave hasFido2 false.
func TestAppendCrypttabNoFido2(t *testing.T) {
	dir := t.TempDir()
	crypttab := filepath.Join(dir, "crypttab")
	require.NoError(t, os.WriteFile(crypttab, []byte(
		"cryptroot UUID=ab6d7d78-b816-4495-928d-766d6607035e none x-initrd.attach\n",
	), 0o644))

	img, _ := newTestImage(t)
	hasFido2, err := img.appendCrypttab(crypttab)
	require.NoError(t, err)
	require.False(t, hasFido2)
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
	require.False(t, isKeyfileOnDevice("/path/key:something"))
}

func TestIsKeyfileOnDeviceEmpty(t *testing.T) {
	require.False(t, isKeyfileOnDevice(""))
}
