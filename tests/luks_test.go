package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLUKS1WithName(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks1.img",
		kernelArgs: []string{"rd.luks.name=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415=cryptroot", "root=/dev/mapper/cryptroot", "rd.luks.options=discard"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS1WithUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks1.img",
		kernelArgs: []string{"rd.luks.uuid=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415", "root=UUID=ec09a1ea-d43c-4262-b701-bf2577a9ab27"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-f0c89fd5-7e1e-4ecc-b310-8cd650bd5415:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2WithName(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.img",
		kernelArgs: []string{"rd.luks.name=639b8fdd-36ba-443e-be3e-e5b335935502=cryptroot", "root=/dev/mapper/cryptroot"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2WithUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.img",
		kernelArgs: []string{"rd.luks.uuid=639b8fdd-36ba-443e-be3e-e5b335935502", "root=UUID=7bbf9363-eb42-4476-8c1c-9f1f4d091385"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-639b8fdd-36ba-443e-be3e-e5b335935502:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2WithQuotesOverUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.img",
		kernelArgs: []string{"rd.luks.uuid=\"639b8fdd-36ba-443e-be3e-e5b335935502\"", "root=UUID=\"7bbf9363-eb42-4476-8c1c-9f1f4d091385\""},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-639b8fdd-36ba-443e-be3e-e5b335935502:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// test that loadable crypto modules work https://github.com/anatol/booster/issues/188
func TestLoadableCryptoModule(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.external.module.img",
		kernelArgs: []string{"rd.luks.name=ad575500-a9e3-4692-b1b2-eed95a6e8ce2=cryptroot", "root=/dev/mapper/cryptroot"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

const (
	detachedHeaderLuksUUID = "cbd49694-81de-41bd-a850-0d934aff8328"
	detachedHeaderFsUUID   = "781780d2-bf67-4a17-9ca8-fd22336c1b2e"

	detachedHeaderHdrdevUUID = "e2d8f1a3-7b4c-4e9d-a1b2-3c4d5e6f7a8b"

	keyfileDevLuksUUID   = "7c2a39be-15d1-4b71-9f2e-5c4d1a3b8e6f"
	keyfileDevFsUUID     = "a3d8e2c1-4f7b-4e9c-b2a1-6d5f3c8e1a7b"
	keyfileDevKeydevUUID = "f1e2d3c4-b5a6-4789-8abc-def123456789"

	keyfileOffsetLuksUUID = "c0d3f4a5-b6e7-4809-9abc-def012345678"
	keyfileOffsetFsUUID   = "d1e2f3a4-c5b6-4789-abcd-ef0123456789"
)

// TestLUKS2KeyfileOnDeviceCmdline verifies that booster can unlock a LUKS2
// volume whose keyfile lives on a separate block device, specified via the
// rd.luks.key=/path:UUID=<keydev> kernel parameter.
func TestLUKS2KeyfileOnDeviceCmdline(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:   "assets/luks2.keyfile_device.img",
		params: []string{"-drive", "file=assets/luks2.keyfile_device.keydev.img,if=virtio,format=raw"},
		kernelArgs: []string{
			"rd.luks.name=" + keyfileDevLuksUUID + "=cryptroot",
			"rd.luks.key=" + keyfileDevLuksUUID + "=/keyfile:UUID=" + keyfileDevKeydevUUID,
			"root=/dev/mapper/cryptroot",
		},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestLUKS2KeyfileOnDeviceCrypttab verifies the same keyfile-on-device unlock
// path but driven by /etc/crypttab (the keyfile= field with :UUID= suffix).
func TestLUKS2KeyfileOnDeviceCrypttab(t *testing.T) {
	crypttab := filepath.Join(t.TempDir(), "crypttab.initramfs")
	content := "cryptroot UUID=" + keyfileDevLuksUUID + " /keyfile:UUID=" + keyfileDevKeydevUUID + "\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.keyfile_device.img",
		params:       []string{"-drive", "file=assets/luks2.keyfile_device.keydev.img,if=virtio,format=raw"},
		kernelArgs:   []string{"root=UUID=" + keyfileDevFsUUID},
		crypttabFile: crypttab,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestLUKS2CrypttabPassphrase verifies that booster can unlock a LUKS2 volume
// driven entirely by /etc/crypttab (no rd.luks.* kernel arguments).
func TestLUKS2CrypttabPassphrase(t *testing.T) {
	crypttab := filepath.Join(t.TempDir(), "crypttab.initramfs")
	content := "cryptroot UUID=639b8fdd-36ba-443e-be3e-e5b335935502 none\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.img",
		kernelArgs:   []string{"root=UUID=7bbf9363-eb42-4476-8c1c-9f1f4d091385"},
		crypttabFile: crypttab,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestLUKS2NofailCrypttab verifies that a crypttab entry with nofail does not
// prevent boot when the referenced device is absent.
func TestLUKS2NofailCrypttab(t *testing.T) {
	crypttab := filepath.Join(t.TempDir(), "crypttab.initramfs")
	content := "cryptroot UUID=639b8fdd-36ba-443e-be3e-e5b335935502 none\n" +
		"nonexistent UUID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee none nofail\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.img",
		kernelArgs:   []string{"root=UUID=7bbf9363-eb42-4476-8c1c-9f1f4d091385"},
		crypttabFile: crypttab,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestLUKS2CrypttabKeyfileOffsetSize verifies that booster can unlock a LUKS2
// volume using a bundled keyfile with keyfile-offset= and keyfile-size= in
// /etc/crypttab — the keyfile has a 512-byte random preamble before the real
// key material.
func TestLUKS2CrypttabKeyfileOffsetSize(t *testing.T) {
	require.NoError(t, checkAsset("assets/luks2.keyfile_offset.img"))

	// The keyfile was written alongside the image by the asset generator.
	// Use its absolute path so the booster generator can bundle it.
	keyfilePath, err := filepath.Abs("assets/luks2.keyfile_offset.key")
	require.NoError(t, err)

	crypttab := filepath.Join(t.TempDir(), "crypttab.initramfs")
	content := "cryptroot UUID=" + keyfileOffsetLuksUUID + " " + keyfilePath + " keyfile-offset=512,keyfile-size=4096\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.keyfile_offset.img",
		kernelArgs:   []string{"root=UUID=" + keyfileOffsetFsUUID},
		crypttabFile: crypttab,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestLUKS2DetachedHeaderCrypttab verifies that booster can unlock a LUKS2
// volume whose header is stored in a separate file, configured via crypttab
// header= option. The header is bundled into the initramfs by the generator.
func TestLUKS2DetachedHeaderCrypttab(t *testing.T) {
	require.NoError(t, checkAsset("assets/luks2.detached_header.img"))

	headerPath, err := filepath.Abs("assets/luks2.detached_header.hdr")
	require.NoError(t, err)

	crypttab := filepath.Join(t.TempDir(), "crypttab.initramfs")
	content := "cryptroot UUID=" + detachedHeaderLuksUUID + " none header=" + headerPath + "\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.detached_header.img",
		kernelArgs:   []string{"root=UUID=" + detachedHeaderFsUUID},
		crypttabFile: crypttab,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestLUKS2DetachedHeaderRawDevice verifies that booster can unlock a LUKS2
// volume whose detached header lives on a separate raw block device (/dev/vdb),
// configured via crypttab header=/dev/vdb.  This exercises the pendingDevices
// retry path: the data device (no embedded LUKS magic) is identified by the
// LUKS UUID read from the header device after it arrives.
func TestLUKS2DetachedHeaderRawDevice(t *testing.T) {
	require.NoError(t, checkAsset("assets/luks2.detached_header.img"))

	crypttab := filepath.Join(t.TempDir(), "crypttab.initramfs")
	// Data device identified by LUKS UUID; header on /dev/vda (virtio-blk, second disk).
	// The main data disk is on virtio-scsi (→ sda); the extra -drive if=virtio disk gets vda.
	content := "cryptroot UUID=" + detachedHeaderLuksUUID + " none header=/dev/vda\n"
	require.NoError(t, os.WriteFile(crypttab, []byte(content), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.detached_header.img",
		params:       []string{"-drive", "file=assets/luks2.detached_header.hdr,if=virtio,format=raw"},
		kernelArgs:   []string{"root=UUID=" + detachedHeaderFsUUID},
		crypttabFile: crypttab,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestLUKS2DetachedHeaderCmdlineOnDevice verifies that booster can unlock a LUKS2
// volume whose detached header lives as a file on a separate block device, specified
// via the rd.luks.header=<UUID>=/root.hdr:UUID=<devuuid> kernel parameter.
// This exercises the headerDeviceRef != nil path in acquireHeader (mountKeyDevice).
func TestLUKS2DetachedHeaderCmdlineOnDevice(t *testing.T) {
	// checkAsset for the main image first — it also creates the .hdr file.
	require.NoError(t, checkAsset("assets/luks2.detached_header.img"))
	require.NoError(t, checkAsset("assets/luks2.detached_header.hdrdev.img"))

	vm, err := buildVmInstance(t, Opts{
		disk:   "assets/luks2.detached_header.img",
		params: []string{"-drive", "file=assets/luks2.detached_header.hdrdev.img,if=virtio,format=raw"},
		kernelArgs: []string{
			"rd.luks.name=" + detachedHeaderLuksUUID + "=cryptroot",
			"rd.luks.header=" + detachedHeaderLuksUUID + "=/root.hdr:UUID=" + detachedHeaderHdrdevUUID,
			"root=UUID=" + detachedHeaderFsUUID,
		},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestLUKS2DetachedHeaderCmdline verifies the same detached-header unlock path
// driven by the rd.luks.header= kernel parameter instead of crypttab.
func TestLUKS2DetachedHeaderCmdline(t *testing.T) {
	require.NoError(t, checkAsset("assets/luks2.detached_header.img"))

	headerPath, err := filepath.Abs("assets/luks2.detached_header.hdr")
	require.NoError(t, err)

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.detached_header.img",
		extraFiles: headerPath,
		kernelArgs: []string{
			"rd.luks.name=" + detachedHeaderLuksUUID + "=cryptroot",
			"rd.luks.header=" + detachedHeaderLuksUUID + "=" + headerPath,
			"root=/dev/mapper/cryptroot",
		},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
