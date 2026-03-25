package tests

import (
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
	detachedHeaderLuksUUID   = "cbd49694-81de-41bd-a850-0d934aff8328"
	detachedHeaderFsUUID     = "781780d2-bf67-4a17-9ca8-fd22336c1b2e"
	detachedHeaderHdrdevUUID = "e2d8f1a3-7b4c-4e9d-a1b2-3c4d5e6f7a8b"
)

// TestLUKS2DetachedHeaderCmdline verifies the detached-header unlock path
// driven by the rd.luks.header= kernel parameter.
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

// TestLUKS2DetachedHeaderCmdlineRawDevice verifies that booster can unlock a LUKS2
// volume whose detached header is stored on a separate raw block device, specified
// via the rd.luks.header=<UUID>=/dev/vda kernel parameter.
// This exercises the /dev/ prefix path in acquireHeader (waitForDeviceRef, no mount).
func TestLUKS2DetachedHeaderCmdlineRawDevice(t *testing.T) {
	require.NoError(t, checkAsset("assets/luks2.detached_header.img"))

	vm, err := buildVmInstance(t, Opts{
		disk:   "assets/luks2.detached_header.img",
		params: []string{"-drive", "file=assets/luks2.detached_header.hdr,if=virtio,format=raw"},
		kernelArgs: []string{
			"rd.luks.name=" + detachedHeaderLuksUUID + "=cryptroot",
			"rd.luks.header=" + detachedHeaderLuksUUID + "=/dev/vda",
			"root=UUID=" + detachedHeaderFsUUID,
		},
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

