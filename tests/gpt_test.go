package tests

import (
	"testing"

	"github.com/anatol/vmtest"
	"github.com/stretchr/testify/require"
)

func TestGptPath(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=/dev/sda3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=UUID=e5404205-ac6a-4e94-bb3b-14433d0af7d1"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptLABEL(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=LABEL=newpart"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptPARTUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=PARTUUID=1b8e9701-59a6-49f4-8c31-b97c99cd52cf"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptPARTLABEL(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=PARTLABEL=раздел3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptPARTNROFF(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=PARTUUID=78073a8b-bdf6-48cc-918e-edb926b25f64/PARTNROFF=2"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptByUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=/dev/disk/by-uuid/e5404205-ac6a-4e94-bb3b-14433d0af7d1"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptByLABEL(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=/dev/disk/by-label/newpart"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptByPARTUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=/dev/disk/by-partuuid/1b8e9701-59a6-49f4-8c31-b97c99cd52cf"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptByPARTLABEL(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=/dev/disk/by-partlabel/раздел3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptWwid(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=WWID=scsi-QEMU_QEMU_HARDDISK_-0:0-part3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptHwpath(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=HWPATH=pci-0000:00:04.0-scsi-0:0:0:0-part3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptRootAutodiscoveryExt4(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		containsESP: true,
		kernelArgs:  []string{"console=ttyS0,115200", "ignore_loglevel"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("booster: mounting /dev/sda2->/booster.root, fs=ext4, flags=0x0, options="))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptRootAutodiscoveryLUKS(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		containsESP:   true,
		scriptEnvvars: []string{"ENABLE_LUKS=1"},
		kernelArgs:    []string{"console=ttyS0,115200", "ignore_loglevel"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for root:"))
	require.NoError(t, vm.ConsoleWrite("66789\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptRootAutodiscoveryNoAuto(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		containsESP:   true,
		scriptEnvvars: []string{"GPT_ATTR=63"},
		kernelArgs:    []string{"console=ttyS0,115200", "ignore_loglevel"},
		mountTimeout:  1,
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("booster: autodiscovery: partition /dev/sda2 has 'do not mount' GPT attribute, skip it"))
	require.NoError(t, vm.ConsoleExpect("Timeout waiting for root filesystem"))
}

func TestGptRootAutodiscoveryReadOnly(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		containsESP:   true,
		scriptEnvvars: []string{"GPT_ATTR=60"},
		kernelArgs:    []string{"console=ttyS0,115200", "ignore_loglevel"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("booster: mounting /dev/sda2->/booster.root, fs=ext4, flags=0x1, options="))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGpt4kSector(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disks:      []vmtest.QemuDisk{{Path: "assets/gpt_4ksector.img", Format: "raw", DeviceParams: []string{"physical_block_size=4096", "logical_block_size=4096"}}},
		kernelArgs: []string{"root=PARTUUID=d4699213-6e73-41d5-ad81-3daf5dfcecfb"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
