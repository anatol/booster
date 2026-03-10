package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBtrfsRaid0(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/btrfs_raid0.img",
		kernelArgs: []string{"root=UUID=5eaa0c1c-e1dc-4be7-9b03-9f1ed5a87289"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

const (
	btrfsSharedLuksUUID1 = "a1b2c3d4-1111-4111-8111-111111111111"
	btrfsSharedLuksUUID2 = "a2b2c3d4-2222-4222-8222-222222222222"
	btrfsSharedFsUUID    = "a3b2c3d4-3333-4333-8333-333333333333"

	btrfsDiffLuksUUID1 = "b1b2c3d4-1111-4111-8111-111111111112"
	btrfsDiffLuksUUID2 = "b2b2c3d4-2222-4222-8222-222222222223"
	btrfsDiffFsUUID    = "b3b2c3d4-3333-4333-8333-333333333334"
)

// TestBtrfsRaid1LuksSharedPassphrase boots a system whose root is a btrfs
// RAID1 spanning two LUKS2-encrypted drives that share the same passphrase.
// Booster prompts once (for crypt2, the virtio_blk drive that appears first).
// After PBKDF completes, the passphrase is cached; crypt1 acquires the console
// mutex, finds the cached password, and unlocks silently — no second prompt.
// waitForBtrfsDevicesReady then assembles and mounts btrfs.
func TestBtrfsRaid1LuksSharedPassphrase(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		// luks2.btrfs_two_a2.img (crypt2, password "1234") is the virtio_blk
		// drive and appears first; luks2.btrfs_two_a.img (crypt1) is the
		// virtio-scsi drive and appears second.
		disk:   "assets/luks2.btrfs_two_a.img",
		params: []string{"-drive", "file=assets/luks2.btrfs_two_a2.img,if=virtio,format=raw"},
		kernelArgs: []string{
			"rd.luks.name=" + btrfsSharedLuksUUID1 + "=crypt1",
			"rd.luks.name=" + btrfsSharedLuksUUID2 + "=crypt2",
			"root=UUID=" + btrfsSharedFsUUID,
		},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// crypt2 prompts first; one passphrase is enough for both drives.
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for crypt2:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestBtrfsRaid1LuksDifferentPassphrases boots a system whose root is a btrfs
// RAID1 spanning two LUKS2-encrypted drives with distinct passphrases.
// crypt2 (virtio_blk, appears first) prompts first; its password is cached but
// does not match crypt1, so crypt1 prompts separately after crypt2's PBKDF.
// waitForBtrfsDevicesReady holds the mount until both dm-crypt devices are open.
func TestBtrfsRaid1LuksDifferentPassphrases(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		// luks2.btrfs_two_b2.img is crypt2 (password "5678", virtio_blk, first).
		// luks2.btrfs_two_b.img  is crypt1 (password "1234", virtio-scsi, second).
		disk:   "assets/luks2.btrfs_two_b.img",
		params: []string{"-drive", "file=assets/luks2.btrfs_two_b2.img,if=virtio,format=raw"},
		kernelArgs: []string{
			"rd.luks.name=" + btrfsDiffLuksUUID1 + "=crypt1",
			"rd.luks.name=" + btrfsDiffLuksUUID2 + "=crypt2",
			"root=UUID=" + btrfsDiffFsUUID,
		},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// crypt2 prompts first; cache tries "5678" against crypt1 (no match);
	// crypt1 then prompts for its own passphrase.
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for crypt2:"))
	require.NoError(t, vm.ConsoleWrite("5678\n"))
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for crypt1:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
