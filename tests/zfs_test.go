package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Arch Linux zfs-dpkg package often lags behind 'linux'. Use older 'linux-lts' for ZFS tests.
func TestZfs(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableZfs:     true,
		zfsCachePath:  "assets/zfs/zpool.cache",
		disk:          "assets/zfs.img",
		kernelVersion: kernelVersions["linux-lts"],
		kernelArgs:    []string{"zfs=testpool/root"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestUnlockEncryptedZfs(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableZfs:     true,
		zfsCachePath:  "assets/zfs/zpool.cache",
		disk:          "assets/zfs_encrypted.img",
		kernelVersion: kernelVersions["linux-lts"],
		kernelArgs:    []string{"zfs=testpool/root"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for 'testpool':"))
	require.NoError(t, vm.ConsoleWrite("encrypted\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
