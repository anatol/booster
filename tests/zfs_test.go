package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestZfs(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableZfs:    true,
		zfsCachePath: "assets/zfs/zpool.cache",
		disk:         "assets/zfs.img",
		kernelArgs:   []string{"zfs=testpool/root"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestUnlockEncryptedZfs(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableZfs:    true,
		zfsCachePath: "assets/zfs/zpool.cache",
		disk:         "assets/zfs_encrypted.img",
		kernelArgs:   []string{"zfs=testpool/root"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for 'testpool':"))
	require.NoError(t, vm.ConsoleWrite("encrypted\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
