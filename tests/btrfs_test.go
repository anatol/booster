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
