package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLVMPath(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableLVM:  true,
		disk:       "assets/lvm.img",
		kernelArgs: []string{"root=/dev/booster_test_vg/booster_test_lv"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLVMUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableLVM:  true,
		disk:       "assets/lvm.img",
		kernelArgs: []string{"root=UUID=74c9e30c-506f-4106-9f61-a608466ef29c"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
