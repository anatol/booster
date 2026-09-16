package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestXZImageCompression(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		compression: "xz",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGzipImageCompression(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		compression: "gzip",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLz4ImageCompression(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		compression: "lz4",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// Tests for https://github.com/anatol/booster/issues/117
func TestLargeLz4ImageCompression(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		compression: "lz4",
		// The point is bulk: issue 117 only reproduces on an image large enough
		// to cross lz4's legacy block boundary.  A path pattern gets there with
		// whatever GPU drivers this kernel ships, and naming modules the host
		// lacks would be an error.
		modules:    "kernel/drivers/gpu/",
		disk:       "assets/ext4.img",
		kernelArgs: []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
