package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestXZImageCompression(t *testing.T) {
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
	vm, err := buildVmInstance(t, Opts{
		compression: "lz4",
		modules:     "nvidia,nvidia_modeset,nvidia_drm,nvidia_uvm,amdgpu",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
