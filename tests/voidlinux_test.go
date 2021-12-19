package tests

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVoidLinux(t *testing.T) {
	require.NoError(t, checkAsset("assets/voidlinux.img")) // it will generate vmlinuz-version needed later

	voidlinuxKernelVersion, err := os.ReadFile("assets/voidlinux/vmlinuz-version")
	require.NoError(t, err)
	vm, err := buildVmInstance(t, Opts{
		modulesDirectory: "assets/voidlinux/modules",
		kernelPath:       "assets/voidlinux/vmlinuz",
		kernelVersion:    string(voidlinuxKernelVersion),
		disk:             "assets/voidlinux.img",
		kernelArgs:       []string{"root=/dev/sda"},
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("runsvchdir: default: current."))
}
