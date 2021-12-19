package tests

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAlpineLinux(t *testing.T) {
	require.NoError(t, checkAsset("assets/alpinelinux.img")) // it will generate vmlinuz-version needed later

	alpinelinuxKernelVersion, err := os.ReadFile("assets/alpinelinux/vmlinuz-version")
	require.NoError(t, err)
	vm, err := buildVmInstance(t, Opts{
		modulesDirectory: "assets/alpinelinux/modules",
		kernelPath:       "assets/alpinelinux/vmlinuz",
		kernelVersion:    string(alpinelinuxKernelVersion),
		disk:             "assets/alpinelinux.img",
		kernelArgs:       []string{"root=/dev/sda"},
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("Welcome to Alpine Linux"))
}
