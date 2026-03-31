package tests

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

// Most of the command (params) come from https://virtio-fs.gitlab.io/howto-qemu.html
func TestVirtiofs(t *testing.T) {
	const pathVirtiofsd string = "/usr/lib/virtiofsd"
	require.True(t, fileExists(pathVirtiofsd))

	// Use the whole assets/ folder as root so we do not need a dedicated folder
	virtiofsd := exec.Command(pathVirtiofsd, "--socket-path=/tmp/vhostqemu", "-o", "source=assets/", "-o", "cache=always")

	require.NoError(t, virtiofsd.Start())

	go func() {
		virtiofsd.Wait()
	}()

	defer func() {
		if virtiofsd.Process != nil {
			virtiofsd.Process.Kill()
		}
	}()
	vm, err := buildVmInstance(t, Opts{
		// The init binary is already there, just use it
		kernelArgs: []string{"rootfstype=virtiofs", "root=root", "init=/init"},
		// The params come from the "Running with virtiofs" section at https://virtio-fs.gitlab.io/howto-qemu.html
		params: []string{
			// to create the communications socket
			"-chardev", "socket,id=char0,path=/tmp/vhostqemu",
			// instantiate the device
			"-device", "vhost-user-fs-pci,queue-size=1024,chardev=char0,tag=root",
			// force use of memory sharable with virtiofsd
			// NOTE: the 8G param must be set explicitly here; when updating utils.go/buildVmInstance, it shall also be updated!
			"-object", "memory-backend-file,id=mem,size=8G,mem-path=/dev/shm,share=on", "-numa", "node,memdev=mem",
		},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
