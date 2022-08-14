package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLUKS1WithName(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks1.img",
		kernelArgs: []string{"rd.luks.name=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415=cryptroot", "root=/dev/mapper/cryptroot", "rd.luks.options=discard"},
		kernelPath: "/boot/vmlinuz-5.18.11-1.el7.elrepo.x86_64",
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("sdbc123sdflkh213\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS1WithUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks1.img",
		kernelArgs: []string{"rd.luks.uuid=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415", "root=UUID=ec09a1ea-d43c-4262-b701-bf2577a9ab27"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-f0c89fd5-7e1e-4ecc-b310-8cd650bd5415:"))
	require.NoError(t, vm.ConsoleWrite("sdbc123sdflkh213\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2WithName(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.img",
		kernelArgs: []string{"rd.luks.name=639b8fdd-36ba-443e-be3e-e5b335935502=cryptroot", "root=/dev/mapper/cryptroot"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("sdbc123sdflkh213\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2WithUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.img",
		kernelArgs: []string{"rd.luks.uuid=639b8fdd-36ba-443e-be3e-e5b335935502", "root=UUID=7bbf9363-eb42-4476-8c1c-9f1f4d091385"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-639b8fdd-36ba-443e-be3e-e5b335935502:"))
	require.NoError(t, vm.ConsoleWrite("sdbc123sdflkh213\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2WithQuotesOverUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.img",
		kernelArgs: []string{"rd.luks.uuid=\"639b8fdd-36ba-443e-be3e-e5b335935502\"", "root=UUID=\"7bbf9363-eb42-4476-8c1c-9f1f4d091385\""},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-639b8fdd-36ba-443e-be3e-e5b335935502:"))
	require.NoError(t, vm.ConsoleWrite("sdbc123sdflkh213\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
