package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMdRaid1Path(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableMdraid: true,
		mdraidConf:   "assets/mdraid_raid1.img.array",
		disk:         "assets/mdraid_raid1.img",
		kernelArgs:   []string{"root=/dev/md/BoosterTestArray1"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestMdRaid1UUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableMdraid: true,
		mdraidConf:   "assets/mdraid_raid1.img.array",
		disk:         "assets/mdraid_raid1.img",
		kernelArgs:   []string{"root=UUID=98b1a905-3c72-42f0-957a-6c23b303b1fd"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestMdRaid5Path(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableMdraid: true,
		mdraidConf:   "assets/mdraid_raid5.img.array",
		disk:         "assets/mdraid_raid5.img",
		kernelArgs:   []string{"root=/dev/md/BoosterTestArray5"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestMdRaid5UUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableMdraid: true,
		mdraidConf:   "assets/mdraid_raid5.img.array",
		disk:         "assets/mdraid_raid5.img",
		kernelArgs:   []string{"root=UUID=e62c7dc0-5728-4571-b475-7745de2eef1e"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
