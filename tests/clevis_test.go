package tests

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLUKS2ClevisYubikey(t *testing.T) {
	yubikeys, err := detectYubikeys()
	require.NoError(t, err)
	if len(yubikeys) == 0 {
		t.Skip("no Yubikeys detected")
	}

	params := make([]string, 0)
	for _, y := range yubikeys {
		params = append(params, y.toQemuParams()...)
	}

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.clevis.yubikey.img",
		kernelArgs: []string{"rd.luks.uuid=f2473f71-9a61-4b16-ae54-8f942b2daf52", "root=UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a"},
		extraFiles: "ykchalresp",
		params:     params,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS1ClevisTang(t *testing.T) {
	tangd, params, err := startTangd()
	require.NoError(t, err)
	defer tangd.Stop()

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/luks1.clevis.tang.img",
		enableNetwork: true,
		params:        params,
		kernelArgs:    []string{"rd.luks.uuid=4cdaa447-ef43-42a6-bfef-89ebb0c61b05", "root=UUID=c23aacf4-9e7e-4206-ba6c-af017934e6fa"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2ClevisTang(t *testing.T) {
	tangd, params, err := startTangd()
	require.NoError(t, err)
	defer tangd.Stop()

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/luks2.clevis.tang.img",
		enableNetwork: true,
		params:        params,
		kernelArgs:    []string{"rd.luks.uuid=f2473f71-9a68-4b16-ae54-8f942b2daf50", "root=UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2ClevisTangDHCP(t *testing.T) {
	tangd, params, err := startTangd()
	require.NoError(t, err)
	defer tangd.Stop()

	vm, err := buildVmInstance(t, Opts{
		disk:            "assets/luks2.clevis.tang.img",
		params:          params,
		enableNetwork:   true,
		useDhcp:         true,
		activeNetIfaces: "52-54-00-12-34-53,52:54:00:12:34:56,52:54:00:12:34:57", // 52:54:00:12:34:56 is QEMU's NIC address
		kernelArgs:      []string{"rd.luks.uuid=f2473f71-9a68-4b16-ae54-8f942b2daf50", "root=UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS1ClevisTpm2(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks1.clevis.tpm2.img",
		params:     params,
		kernelArgs: []string{"rd.luks.uuid=28c2e412-ab72-4416-b224-8abd116d6f2f", "root=UUID=2996cec0-16fd-4f1d-8bf3-6606afa77043"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2ClevisTpm2(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.clevis.tpm2.img",
		params:     params,
		kernelArgs: []string{"rd.luks.uuid=3756ba2c-1505-4283-8f0b-b1d1bd7b844f", "root=UUID=c3cc0321-fba8-42c3-ad73-d13f8826d8d7"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestInactiveNetwork(t *testing.T) {
	tangd, params, err := startTangd()
	require.NoError(t, err)
	defer tangd.Stop()

	vm, err := buildVmInstance(t, Opts{
		disk:            "assets/luks2.clevis.tang.img",
		params:          params,
		enableNetwork:   true,
		useDhcp:         true,
		activeNetIfaces: "52:54:00:12:34:57", // 52:54:00:12:34:56 is QEMU's NIC address
		kernelArgs:      []string{"rd.luks.uuid=f2473f71-9a68-4b16-ae54-8f942b2daf50", "root=UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a"},
		mountTimeout:    10,
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("Timeout waiting for root filesystem"))
}

func TestRemoteUnlock(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/luks2.clevis.remote.img",
		enableNetwork: true,
		params:        []string{"-nic", "user,id=n1,hostfwd=tcp::34551-:34551"},
		kernelArgs:    []string{"rd.luks.uuid=f2473f71-9a61-4b16-ae54-8f942b2daf22", "root=UUID=7acb3a9e-9b51-4aa2-9965-e41ae8467d8a"},
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("link becomes ready")) // wait for the network
	time.Sleep(time.Second)

	// unlock remotely
	cmd := exec.Command("tangctl", "unlock", "localhost:34551", "assets/remote/key.priv")
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	require.NoError(t, cmd.Run())

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
