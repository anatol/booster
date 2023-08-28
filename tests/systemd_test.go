package tests

import (
	"os"
	"plugin"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSystemdFido2(t *testing.T) {
	yubikeys, err := detectYubikeys()
	require.NoError(t, err)
	if len(yubikeys) == 0 {
		t.Skip("no Yubikeys detected")
	}

	params := make([]string, 0)
	for _, y := range yubikeys {
		params = append(params, y.toQemuParams()...)
	}

	opts := Opts{
		disk:       "assets/systemd-fido2.img",
		kernelArgs: []string{"rd.luks.uuid=b12cbfef-da87-429f-ac96-7dda7232c189", "root=UUID=bb351f0d-07f2-4fe4-bc53-d6ae39fa1c23"},
		params:     params,
		extraFiles: "/usr/lib/booster/libfido2_plugin.so",
	}

	vm, err := buildVmInstance(t, opts)
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NotEmpty(t, opts.extraFiles)
	require.Contains(t, opts.extraFiles, "/usr/lib/booster/libfido2_plugin.so")

	path := "/usr/lib/booster/libfido2_plugin.so"
	p, err := plugin.Open(path)

	require.NoError(t, err)
	require.NotEmpty(t, p)

	sym, err := p.Lookup("GetFido2HMACSecret")

	require.NoError(t, err)
	require.NotEmpty(t, sym)

	hmacSecret, err := sym.(func(
		devName string,
		rpID string,
		clientDataHash []byte,
		credentialID []byte,
		pin string,
		hmacSalt []byte,
		userPresenceRequired bool,
		userVerificationRequired bool) ([]byte, error))("hidraw1", "io.systemd.cryptsetup", make([]byte, 32), make([]byte, 32), "", make([]byte, 32), true, false)

	require.Error(t, err)
	require.Empty(t, hmacSecret)
}

func TestSystemdTPM2(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-tpm2.img",
		kernelArgs: []string{"rd.luks.uuid=5cbc48ce-0e78-4c6b-ac90-a8a540514b90", "root=UUID=d8673e36-d4a3-4408-a87d-be0cb79f91a2"},
		params:     params,
		extraFiles: "fido2-assert",
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestSystemdTPM2WithPin(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-tpm2-withpin.img",
		kernelArgs: []string{"rd.luks.uuid=8bb97618-7ef4-4c93-b4f7-f2cb17cf7da1", "root=UUID=26dbbe17-9af9-4322-bb5f-c1d74a40e618"},
		params:     params,
		extraFiles: "fido2-assert",
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Please enter TPM pin:"))
	require.NoError(t, vm.ConsoleWrite("foo654\n"))

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestSystemdRecovery(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-recovery.img",
		kernelArgs: []string{"rd.luks.uuid=62020168-58b9-4095-a3d0-176403353d20", "root=UUID=b0cfeb48-c1e2-459d-a327-4d611804ac24"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// enter password manually as recovery file might not be ready at the time test initialized
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-62020168-58b9-4095-a3d0-176403353d20:"))

	password, err := os.ReadFile("assets/systemd.recovery.key")
	require.NoError(t, err)
	require.NoError(t, vm.ConsoleWrite(string(password)+"\n"))
}
