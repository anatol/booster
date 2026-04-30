package tests

import (
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSystemdFido2(t *testing.T) {
	// PIN is read from the environment to avoid hardcoding it in source.
	// Set BOOSTER_TEST_FIDO2_PIN to the PIN on your FIDO2 device before running.
	// Tip: use read -s to avoid shell history: read -s BOOSTER_TEST_FIDO2_PIN
	pin := os.Getenv("BOOSTER_TEST_FIDO2_PIN")
	if pin == "" {
		t.Skip("BOOSTER_TEST_FIDO2_PIN not set")
	}

	yubikeys, err := detectYubikeys()
	require.NoError(t, err)
	if len(yubikeys) == 0 {
		t.Skip("no Yubikeys detected")
	}

	// Create a fresh LUKS image enrolled against the connected FIDO2 device so
	// the test works for any device without pre-built assets.
	luksUUID, fsUUID, imgPath := createFido2LuksImage(t, pin)

	params := make([]string, 0)
	for _, y := range yubikeys {
		params = append(params, y.toQemuParams()...)
	}
	vm, err := buildVmInstance(t, Opts{
		disk:        imgPath,
		kernelArgs:  []string{"rd.luks.uuid=" + luksUUID, "root=UUID=" + fsUUID},
		params:      params,
		enableFido2: true,
	})
	require.NoError(t, err)
	defer vm.Shutdown()
	// there can be multiple Yubikeys, iterate over all "Enter FIDO2 PIN" requests
	re, err := regexp.Compile(`(Enter FIDO2 PIN for |Hello, booster!)`)
	require.NoError(t, err)
	for {
		matches, err := vm.ConsoleExpectRE(re)
		require.NoError(t, err)
		if matches[0] == "Hello, booster!" {
			break
		}
		require.NoError(t, vm.ConsoleWrite(pin+"\n"))
	}
}

func TestSystemdTPM2(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-tpm2.img",
		kernelArgs: []string{"rd.luks.uuid=5cbc48ce-0e78-4c6b-ac90-a8a540514b90", "root=UUID=d8673e36-d4a3-4408-a87d-be0cb79f91a2"},
		params:     params,
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
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Please enter TPM pin:"))
	require.NoError(t, vm.ConsoleWrite("foo654\n"))

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestSystemdTPM2NoPcrPin tests unlock of a LUKS2 volume whose TPM2+PIN token
// was enrolled without PCR binding (--tpm2-pcrs="").  The policy digest only
// covers PolicyPassword; a previous bug caused policyPCRSession to call
// PolicyPCR with an empty selection even when len(pcrs)==0, which mutated the
// digest and made the unseal fail regardless of PIN correctness.
func TestSystemdTPM2NoPcrPin(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-tpm2-nopcr-pin.img",
		kernelArgs: []string{"rd.luks.uuid=d9ef7bf3-b4f8-4271-9f3c-df63d457fcc6", "root=UUID=6abcf123-4182-452b-9c87-a769dc344e3b"},
		params:     params,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter TPM2 PIN for"))
	require.NoError(t, vm.ConsoleWrite("foo654\n"))

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestSystemdTPM2SRK tests unlock of a LUKS2 volume enrolled with systemd-cryptenroll
// v252+, which provisions a persistent SRK at handle 0x81000001 and records it as
// tpm2_srk in the token JSON. Booster must use that handle rather than deriving a
// transient primary, otherwise tpm2.Load returns an integrity check failure.
func TestSystemdTPM2SRK(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-tpm2-srk.img",
		kernelArgs: []string{"rd.luks.uuid=c09debc6-6a06-4317-94f5-0916bb9ea1c8", "root=UUID=5a6daa83-ea51-47dd-a38b-2b66d5cc8428"},
		params:     params,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestSystemdTPM2LegacyPin tests unlock of a LUKS2 volume whose systemd-tpm2
// token was enrolled with a v252–254 era systemd-cryptenroll: the token has
// tpm2_srk (persistent SRK) but no tpm2_salt, so PIN auth uses the pre-v255
// convention authValue = SHA256_trimmed(pin) rather than the PBKDF2 path.
// The image is generated with raw tpm2-tools to be independent of the installed
// systemd version.  The test is skipped when tpm2-tools are not available.
func TestSystemdTPM2LegacyPin(t *testing.T) {
	if _, err := exec.LookPath("tpm2_create"); err != nil {
		t.Skip("tpm2-tools not installed; skipping legacy-pin backward-compat test")
	}

	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-tpm2-legacy-pin.img",
		kernelArgs: []string{"rd.luks.uuid=1e8a6049-18a7-48df-a4f6-edc80650e19f", "root=UUID=b0d4b4c2-cef2-43b5-a063-e3379a49f79c"},
		params:     params,
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
