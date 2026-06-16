package tests

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSupplantationPCR15Latch is the end-to-end proof for the TPM2 filesystem-
// supplantation hardening. A volume whose systemd-tpm2 token binds PCR15
// auto-unseals at the uninitialized PCR15 (==0); booster must then extend PCR15
// with the volume-key measurement *before* pivot, so the key can no longer be
// re-unsealed for the rest of the boot — closing the TPM re-unseal oracle.
//
// Observable: booster logs "PCR15 re-unseal latch engaged" once it extends the
// PCR. The init-package unit tests separately prove the extend value is the
// correct systemd-compatible HMAC across all active banks, and that PCR15 cannot
// be reset without a reboot — so the log line firing on a real boot, combined
// with those, demonstrates the oracle is closed. Pre-fix booster has zero
// PCR-extend calls, so the line never appears and this test fails.
//
// The disk asset auto-generates on first run via checkAsset (systemd_tpm2.sh,
// which uses sudo for losetup/cryptsetup/mkfs); no qemu-claude bootstrap needed.
// Its token binds PCR 10+13+15 — including PCR15, so the latch engages.
func TestSupplantationPCR15Latch(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-tpm2-pcr15.img",
		kernelArgs: []string{"rd.luks.uuid=7a9f3c21-5e84-4d16-b2c7-1f0a9e6d4b33", "root=UUID=8b0a4d32-6f95-4e27-93d8-2a1baf7e5c44", "booster.log=debug"},
		params:     params,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// The token unseals while PCR15 is still 0, then booster extends PCR15.
	require.NoError(t, vm.ConsoleExpect("PCR15 re-unseal latch engaged"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
