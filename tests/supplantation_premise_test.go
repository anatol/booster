package tests

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Decision-validation / characterization tests for the TPM2 filesystem-
// supplantation hardening work. These do not exercise booster
// itself; they pin the TPM-semantics premises the PCR15-latch design depends
// on, so the rationale is executable and a future TPM/tooling change that
// invalidates a premise trips a test instead of silently weakening the design.
//
// Pure swtpm + tpm2-tools — no qemu boot, no booster image. Skipped when the
// tools are unavailable (same pattern as TestSystemdTPM2LegacyPin).

const (
	swtpmTCPDataPort = "2321"
	swtpmTCPCtrlPort = "2322"
)

func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not installed; skipping TPM-premise characterization test", name)
	}
}

// startSwtpmTCP starts swtpm in TCP server mode so tpm2-tools can drive it via
// the swtpm TCTI. The integration harness' startSwtpm() uses a unixio control
// socket for QEMU; tpm2-tools needs the TCP data/ctrl ports instead. Returns
// the TPM2TOOLS_TCTI string; the swtpm process is killed on test cleanup.
func startSwtpmTCP(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--server", "type=tcp,port="+swtpmTCPDataPort,
		"--ctrl", "type=tcp,port="+swtpmTCPCtrlPort,
		"--tpmstate", "dir="+dir,
		"--flags", "not-need-init,startup-clear")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+swtpmTCPDataPort, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		require.False(t, time.Now().After(deadline), "swtpm TCP port did not open")
	}
	return "swtpm:host=127.0.0.1,port=" + swtpmTCPDataPort
}

func tpm2Run(t *testing.T, tcti string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "TPM2TOOLS_TCTI="+tcti)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// restartableSwtpm is a swtpm TCP instance over a fixed state directory that can
// be power-cycled: reboot() kills and restarts the process so the PCRs reset
// (Startup CLEAR) while persistent hierarchy seeds and persistent handles in the
// state dir survive — exactly the TPM behaviour across a real reboot. Used to
// contrast a genuine boot with an attacker boot against the same enrolled key.
type restartableSwtpm struct {
	t    *testing.T
	dir  string
	port int
	cmd  *exec.Cmd
	tcti string
}

func newRestartableSwtpm(t *testing.T, port int) *restartableSwtpm {
	s := &restartableSwtpm{t: t, dir: t.TempDir(), port: port}
	s.start()
	t.Cleanup(func() {
		if s.cmd != nil {
			_ = s.cmd.Process.Kill()
		}
	})
	return s
}

func (s *restartableSwtpm) start() {
	data := strconv.Itoa(s.port)
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--server", "type=tcp,port="+data,
		"--ctrl", "type=tcp,port="+strconv.Itoa(s.port+1),
		"--tpmstate", "dir="+s.dir,
		"--flags", "not-need-init,startup-clear")
	require.NoError(s.t, cmd.Start())
	s.cmd = cmd
	s.tcti = "swtpm:host=127.0.0.1,port=" + data

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+data, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		require.False(s.t, time.Now().After(deadline), "swtpm TCP port did not open")
	}
}

// reboot simulates a power cycle: kill (no graceful shutdown, so volatile state
// is dropped and PCRs reset) and restart on a fresh port (avoids TIME_WAIT).
func (s *restartableSwtpm) reboot() {
	_ = s.cmd.Process.Kill()
	_, _ = s.cmd.Process.Wait()
	s.port += 2
	s.start()
}

func tpm2Must(t *testing.T, tcti string, args ...string) string {
	t.Helper()
	out, err := tpm2Run(t, tcti, args...)
	require.NoError(t, err, "%v failed: %s", args, out)
	return out
}

const (
	pcr15Zero256 = "0x0000000000000000000000000000000000000000000000000000000000000000"
	pcr15Zero1   = "0x0000000000000000000000000000000000000000"
)

// TestSupplantationPCR15NonResettable validates the "the known all-zero value is
// safe" premise: an attacker who knows PCR15's uninitialized value (all zeros)
// still cannot make the register hold it again. PCRs 0-15 are non-resettable
// SRTM registers (TCG PTP); only a full TPM reset (reboot) returns them to zero.
// This is why sealing to an uninitialized PCR15 + extending it before pivot
// closes the re-unseal oracle within a boot.
func TestSupplantationPCR15NonResettable(t *testing.T) {
	requireTool(t, "swtpm")
	requireTool(t, "tpm2_pcrread")
	requireTool(t, "tpm2_pcrextend")
	requireTool(t, "tpm2_pcrreset")
	tcti := startSwtpmTCP(t)

	out, err := tpm2Run(t, tcti, "tpm2_pcrread", "sha256:15")
	require.NoError(t, err)
	require.Contains(t, out, pcr15Zero256, "PCR15 must start uninitialized (all zeros)")

	_, err = tpm2Run(t, tcti, "tpm2_pcrextend",
		"15:sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.NoError(t, err)

	out, err = tpm2Run(t, tcti, "tpm2_pcrread", "sha256:15")
	require.NoError(t, err)
	require.NotContains(t, out, pcr15Zero256, "PCR15 must change after extend")

	// The core assertion: PCR15 cannot be reset back to zero.
	out, err = tpm2Run(t, tcti, "tpm2_pcrreset", "15")
	require.Error(t, err, "PCR15 must NOT be resettable (would defeat the latch); got output: %s", out)

	out, err = tpm2Run(t, tcti, "tpm2_pcrread", "sha256:15")
	require.NoError(t, err)
	require.NotContains(t, out, pcr15Zero256, "PCR15 must remain extended after a refused reset")
}

// TestSupplantationPCRBankIsolation validates the "extend ALL active banks"
// premise: extending PCR15 in one bank leaves the other bank untouched, so
// a policy that can be satisfied via the un-extended bank is bypassable. Booster
// must extend PCR15 across every active bank, not just the token's recorded one.
func TestSupplantationPCRBankIsolation(t *testing.T) {
	requireTool(t, "swtpm")
	requireTool(t, "tpm2_pcrread")
	requireTool(t, "tpm2_pcrextend")
	tcti := startSwtpmTCP(t)

	out, err := tpm2Run(t, tcti, "tpm2_pcrread", "sha256:15+sha1:15")
	require.NoError(t, err)
	require.Contains(t, out, pcr15Zero256, "sha256:15 must start zero")
	require.Contains(t, out, pcr15Zero1, "sha1:15 must start zero")

	// Extend only the sha256 bank.
	_, err = tpm2Run(t, tcti, "tpm2_pcrextend",
		"15:sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	require.NoError(t, err)

	out, err = tpm2Run(t, tcti, "tpm2_pcrread", "sha256:15+sha1:15")
	require.NoError(t, err)
	require.NotContains(t, out, pcr15Zero256, "sha256:15 must be extended")
	require.Contains(t, out, pcr15Zero1,
		"sha1:15 must still be zero => extending one bank leaves others exploitable; booster must extend ALL active banks")
}

// TestSupplantationPCR15WithoutPCR11Leaks validates the central premise: PCR15
// contamination ALONE is not a defense. Co-binding to a PCR covering the
// kernel+initrd (PCR11, via the UKI) is load-bearing — PCR15 is only a
// single-use latch, not the thing that forces the real initrd to run.
//
// The test seals the same secret under two PCR policies captured at the same
// "real boot" state, then simulates a supplanted initrd by changing PCR11:
//
//	A) PCR15 only      -> still unseals (the changed PCR11 is invisible) = LEAK
//	B) PCR11 + PCR15   -> refuses (the changed PCR11 breaks the policy)  = SAFE
//
// The B branch is the internal control: if a misconfigured seal unsealed
// unconditionally, B would fail too, so a green test genuinely shows that PCR11
// — not PCR15 — is what catches the supplantation.
func TestSupplantationPCR15WithoutPCR11Leaks(t *testing.T) {
	requireTool(t, "swtpm")
	for _, tool := range []string{
		"tpm2_pcrextend", "tpm2_createprimary", "tpm2_createpolicy", "tpm2_create",
		"tpm2_load", "tpm2_startauthsession", "tpm2_policypcr", "tpm2_unseal", "tpm2_flushcontext",
	} {
		requireTool(t, tool)
	}
	tcti := startSwtpmTCP(t)
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }
	// swtpm has only a few transient object slots; each create/load reloads the
	// parent, so flush transients between steps to avoid TPM_RC_OBJECT_MEMORY.
	flushT := func() { _, _ = tpm2Run(t, tcti, "tpm2_flushcontext", "-t") }

	// "Real boot": stamp a representative kernel+initrd measurement into PCR11.
	tpm2Must(t, tcti, "tpm2_pcrextend", "11:sha256="+strings.Repeat("11", 32))

	// One primary shared by both sealed objects.
	tpm2Must(t, tcti, "tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", p("primary.ctx"))
	flushT()

	// Two policies captured at the same real state (PCR15==0, PCR11==real):
	//   A) PCR15 only    -- the reporter's "PCR15 contamination" approach
	//   B) PCR11 + PCR15 -- our co-binding
	tpm2Must(t, tcti, "tpm2_createpolicy", "--policy-pcr", "-l", "sha256:15", "-L", p("polA.dat"))
	tpm2Must(t, tcti, "tpm2_createpolicy", "--policy-pcr", "-l", "sha256:11,15", "-L", p("polB.dat"))

	const secret = "super-secret-volume-key"
	require.NoError(t, os.WriteFile(p("secret.txt"), []byte(secret), 0o600))

	seal := func(pol, pub, priv, ctx string) {
		tpm2Must(t, tcti, "tpm2_create", "-C", p("primary.ctx"), "-L", p(pol),
			"-i", p("secret.txt"), "-u", p(pub), "-r", p(priv))
		flushT()
		tpm2Must(t, tcti, "tpm2_load", "-C", p("primary.ctx"), "-u", p(pub), "-r", p(priv), "-c", p(ctx))
		flushT()
	}
	seal("polA.dat", "a.pub", "a.priv", "a.ctx")
	seal("polB.dat", "b.pub", "b.priv", "b.ctx")

	// Supplantation: a different initrd runs -> PCR11 changes. PCR15 stays 0 (the
	// attacker simply never runs booster's extend, or has just rebooted).
	tpm2Must(t, tcti, "tpm2_pcrextend", "11:sha256="+strings.Repeat("ee", 32))

	unseal := func(ctx, pcrs string) (string, error) {
		sess := p("sess.ctx")
		defer func() { _, _ = tpm2Run(t, tcti, "tpm2_flushcontext", sess); flushT() }()
		if out, err := tpm2Run(t, tcti, "tpm2_startauthsession", "--policy-session", "-S", sess); err != nil {
			return out, err
		}
		if out, err := tpm2Run(t, tcti, "tpm2_policypcr", "-S", sess, "-l", pcrs); err != nil {
			return out, err
		}
		return tpm2Run(t, tcti, "tpm2_unseal", "-c", p(ctx), "-p", "session:"+sess)
	}

	// A) PCR15-only: the changed PCR11 is invisible -> the key still falls out.
	outA, errA := unseal("a.ctx", "sha256:15")
	require.NoError(t, errA,
		"PCR15-only seal should STILL unseal after PCR11 changed (the bypass); output: %s", outA)
	require.Contains(t, outA, secret,
		"PCR15-only policy leaked the volume key despite a supplanted initrd => PCR15 alone is not a defense")

	// B) PCR11+PCR15: the changed PCR11 breaks the policy -> the key is protected.
	outB, errB := unseal("b.ctx", "sha256:11,15")
	require.Error(t, errB,
		"PCR11-co-bound seal MUST refuse after PCR11 changed; it unsealed instead: %s", outB)
	require.NotContains(t, outB, secret,
		"PCR11 co-binding must not release the key for a supplanted initrd")
}

// TestSupplantationCrossBootDenied is the positive counterpart to
// TestSupplantationPCR15WithoutPCR11Leaks: with the key co-bound to
// PCR 7+11+15, an attacker who power-cycles the machine and boots a DIFFERENT
// image is denied the key — even though they trivially reproduce PCR7 (same
// firmware / Secure Boot state) and a fresh, uninitialised PCR15==0. Only PCR11,
// the UKI/initrd measurement they cannot forge without the genuine image,
// withholds it. This is exactly the supplantation attack run end to end against
// the defended enrollment.
//
// It uses a real swtpm power-cycle (PCRs reset, persistent SRK survives), not a
// full booster+UKI+OVMF in-guest boot — that broader integration harness does
// not exist yet — but the cryptographic claim (PCR11 blocks, PCR7+15 do not) is
// the same one booster's enrollment guidance and Phase-1b warning rely on.
func TestSupplantationCrossBootDenied(t *testing.T) {
	requireTool(t, "swtpm")
	for _, tool := range []string{
		"tpm2_pcrextend", "tpm2_createprimary", "tpm2_evictcontrol", "tpm2_createpolicy",
		"tpm2_create", "tpm2_load", "tpm2_startauthsession", "tpm2_policypcr",
		"tpm2_unseal", "tpm2_flushcontext",
	} {
		requireTool(t, tool)
	}
	s := newRestartableSwtpm(t, 2323)
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	flushT := func() { _, _ = tpm2Run(t, s.tcti, "tpm2_flushcontext", "-t") }

	const (
		parent = "0x81000001"
		secret = "super-secret-volume-key"
	)
	var (
		fw       = strings.Repeat("77", 32) // PCR7:  firmware / Secure Boot state (reproducible)
		realInit = strings.Repeat("be", 32) // PCR11: the genuine UKI/initrd
		evilInit = strings.Repeat("ad", 32) // PCR11: the attacker's image
	)
	require.NoError(t, os.WriteFile(p("secret.txt"), []byte(secret), 0o600))

	// measure replays a boot's measurements into PCR7 and PCR11. PCR15 is left at
	// its fresh, uninitialised 0 — the "system-identity" value the token seals to.
	measure := func(pcr7, pcr11 string) {
		tpm2Must(t, s.tcti, "tpm2_pcrextend", "7:sha256="+pcr7)
		tpm2Must(t, s.tcti, "tpm2_pcrextend", "11:sha256="+pcr11)
	}
	unseal := func() (string, error) {
		sess := p("sess.ctx")
		defer func() { _, _ = tpm2Run(t, s.tcti, "tpm2_flushcontext", sess); flushT() }()
		if out, err := tpm2Run(t, s.tcti, "tpm2_load", "-C", parent,
			"-u", p("seal.pub"), "-r", p("seal.priv"), "-c", p("seal.ctx")); err != nil {
			return out, err
		}
		if out, err := tpm2Run(t, s.tcti, "tpm2_startauthsession", "--policy-session", "-S", sess); err != nil {
			return out, err
		}
		if out, err := tpm2Run(t, s.tcti, "tpm2_policypcr", "-S", sess, "-l", "sha256:7,11,15"); err != nil {
			return out, err
		}
		return tpm2Run(t, s.tcti, "tpm2_unseal", "-c", p("seal.ctx"), "-p", "session:"+sess)
	}

	// Enrollment during the genuine boot's measured state. The primary is made
	// persistent so it survives the simulated reboots, like a real SRK.
	tpm2Must(t, s.tcti, "tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "ecc", "-c", p("primary.ctx"))
	tpm2Must(t, s.tcti, "tpm2_evictcontrol", "-C", "o", "-c", p("primary.ctx"), parent)
	flushT()
	measure(fw, realInit)
	tpm2Must(t, s.tcti, "tpm2_createpolicy", "--policy-pcr", "-l", "sha256:7,11,15", "-L", p("pol.dat"))
	tpm2Must(t, s.tcti, "tpm2_create", "-C", parent, "-L", p("pol.dat"),
		"-i", p("secret.txt"), "-u", p("seal.pub"), "-r", p("seal.priv"))
	flushT()

	// Sanity: the genuine boot unseals.
	out, err := unseal()
	require.NoError(t, err, "genuine boot must unseal; output: %s", out)
	require.Contains(t, out, secret)

	// Attacker boot: power-cycle, reproduce PCR7 and a fresh PCR15==0, but run a
	// different initrd (PCR11 differs). The key must be withheld.
	s.reboot()
	flushT()
	measure(fw, evilInit)
	out, err = unseal()
	require.Error(t, err, "attacker boot (different PCR11) MUST be denied; it unsealed: %s", out)
	require.NotContains(t, out, secret,
		"PCR11 co-binding must withhold the key from a supplanted initrd, despite a reproduced PCR7 and a fresh PCR15==0")

	// Control: a genuine re-boot (same PCR7+PCR11) still unseals, proving the
	// denial above was the PCR11 difference and not a broken reload after reboot.
	s.reboot()
	flushT()
	measure(fw, realInit)
	out, err = unseal()
	require.NoError(t, err, "genuine re-boot must still unseal; output: %s", out)
	require.Contains(t, out, secret)
}
