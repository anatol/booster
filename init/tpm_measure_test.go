package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

// startSwtpmTCPForTest starts swtpm in TCP server mode so booster's
// enableSwEmulator path (which dials :2321) talks to it. Skips when swtpm is
// unavailable; the process is killed on test cleanup.
func startSwtpmTCPForTest(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed")
	}
	dir := t.TempDir()
	cmd := exec.Command("swtpm", "socket", "--tpm2",
		"--server", "type=tcp,port=2321",
		"--ctrl", "type=tcp,port=2322",
		"--tpmstate", "dir="+dir,
		"--flags", "not-need-init,startup-clear")
	require.NoError(t, cmd.Start())
	// Kill AND reap so the fixed :2321 port is released before the next
	// swtpm-binding test starts (booster's emulator path hardcodes :2321, so
	// these tests can't use random ports and must serialize cleanly).
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", "127.0.0.1:2321", 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		require.False(t, time.Now().After(deadline), "swtpm TCP port never opened")
	}
}

func readPCR15(t *testing.T, bank tpm2.Algorithm) []byte {
	t.Helper()
	return readPCRIndex(t, bank, 15)
}

func readPCRIndex(t *testing.T, bank tpm2.Algorithm, idx int) []byte {
	t.Helper()
	dev, err := openTPM()
	require.NoError(t, err)
	defer dev.Close()
	pcrs, err := tpm2.ReadPCRs(dev, tpm2.PCRSelection{Hash: bank, PCRs: []int{idx}})
	require.NoError(t, err)
	return pcrs[idx]
}

// TestMeasurePhaseToPCR11 pins the boot-phase barrier byte format: booster
// extends PCR11 with a phase word exactly as systemd-pcrextend does — the raw
// ASCII word (no NUL terminator, no HMAC, unlike the PCR15 volume-key
// measurement), hashed per active bank, then PCR-extended. This is what makes a
// PCR11-bound (signed) key match systemd's "enter-initrd" phase value at unlock.
// Expected values are pinned to systemd's formula (src/shared/tpm2-util.c
// tpm2_pcr_extend_bytes with secret=NULL):
//
//	extend value = bankHash(word)              // e.g. SHA256("enter-initrd")
//	PCR11_new    = bankHash(PCR11_old || extend value)
func TestMeasurePhaseToPCR11(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	require.Equal(t, make([]byte, 32), readPCRIndex(t, tpm2.AlgSHA256, pcrKernelBoot), "sha256:11 must start zero")
	require.Equal(t, make([]byte, 20), readPCRIndex(t, tpm2.AlgSHA1, pcrKernelBoot), "sha1:11 must start zero")

	require.NoError(t, measurePhaseToPCR11(phaseEnterInitrd))

	// sha256 bank: PCR11 = SHA256(zeros32 || SHA256("enter-initrd"))
	d256 := sha256.Sum256([]byte(phaseEnterInitrd))
	e256 := sha256.New()
	e256.Write(make([]byte, 32))
	e256.Write(d256[:])
	require.Equal(t, e256.Sum(nil), readPCRIndex(t, tpm2.AlgSHA256, pcrKernelBoot),
		"sha256 bank must extend PCR11 with the plain SHA256(word), no NUL, no HMAC")

	// sha1 bank: PCR11 = SHA1(zeros20 || SHA1("enter-initrd")) — all active banks.
	d1 := sha1.Sum([]byte(phaseEnterInitrd))
	e1 := sha1.New()
	e1.Write(make([]byte, 20))
	e1.Write(d1[:])
	require.Equal(t, e1.Sum(nil), readPCRIndex(t, tpm2.AlgSHA1, pcrKernelBoot),
		"sha1 bank must be extended too (a policy satisfiable via an un-extended bank is bypassable)")
}

// TestMeasurePhaseToPCR11FailsClosedWhenTPMUnavailable pins the fail-safe
// contract: if the phase barrier cannot be applied, the extend must error so the
// caller aborts rather than unsealing against an un-barriered PCR11. Here the TPM
// is unreachable (emulator dial to :2321 with no swtpm running).
func TestMeasurePhaseToPCR11FailsClosedWhenTPMUnavailable(t *testing.T) {
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	require.Error(t, measurePhaseToPCR11(phaseEnterInitrd),
		"phase barrier must fail closed when it cannot be applied")
}

func resetEnterInitrdBarrier() {
	enterInitrdOnce = sync.Once{}
	enterInitrdErr = nil
	enterInitrdApplied = false
}

// TestEnsureEnterInitrdBarrierOnce pins the idempotency the unlock path relies
// on: the barrier extends "enter-initrd" into PCR11 exactly ONCE per boot, no
// matter how many PCR11-bound volumes or PIN retries call it. PCR extension is
// monotonic, so a second extend would push PCR11 to the wrong value and break
// every signed unseal. It must also record that it ran, so switch_root can apply
// the matching "leave-initrd" forward-lock.
func TestEnsureEnterInitrdBarrierOnce(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })
	resetEnterInitrdBarrier()
	t.Cleanup(resetEnterInitrdBarrier)

	require.NoError(t, ensureEnterInitrdBarrier())
	require.True(t, enterInitrdApplied, "barrier must record that it ran (for the leave-initrd forward-lock)")

	d := sha256.Sum256([]byte(phaseEnterInitrd))
	e := sha256.New()
	e.Write(make([]byte, 32))
	e.Write(d[:])
	want := e.Sum(nil)
	require.Equal(t, want, readPCRIndex(t, tpm2.AlgSHA256, pcrKernelBoot), "first call extends enter-initrd")

	// Repeated calls must NOT extend again — PCR11 stays put.
	require.NoError(t, ensureEnterInitrdBarrier())
	require.NoError(t, ensureEnterInitrdBarrier())
	require.Equal(t, want, readPCRIndex(t, tpm2.AlgSHA256, pcrKernelBoot), "barrier must extend exactly once per boot")
}

// rawKeyHMACer is a test volumeKeyHMACer backed by a raw key, mirroring what
// luks.Volume.HMAC does in production (HMAC keyed by the master key).
type rawKeyHMACer []byte

func (k rawKeyHMACer) HMAC(h crypto.Hash, message []byte) ([]byte, error) {
	m := hmac.New(h.New, k)
	m.Write(message)
	return m.Sum(nil), nil
}

// TestMeasureVolumeKeyToPCR15ExtendsSHA256 checks the PCR15 latch: after booster
// unseals a volume it extends PCR15 with the systemd-compatible volume-key HMAC,
// so the key cannot be re-unsealed for the rest of the boot (closing the
// re-unseal oracle). The expected value is pinned to systemd's exact formula so
// a wrong-formula implementation fails:
//
//	extend value = HMAC-SHA256(volumeKey, "cryptsetup:" + name + ":" + uuid)
//	PCR15_new    = SHA256( PCR15_old(32 zero bytes) || extend value )
func TestMeasureVolumeKeyToPCR15ExtendsSHA256(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	const name = "cryptroot"
	const uuid = "5cbc48ce-0e78-4c6b-ac90-a8a540514b90"
	volumeKey := []byte("0123456789abcdef0123456789abcdef")

	before := readPCR15(t, tpm2.AlgSHA256)
	require.Equal(t, make([]byte, 32), before, "PCR15 must start uninitialized (all zeros)")

	require.NoError(t, measureVolumeKeyToPCR15(rawKeyHMACer(volumeKey), name, uuid))

	mac := hmac.New(sha256.New, volumeKey)
	mac.Write([]byte("cryptsetup:" + name + ":" + uuid))
	digest := mac.Sum(nil)
	h := sha256.New()
	h.Write(make([]byte, 32)) // PCR15 started at all-zeros
	h.Write(digest)
	want := h.Sum(nil)

	after := readPCR15(t, tpm2.AlgSHA256)
	require.Equal(t, want, after,
		"PCR15 must equal the systemd-compatible HMAC(volume_key, \"cryptsetup:\"+name+\":\"+uuid) extend")
}

// TestHashForPCRBankUnsupported pins the fail-safe primitive: a PCR bank
// booster cannot compute must report unsupported, so measureVolumeKeyToPCR15
// aborts rather than silently leaving that bank's PCR15 un-extended (which would
// leave a satisfiable-via-that-bank policy bypassable).
func TestHashForPCRBankUnsupported(t *testing.T) {
	for _, alg := range []tpm2.Algorithm{tpm2.AlgSHA1, tpm2.AlgSHA256, tpm2.AlgSHA384, tpm2.AlgSHA512} {
		_, ok := cryptoHashForPCRBank(alg)
		require.True(t, ok, "bank %v must be supported", alg)
	}
	_, ok := cryptoHashForPCRBank(tpm2.AlgNull)
	require.False(t, ok, "unknown bank must report unsupported (fail closed)")
}

// TestMeasureVolumeKeyToPCR15FailsClosedWhenTPMUnavailable pins the fail-safe
// contract (systemd #36705): if the PCR15 latch can't be applied, the measure
// must return an error so the caller aborts the unlock rather than booting with
// the re-unseal oracle left open. Here the TPM is unreachable (emulator dial to
// :2321 with no swtpm running), standing in for any extend failure.
func TestMeasureVolumeKeyToPCR15FailsClosedWhenTPMUnavailable(t *testing.T) {
	enableSwEmulator = true // openTPM dials :2321; no swtpm is started
	t.Cleanup(func() { enableSwEmulator = false })

	err := measureVolumeKeyToPCR15(rawKeyHMACer([]byte("k")), "cryptroot", "uuid")
	require.Error(t, err, "measure must fail closed when the latch cannot be applied")
}

// TestMeasureVolumeKeyToPCR15ExtendsAllActiveBanks verifies all-banks coverage: a
// policy satisfiable via an un-extended bank is bypassable, so booster extends
// PCR15 in EVERY active bank, each with that bank's own HMAC algorithm (systemd
// does HMAC-SHA256 for the sha256 bank, HMAC-SHA1 for the sha1 bank, etc.).
// swtpm activates both sha1 and sha256.
func TestMeasureVolumeKeyToPCR15ExtendsAllActiveBanks(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	const name = "cryptroot"
	const uuid = "5cbc48ce-0e78-4c6b-ac90-a8a540514b90"
	volumeKey := []byte("0123456789abcdef0123456789abcdef")
	data := []byte("cryptsetup:" + name + ":" + uuid)

	require.Equal(t, make([]byte, 32), readPCR15(t, tpm2.AlgSHA256), "sha256:15 must start zero")
	require.Equal(t, make([]byte, 20), readPCR15(t, tpm2.AlgSHA1), "sha1:15 must start zero")

	require.NoError(t, measureVolumeKeyToPCR15(rawKeyHMACer(volumeKey), name, uuid))

	// sha256 bank: PCR15 = SHA256(zeros32 || HMAC-SHA256(key, data))
	m256 := hmac.New(sha256.New, volumeKey)
	m256.Write(data)
	e256 := sha256.New()
	e256.Write(make([]byte, 32))
	e256.Write(m256.Sum(nil))
	require.Equal(t, e256.Sum(nil), readPCR15(t, tpm2.AlgSHA256), "sha256 bank must be extended with HMAC-SHA256")

	// sha1 bank: PCR15 = SHA1(zeros20 || HMAC-SHA1(key, data))
	m1 := hmac.New(sha1.New, volumeKey)
	m1.Write(data)
	e1 := sha1.New()
	e1.Write(make([]byte, 20))
	e1.Write(m1.Sum(nil))
	require.Equal(t, e1.Sum(nil), readPCR15(t, tpm2.AlgSHA1), "sha1 bank must be extended with HMAC-SHA1 (all active banks)")
}

// TestXescapeColon pins booster's reimplementation of systemd's
// xescape(name, ":") used to build the volume-key measurement message, so the
// HMAC stays byte-compatible for volume names containing ':', '\', control or
// high bytes. systemd escapes c<0x20 || c>=0x7f || c=='\\' || c==':' as \xNN
// (lowercase), copying everything else verbatim (src/basic/escape.c xescape_full).
func TestXescapeColon(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cryptroot", "cryptroot"}, // common case: unchanged
		{"my:vol", `my\x3avol`},    // colon (the bad char) escaped
		{"a\\b", `a\x5cb`},         // backslash escaped
		{"a b", "a b"},             // space (0x20) kept
		{"a\tb", `a\x09b`},         // tab (control) escaped
		{"\x7f", `\x7f`},           // DEL escaped
		{"é", `\xc3\xa9`},          // high bytes (UTF-8) escaped
	}
	for _, c := range cases {
		require.Equal(t, c.want, xescapeColon(c.in), "xescapeColon(%q)", c.in)
	}
}
