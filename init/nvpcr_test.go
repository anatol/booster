package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

// These tests replace package globals (definition and config dirs, the auth
// dir, the emulator switch), so none of them runs in parallel.

const (
	testNvIndexHardware = 0x01d10200
	testNvIndexLogin    = 0x01d10203
)

// nvpcrRig is a swtpm with booster's NvPCR dirs pointed at temp dirs. It keeps
// one TPM connection open; swtpm serves one client at a time, so a test drops it
// before calling code that opens its own.
type nvpcrRig struct {
	t       *testing.T
	dev     io.ReadWriteCloser
	tpm     transport.TPM
	defDir  string
	confDir string
	authDir string
}

func newNvPCRRig(t *testing.T) *nvpcrRig {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	r := &nvpcrRig{t: t, defDir: t.TempDir(), confDir: t.TempDir(), authDir: t.TempDir()}
	oldDef, oldKey, oldSig, oldAuth, oldExh := nvpcrDefDir, pcrPublicKeyPaths, pcrSignatureSearchPaths, nvpcrAuthDir, nvpcrExhaustedDir
	nvpcrDefDir, nvpcrAuthDir, nvpcrExhaustedDir = r.defDir, r.authDir, r.authDir
	pcrPublicKeyPaths = []string{filepath.Join(r.confDir, "tpm2-pcr-public-key.pem")}
	pcrSignatureSearchPaths = []string{filepath.Join(r.confDir, "tpm2-pcr-signature.json")}
	t.Cleanup(func() {
		nvpcrDefDir, pcrPublicKeyPaths, pcrSignatureSearchPaths, nvpcrAuthDir, nvpcrExhaustedDir = oldDef, oldKey, oldSig, oldAuth, oldExh
		enableSwEmulator = false
	})
	r.open()
	t.Cleanup(r.close)
	return r
}

func (r *nvpcrRig) open() {
	dev, err := openTPM()
	require.NoError(r.t, err)
	r.dev, r.tpm = dev, transport.FromReadWriter(dev)
}

func (r *nvpcrRig) close() {
	if r.dev != nil {
		_ = r.dev.Close()
		r.dev = nil
	}
}

func (r *nvpcrRig) def(name string, index uint32, extra string) nvpcrDef {
	js := fmt.Sprintf(`{"name":"%s","algorithm":"sha256","nvIndex":%d%s}`, name, index, extra)
	require.NoError(r.t, os.WriteFile(filepath.Join(r.defDir, name+".nvpcr"), []byte(js), 0o644))
	defs := loadNvPCRDefs(nvpcrDefDir)
	for _, d := range defs {
		if d.Name == name {
			return d
		}
	}
	require.FailNow(r.t, "definition not loaded", name)
	return nvpcrDef{}
}

// signInitrd writes a PCR public key and a signature JSON whose "initrd" entry
// covers the current PCR 11, as ukify SignInitrdPCRs=yes would.
func (r *nvpcrRig) signInitrd() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(r.t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(r.t, err)
	require.NoError(r.t, os.WriteFile(filepath.Join(r.confDir, "tpm2-pcr-public-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644))

	approved, err := pcr11PolicyDigest(r.tpm)
	require.NoError(r.t, err)
	h := sha256.Sum256(append(append([]byte{}, approved...), policyRefDigest("initrd")...))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	require.NoError(r.t, err)
	js := fmt.Sprintf(`{"sha256":[{"pcrs":[11],"pkfp":"%s","pol":"%s","ref":"initrd","sig":"%s"}]}`,
		rsaPublicKeyFingerprint(&key.PublicKey), hex.EncodeToString(approved), base64.StdEncoding.EncodeToString(sig))
	require.NoError(r.t, os.WriteFile(filepath.Join(r.confDir, "tpm2-pcr-signature.json"), []byte(js), 0o644))
	return key
}

func (r *nvpcrRig) authDigest(name string) []byte {
	data, err := os.ReadFile(filepath.Join(r.authDir, name+".auth"))
	require.NoError(r.t, err)
	d, err := hex.DecodeString(strings.TrimSpace(string(data)))
	require.NoError(r.t, err)
	return d
}

func (r *nvpcrRig) nvPublic(index uint32) *tpm2.TPMSNVPublic {
	rp, err := (&tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}).Execute(r.tpm)
	require.NoError(r.t, err)
	pub, err := rp.NVPublic.Contents()
	require.NoError(r.t, err)
	return pub
}

func (r *nvpcrRig) nvRead(index uint32) []byte {
	rp, err := (&tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}).Execute(r.tpm)
	require.NoError(r.t, err)
	rd, err := (&tpm2.NVRead{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: rp.NVName},
		Size:       32,
	}).Execute(r.tpm)
	require.NoError(r.t, err)
	return rd.Data.Buffer
}

// hostExtend is what systemd-pcrextend does on the host for every later event:
// the PolicyNvWritten branch, with the init branch taken from the .auth file.
func (r *nvpcrRig) hostExtend(index uint32, authDigest, data []byte) error {
	sess, cleanup, err := tpm2.PolicySession(r.tpm, tpm2.TPMAlgSHA256, 16)
	require.NoError(r.t, err)
	defer func() { _ = cleanup() }()
	if _, err := (&tpm2.PolicyNVWritten{PolicySession: sess.Handle(), WrittenSet: true}).Execute(r.tpm); err != nil {
		return err
	}
	if _, err := (&tpm2.PolicyOr{PolicySession: sess.Handle(), PHashList: nvpcrBranches(authDigest)}).Execute(r.tpm); err != nil {
		return err
	}
	return nvExtend(r.tpm, tpm2.TPMHandle(index), sess.Handle(), data)
}

func (r *nvpcrRig) pcr(idx int) []byte { return readSHA256PCRFrom(r.t, r.dev, idx) }

// extendChain is the sha256 PCR value after extending a zero PCR with each word.
func extendChain(start []byte, words ...string) []byte {
	v := start
	for _, w := range words {
		d := sha256.Sum256([]byte(w))
		h := sha256.Sum256(append(append([]byte{}, v...), d[:]...))
		v = h[:]
	}
	return v
}

func initWord(r *nvpcrRig, name string, index uint32) string {
	rp, err := (&tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}).Execute(r.tpm)
	require.NoError(r.t, err)
	return fmt.Sprintf("nvpcr-init:%s:0x%x:%s", name, index, hex.EncodeToString(rp.NVName.Buffer))
}

// The definitions follow systemd's rules: name must match the file, only sha256
// is supported, priority defaults to 1000 and orders allocation, orderly
// defaults to true. Precedence between dirs is the generator's job.
func TestLoadNvPCRDefs(t *testing.T) {
	dir := t.TempDir()
	write := func(file, js string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, file), []byte(js), 0o644))
	}
	write("hardware.nvpcr", `{"name":"hardware","nvIndex":1,"priority":500,"orderly":false}`)
	write("login.nvpcr", `{"name":"login","nvIndex":9,"priority":800}`)
	write("cryptsetup.nvpcr", `{"name":"cryptsetup","nvIndex":3}`)
	write("aaa.nvpcr", `{"name":"aaa","nvIndex":4}`)
	write("wrong.nvpcr", `{"name":"other","nvIndex":5}`)
	write("sha1.nvpcr", `{"name":"sha1","algorithm":"sha1","nvIndex":6}`)
	write("noindex.nvpcr", `{"name":"noindex"}`)
	write("README", `not a definition`)

	defs := loadNvPCRDefs(dir)
	var got []string
	for _, d := range defs {
		got = append(got, fmt.Sprintf("%s:%d:%d:%v", d.Name, d.NVIndex, d.Priority, d.orderly()))
	}
	require.Equal(t, []string{
		"hardware:1:500:false",
		"login:9:800:true",
		"aaa:4:1000:true",
		"cryptsetup:3:1000:true",
	}, got)
}

// systemd-tpm2-setup leaves this flag in /run/systemd, which does not exist in
// booster's initrd until something creates it.
func TestFlagNVSpaceExhausted(t *testing.T) {
	old := nvpcrExhaustedDir
	nvpcrExhaustedDir = filepath.Join(t.TempDir(), "run", "systemd")
	t.Cleanup(func() { nvpcrExhaustedDir = old })

	require.NoError(t, flagNVSpaceExhausted(true))
	require.NoError(t, flagNVSpaceExhausted(false))
	require.FileExists(t, filepath.Join(nvpcrExhaustedDir, "tpm2-nv-space-exhausted-orderly"))
	require.FileExists(t, filepath.Join(nvpcrExhaustedDir, "tpm2-nv-space-exhausted-non-orderly"))
}

func TestMeasuredOSCommandLine(t *testing.T) {
	t.Cleanup(func() { cmdlineMeasuredOS = nil })
	yes, no := true, false
	cmdlineMeasuredOS = &yes
	require.True(t, measuredOS())
	cmdlineMeasuredOS = &no
	require.False(t, measuredOS())

	for _, s := range []string{"1", "yes", "y", "true", "on", "TRUE"} {
		b, ok := parseBoolean(s)
		require.True(t, ok, s)
		require.True(t, b, s)
	}
	for _, s := range []string{"0", "no", "n", "false", "off"} {
		b, ok := parseBoolean(s)
		require.True(t, ok, s)
		require.False(t, b, s)
	}
	_, ok := parseBoolean("maybe")
	require.False(t, ok)
}

// With the UKI's "initrd" signature, the first write goes through the signed
// branch: the .auth file holds the PolicyAuthorize(key, "initrd") digest, the
// index is written with zeros, PCR 9 records each initialization, and the host
// can extend through the PolicyNvWritten branch without any signature.
func TestNvPCRInitSigned(t *testing.T) {
	r := newNvPCRRig(t)
	key := r.signInitrd()
	hw := r.def("hardware", testNvIndexHardware, `,"priority":500,"orderly":false`)
	login := r.def("login", testNvIndexLogin, `,"priority":800`)

	require.NoError(t, initNvPCRs(r.dev, []nvpcrDef{hw, login}))

	area := rsaPublicArea(&key.PublicKey, uint32(key.PublicKey.E))
	keyName, err := tpm2.ObjectName(&area)
	require.NoError(t, err)
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	require.NoError(t, (&tpm2.PolicyAuthorize{KeySign: *keyName, PolicyRef: tpm2.TPM2BDigest{Buffer: policyRefDigest("initrd")}}).Update(calc))
	require.Equal(t, calc.Hash().Digest, r.authDigest("hardware"))
	require.Equal(t, calc.Hash().Digest, r.authDigest("login"))

	zeros := sha256.Sum256(make([]byte, 64))
	for _, idx := range []uint32{testNvIndexHardware, testNvIndexLogin} {
		require.True(t, r.nvPublic(idx).Attributes.Written)
		require.Equal(t, zeros[:], r.nvRead(idx))
	}
	require.False(t, r.nvPublic(testNvIndexHardware).Attributes.Orderly)
	require.True(t, r.nvPublic(testNvIndexLogin).Attributes.Orderly)

	require.Equal(t, extendChain(make([]byte, 32),
		initWord(r, "hardware", testNvIndexHardware), initWord(r, "login", testNvIndexLogin)),
		r.pcr(pcrKernelInitrd))

	ev := sha256.Sum256([]byte("event"))
	require.NoError(t, r.hostExtend(testNvIndexLogin, r.authDigest("login"), ev[:]))
	want := sha256.Sum256(append(zeros[:], ev[:]...))
	require.Equal(t, want[:], r.nvRead(testNvIndexLogin))
}

// countingTPM counts the commands written to the TPM by command code.
type countingTPM struct {
	io.ReadWriter
	counts map[tpm2.TPMCC]int
}

func (c *countingTPM) Write(b []byte) (int, error) {
	if len(b) >= 10 {
		c.counts[tpm2.TPMCC(binary.BigEndian.Uint32(b[6:10]))]++
	}
	return c.ReadWriter.Write(b)
}

// The signed first write verifies the "initrd" signature once per setup and
// reuses the ticket for every NvPCR. Each VerifySignature costs about 500 ms
// on a Nuvoton dTPM, so verifying per index multiplies the setup time.
func TestNvPCRInitSignedVerifiesOnce(t *testing.T) {
	r := newNvPCRRig(t)
	r.signInitrd()
	defs := []nvpcrDef{
		r.def("hardware", testNvIndexHardware, `,"priority":500`),
		r.def("login", testNvIndexLogin, `,"priority":800`),
	}
	c := &countingTPM{ReadWriter: r.dev, counts: map[tpm2.TPMCC]int{}}

	require.NoError(t, initNvPCRs(c, defs))
	require.Equal(t, 1, c.counts[tpm2.TPMCCVerifySignature])
	require.Equal(t, 2, c.counts[tpm2.TPMCCPolicyAuthorize])
}

// A reused ticket only proves the key signed the approved digest. The TPM
// still compares that digest with the session's live PolicyPCR, so a ticket
// taken before a PCR 11 change cannot satisfy PolicyAuthorize after it.
func TestNvPCRSignedTicketBoundToPCR11(t *testing.T) {
	r := newNvPCRRig(t)
	r.signInitrd()
	init, err := chooseNvPCRInit(r.tpm)
	require.NoError(t, err)
	writePolicy, err := nvpcrWritePolicy(init.digest)
	require.NoError(t, err)
	nv, err := defineNvPCR(r.tpm, r.def("login", testNvIndexLogin, ""), writePolicy)
	require.NoError(t, err)
	require.NoError(t, firstWriteNvPCR(r.tpm, nv, init))
	require.NotEmpty(t, init.ticket.keyName.Buffer)

	extendPhasePCR11(t, r.tpm, phaseLeaveInitrd)
	sess, cleanup, err := tpm2.PolicySession(r.tpm, tpm2.TPMAlgSHA256, 16)
	require.NoError(t, err)
	defer func() { _ = cleanup() }()
	_, err = (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcrKernelBoot)),
	}}}}).Execute(r.tpm)
	require.NoError(t, err)
	_, err = (&tpm2.PolicyAuthorize{
		PolicySession:  sess.Handle(),
		ApprovedPolicy: tpm2.TPM2BDigest{Buffer: init.ticket.approved},
		PolicyRef:      tpm2.TPM2BDigest{Buffer: policyRefDigest(nvpcrInitPolicyRef)},
		KeySign:        init.ticket.keyName,
		CheckTicket:    init.ticket.validation,
	}).Execute(r.tpm)
	require.Error(t, err)
}

// Without an "initrd" signature the first write is bound to the current PCR 11
// (systemd v263). The policy is lost once PCR 11 leaves the initrd value, which
// is what keeps a booted system from initializing an NvPCR itself.
func TestNvPCRInitPCRFallback(t *testing.T) {
	r := newNvPCRRig(t)
	extendPhasePCR11(t, r.tpm, phaseEnterInitrd)
	approved, err := pcr11PolicyDigest(r.tpm)
	require.NoError(t, err)
	login := r.def("login", testNvIndexLogin, "")

	require.NoError(t, initNvPCRs(r.dev, []nvpcrDef{login}))
	require.Equal(t, approved, r.authDigest("login"))
	require.True(t, r.nvPublic(testNvIndexLogin).Attributes.Written)
	ev := sha256.Sum256([]byte("event"))
	require.NoError(t, r.hostExtend(testNvIndexLogin, approved, ev[:]))

	// A second index defined under the same policy cannot take its first write
	// after leave-initrd.
	writePolicy, err := nvpcrWritePolicy(approved)
	require.NoError(t, err)
	nv, err := defineNvPCR(r.tpm, r.def("hardware", testNvIndexHardware, ""), writePolicy)
	require.NoError(t, err)
	extendPhasePCR11(t, r.tpm, phaseLeaveInitrd)
	require.Error(t, firstWriteNvPCR(r.tpm, nv, nvpcrInit{digest: approved}))
	require.False(t, r.nvPublic(testNvIndexHardware).Attributes.Written)
}

// An existing index is reused when it already has the expected Name, replaced
// when it looks like an NvPCR from another key or from systemd 261, and left
// alone otherwise.
func TestNvPCRDefineReuseReplace(t *testing.T) {
	r := newNvPCRRig(t)
	approved, err := pcr11PolicyDigest(r.tpm)
	require.NoError(t, err)
	writePolicy, err := nvpcrWritePolicy(approved)
	require.NoError(t, err)

	define := func(index uint32, attrs tpm2.TPMANV, size uint16) {
		_, err := (&tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex: tpm2.TPMHandle(index), NameAlg: tpm2.TPMAlgSHA256, Attributes: attrs, DataSize: size,
		})}).Execute(r.tpm)
		require.NoError(t, err)
	}

	// systemd 261 anchor-style NvPCR: replaced.
	define(testNvIndexHardware, tpm2.TPMANV{ClearSTClear: true, OwnerWrite: true, AuthWrite: true, OwnerRead: true, AuthRead: true, NT: tpm2.TPMNTExtend}, 32)
	hw := r.def("hardware", testNvIndexHardware, "")
	_, err = defineNvPCR(r.tpm, hw, writePolicy)
	require.NoError(t, err)
	require.True(t, r.nvPublic(testNvIndexHardware).Attributes.PolicyWrite)

	// Same Name: reused as is.
	_, err = defineNvPCR(r.tpm, hw, writePolicy)
	require.NoError(t, err)

	// Some other application's index: refused.
	define(testNvIndexLogin, tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, NT: tpm2.TPMNTOrdinary}, 8)
	_, err = defineNvPCR(r.tpm, r.def("login", testNvIndexLogin, ""), writePolicy)
	require.ErrorContains(t, err, "not an NvPCR")
	require.Equal(t, tpm2.TPMNTOrdinary, r.nvPublic(testNvIndexLogin).Attributes.NT)

}

// When the TPM runs out of NV space, the setup stops at that NvPCR and skips
// the less important ones, and leaves the flag systemd-tpm2-setup leaves so the
// host reports it.
func TestNvPCRInitNVSpaceExhausted(t *testing.T) {
	r := newNvPCRRig(t)
	// Fill with ever smaller indexes so no 32-byte NvPCR fits afterwards.
	handle, filled := tpm2.TPMHandle(0x01500000), false
	for _, size := range []uint16{2048, 256, 32, 1} {
		for range 1024 {
			_, err := (&tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
				NVIndex:    handle,
				NameAlg:    tpm2.TPMAlgSHA256,
				Attributes: tpm2.TPMANV{OwnerWrite: true, OwnerRead: true, NT: tpm2.TPMNTOrdinary},
				DataSize:   size,
			})}).Execute(r.tpm)
			if errors.Is(err, tpm2.TPMRCNVSpace) {
				filled = true
				break
			}
			require.NoError(t, err)
			handle++
		}
	}
	require.True(t, filled, "swtpm never ran out of NV space")

	hw := r.def("hardware", testNvIndexHardware, `,"priority":500,"orderly":false`)
	login := r.def("login", testNvIndexLogin, `,"priority":800`)
	require.NoError(t, initNvPCRs(r.dev, []nvpcrDef{hw, login}))

	require.FileExists(t, filepath.Join(r.authDir, "tpm2-nv-space-exhausted-non-orderly"))
	require.NoFileExists(t, filepath.Join(r.authDir, "hardware.auth"))
	require.NoFileExists(t, filepath.Join(r.authDir, "login.auth"))
	_, err := (&tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(testNvIndexLogin)}).Execute(r.tpm)
	require.ErrorIs(t, err, tpm2.TPMRCHandle, "a less important NvPCR must not be tried")
}

// The whole setup as boost() runs it: gated on a measured boot, extends
// enter-initrd first, initializes the NvPCRs, then closes with the PCR 9
// separator that systemd-pcrnvdone extends before any unlock.
func TestSetupNvPCRs(t *testing.T) {
	r := newNvPCRRig(t)
	r.def("login", testNvIndexLogin, "")
	resetEnterInitrdBarrier()
	t.Cleanup(resetEnterInitrdBarrier)
	t.Cleanup(func() { cmdlineMeasuredOS = nil })
	r.close()

	no := false
	cmdlineMeasuredOS = &no
	setupNvPCRs()
	r.open()
	require.Equal(t, make([]byte, 32), r.pcr(pcrKernelBoot), "an unmeasured boot must leave PCR 11 alone")
	require.Equal(t, make([]byte, 32), r.pcr(pcrKernelInitrd))
	r.close()

	yes := true
	cmdlineMeasuredOS = &yes
	setupNvPCRs()
	r.open()
	require.Equal(t, extendChain(make([]byte, 32), phaseEnterInitrd), r.pcr(pcrKernelBoot))
	require.True(t, r.nvPublic(testNvIndexLogin).Attributes.Written)
	require.Equal(t, extendChain(make([]byte, 32), initWord(r, "login", testNvIndexLogin), "nvpcr-separator"),
		r.pcr(pcrKernelInitrd))
}

// TPM users that run a policy session or extend a PCR wait for the NvPCR setup,
// so an extend cannot land inside a session that the setup has open. Resume
// waits too: it hands over to a kernel whose NvPCRs this boot must initialize.
func TestNvPCRSetupGatesTPMUsers(t *testing.T) {
	enableSwEmulator = true // no swtpm: the latch fails fast once it runs
	t.Cleanup(func() { enableSwEmulator = false })

	for name, run := range map[string]func(){
		"PCR 15 latch": func() { _ = measureVolumeKeyToPCR15(nil, "root", "uuid") },
		// A missing device makes resume fail before it writes /sys/power/resume.
		"resume": func() { _ = resume(filepath.Join(t.TempDir(), "no-such-swap")) },
	} {
		nvpcrSetup.Add(1)
		var release sync.Once
		t.Cleanup(func() { release.Do(nvpcrSetup.Done) }) // a failure must not wedge later tests
		done := make(chan struct{})
		go func() {
			run()
			close(done)
		}()
		select {
		case <-done:
			require.Fail(t, name+" ran while the NvPCR setup was in progress")
		case <-time.After(200 * time.Millisecond):
		}
		release.Do(nvpcrSetup.Done)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.Fail(t, name+" did not run after the NvPCR setup finished")
		}
	}
}

func TestNvPCRBrokenTPMMatch(t *testing.T) {
	props := func(mf string, fw uint32) []tpm2.TPMSTaggedProperty {
		return []tpm2.TPMSTaggedProperty{
			{Property: tpm2.TPMPTManufacturer, Value: binary.BigEndian.Uint32([]byte(mf))},
			{Property: tpm2.TPMPTFirmwareVersion1, Value: fw},
		}
	}
	require.True(t, brokenNvPCRVendor(props("STM ", 73<<16|4)))
	require.True(t, brokenNvPCRVendor(props("STM\x00", 73<<16|4)))
	require.False(t, brokenNvPCRVendor(props("STM ", 73<<16|8)))
	require.False(t, brokenNvPCRVendor(props("IBM\x00", 73<<16|4)))
	require.False(t, brokenNvPCRVendor(nil))
}

// A TPM that never finishes the setup must not hang the boot: the wait gives
// up after nvpcrSetupTimeout, once, and later waiters do not wait again.
func TestNvPCRSetupWaitIsBounded(t *testing.T) {
	oldTimeout := nvpcrSetupTimeout
	nvpcrSetupTimeout = 100 * time.Millisecond
	nvpcrSetup.Add(1)
	t.Cleanup(func() {
		nvpcrSetup.Done()
		nvpcrSetupTimeout = oldTimeout
		nvpcrSetupAbandoned.Store(false)
	})

	start := time.Now()
	awaitNvPCRSetup()
	require.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond)
	require.True(t, nvpcrSetupAbandoned.Load())

	start = time.Now()
	awaitNvPCRSetup()
	require.Less(t, time.Since(start), 50*time.Millisecond, "a later waiter must not wait again")
}
