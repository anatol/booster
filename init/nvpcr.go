package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// NvPCRs are systemd's NT_EXTEND NV indexes, initialized here as systemd's
// tpm2_nvpcr_initialize and systemd-pcrnvdone do.

const (
	nvpcrInitPolicyRef  = "initrd"
	nvpcrDefaultPrio    = 1000
	nvpcrMaxInitRetries = 30
)

var (
	// nvpcrDefDir holds the definitions the generator already resolved.
	nvpcrDefDir       = "/usr/lib/nvpcr"
	pcrPublicKeyPaths = []string{"/.extra/tpm2-pcr-public-key.pem"}
	nvpcrAuthDir      = "/run/systemd/nvpcr"
	nvpcrExhaustedDir = "/run/systemd"

	// nvpcrSetup is held while setupNvPCRs runs. TPM users that start a policy
	// session or extend a PCR wait on it, since an extend between PolicyPCR and
	// the command that consumes the session fails it with TPM_RC_PCR_CHANGED.
	nvpcrSetup sync.WaitGroup

	// nvpcrSetupTimeout bounds that wait: a TPM that hangs in NV_Extend would
	// otherwise hang the boot.
	nvpcrSetupTimeout   = 30 * time.Second
	nvpcrSetupAbandoned atomic.Bool

	// cmdlineMeasuredOS is systemd.tpm2_measured_os=, nil when unset.
	cmdlineMeasuredOS *bool
)

// awaitNvPCRSetup waits for setupNvPCRs, at most nvpcrSetupTimeout per boot.
func awaitNvPCRSetup() {
	if nvpcrSetupAbandoned.Load() || !waitTimeout(&nvpcrSetup, nvpcrSetupTimeout) {
		return
	}
	if !nvpcrSetupAbandoned.Swap(true) {
		warning("nvpcr: setup still running after %v, continuing without it", nvpcrSetupTimeout)
	}
}

type nvpcrDef struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	NVIndex   uint32 `json:"nvIndex"`
	Priority  uint64 `json:"priority"`
	Orderly   *bool  `json:"orderly"`
}

func (d nvpcrDef) orderly() bool { return d.Orderly == nil || *d.Orderly }

func loadNvPCRDefs(dir string) []nvpcrDef {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var defs []nvpcrDef
	for _, e := range entries {
		stem, ok := strings.CutSuffix(e.Name(), ".nvpcr")
		if !ok {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			warning("nvpcr: %v", err)
			continue
		}
		d := nvpcrDef{Priority: nvpcrDefaultPrio}
		if err := json.Unmarshal(data, &d); err != nil {
			warning("nvpcr: %s: %v", e.Name(), err)
			continue
		}
		if d.Name != stem || d.NVIndex == 0 || (d.Algorithm != "" && d.Algorithm != "sha256") {
			warning("nvpcr: %s: unsupported definition, skipping", e.Name())
			continue
		}
		defs = append(defs, d)
	}
	sort.Slice(defs, func(i, j int) bool {
		if defs[i].Priority != defs[j].Priority {
			return defs[i].Priority < defs[j].Priority
		}
		return defs[i].Name < defs[j].Name
	})
	return defs
}

// measuredOS mirrors systemd's efi_measured_os: the command line decides,
// otherwise the boot counts as measured when systemd-stub measured the UKI into
// PCR 11 (src/shared/efi-loader.c).
func measuredOS() bool {
	if cmdlineMeasuredOS != nil {
		return *cmdlineMeasuredOS
	}
	_, data, err := readEfiVar("StubPcrKernelImage", "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f")
	if err != nil {
		return false
	}
	return fromUnicode16(data, binary.LittleEndian) == "11"
}

// nvpcrBrokenTPM matches systemd's hwdb TPM2_BROKEN_NVPCR entry: ST33 firmware
// 73.4 crashes on the second NV_Extend to an orderly NT_EXTEND index
// (hwdb.d/60-tpm2.hwdb, systemd issue 40485).
func nvpcrBrokenTPM(t transport.TPM) bool {
	rsp, err := (&tpm2.GetCapability{Capability: tpm2.TPMCapTPMProperties, Property: uint32(tpm2.TPMPTManufacturer), PropertyCount: 7}).Execute(t)
	if err != nil {
		return false
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	return err == nil && brokenNvPCRVendor(props.TPMProperty)
}

func brokenNvPCRVendor(props []tpm2.TPMSTaggedProperty) bool {
	var mf, fw uint32
	for _, p := range props {
		switch p.Property {
		case tpm2.TPMPTManufacturer:
			mf = p.Value
		case tpm2.TPMPTFirmwareVersion1:
			fw = p.Value
		}
	}
	return mf&^0xff == 0x53544d00 && fw == 73<<16|4 // "STM" padded with a space or NUL
}

// nvpcrInit is how the first write to every NvPCR is authorized this boot.
type nvpcrInit struct {
	digest []byte // policy digest of the init branch, stored in the .auth file
	key    *rsa.PublicKey
	sigs   map[string][]pcrSignature // nil for the PCR 11 fallback
	ticket *policyTicket
}

// pcr11PolicyDigest returns the PolicyPCR digest over the current sha256 PCR 11.
func pcr11PolicyDigest(t transport.TPM) ([]byte, error) {
	sess, cleanup, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()
	if err := policyPCR11(t, sess.Handle()); err != nil {
		return nil, err
	}
	pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(t)
	if err != nil {
		return nil, err
	}
	return pgd.PolicyDigest.Buffer, nil
}

func policyPCR11(t transport.TPM, sess tpm2.TPMHandle) error {
	sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(pcrKernelBoot),
	}}}
	_, err := (&tpm2.PolicyPCR{PolicySession: sess, Pcrs: sel}).Execute(t)
	return err
}

// chooseNvPCRInit prefers the UKI's signed "initrd" policy and falls back to a
// PolicyPCR over the current PCR 11, which only holds while PCR 11 is in its
// initrd state (systemd tpm2_nvpcr_load_signed_init_policy, commit 7d37482ce4).
func chooseNvPCRInit(t transport.TPM) (nvpcrInit, error) {
	approved, err := pcr11PolicyDigest(t)
	if err != nil {
		return nvpcrInit{}, err
	}
	if key, sigs := nvpcrSignedPolicy(approved); key != nil {
		area := rsaPublicArea(key, uint32(key.E))
		name, err := tpm2.ObjectName(&area)
		if err != nil {
			return nvpcrInit{}, err
		}
		calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
		if err != nil {
			return nvpcrInit{}, err
		}
		if err := (&tpm2.PolicyAuthorize{KeySign: *name, PolicyRef: tpm2.TPM2BDigest{Buffer: policyRefDigest(nvpcrInitPolicyRef)}}).Update(calc); err != nil {
			return nvpcrInit{}, err
		}
		return nvpcrInit{digest: calc.Hash().Digest, key: key, sigs: sigs, ticket: &policyTicket{}}, nil
	}
	debug("nvpcr: no signed initrd policy, binding the first write to PCR%d", pcrKernelBoot)
	return nvpcrInit{digest: approved}, nil
}

// nvpcrSignedPolicy returns the UKI's PCR key and signatures when they hold an
// "initrd" entry for the current PCR 11.
func nvpcrSignedPolicy(approved []byte) (*rsa.PublicKey, map[string][]pcrSignature) {
	pemData, sigData := readFirstFile(pcrPublicKeyPaths), readFirstFile(pcrSignatureSearchPaths)
	if pemData == nil || sigData == nil {
		return nil, nil
	}
	key, err := parseRSAPublicKey(pemData)
	if err != nil {
		warning("nvpcr: PCR public key: %v", err)
		return nil, nil
	}
	sigs, err := parseSignatureJSON(sigData)
	if err != nil {
		warning("nvpcr: PCR signature: %v", err)
		return nil, nil
	}
	if _, err := selectSignature(sigs, "sha256", key, approved, nvpcrInitPolicyRef); err != nil {
		return nil, nil
	}
	return key, sigs
}

// nvWrittenDigest is the PolicyNvWritten(true) branch of every NvPCR write policy.
var nvWrittenDigest = func() []byte {
	calc, _ := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	_ = (&tpm2.PolicyNVWritten{WrittenSet: true}).Update(calc)
	return calc.Hash().Digest
}()

// nvpcrBranches is the PolicyOR list of an NvPCR write policy: the init branch,
// then PolicyNvWritten. The host rebuilds it from the .auth file for every
// later extend.
func nvpcrBranches(init []byte) tpm2.TPMLDigest {
	return tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{{Buffer: init}, {Buffer: nvWrittenDigest}}}
}

func nvpcrWritePolicy(init []byte) ([]byte, error) {
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	if err := (&tpm2.PolicyOr{PHashList: nvpcrBranches(init)}).Update(calc); err != nil {
		return nil, err
	}
	return calc.Hash().Digest, nil
}

func nvpcrPublic(d nvpcrDef, writePolicy []byte) tpm2.TPMSNVPublic {
	return tpm2.TPMSNVPublic{
		NVIndex: tpm2.TPMHandle(d.NVIndex),
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			ClearSTClear: true,
			Orderly:      d.orderly(),
			PolicyWrite:  true,
			OwnerRead:    true,
			AuthRead:     true,
			NT:           tpm2.TPMNTExtend,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: writePolicy},
		DataSize:   32,
	}
}

// looksLikeNvPCR reports whether an existing index is an NvPCR this code may
// replace: one defined under another key or init policy, or the anchor-based
// kind from systemd 261. Anything else at the same handle is left alone.
func looksLikeNvPCR(have, want tpm2.TPMANV) bool {
	norm := func(a tpm2.TPMANV) tpm2.TPMANV {
		a.Written, a.Orderly = false, false
		return a
	}
	old := tpm2.TPMANV{ClearSTClear: true, OwnerWrite: true, AuthWrite: true, OwnerRead: true, AuthRead: true, NT: tpm2.TPMNTExtend}
	return norm(have) == norm(want) || norm(have) == old
}

var errNVSpace = errors.New("TPM NV index space exhausted")

// defineNvPCR returns the index ready for its first write, reusing an unwritten
// one with the expected Name (tpm2_reuse_or_redefine_nvpcr_nv_index).
func defineNvPCR(t transport.TPM, d nvpcrDef, writePolicy []byte) (tpm2.NamedHandle, error) {
	want := nvpcrPublic(d, writePolicy)
	wantName, err := tpm2.NVName(&want)
	if err != nil {
		return tpm2.NamedHandle{}, err
	}
	handle := tpm2.TPMHandle(d.NVIndex)
	rp, err := (&tpm2.NVReadPublic{NVIndex: handle}).Execute(t)
	switch {
	case err == nil && bytes.Equal(rp.NVName.Buffer, wantName.Buffer):
		return tpm2.NamedHandle{Handle: handle, Name: rp.NVName}, nil
	case err == nil:
		have, err := rp.NVPublic.Contents()
		if err != nil {
			return tpm2.NamedHandle{}, err
		}
		if !looksLikeNvPCR(have.Attributes, want.Attributes) {
			return tpm2.NamedHandle{}, fmt.Errorf("NV index %#x is not an NvPCR, leaving it alone", d.NVIndex)
		}
		if _, err := (&tpm2.NVUndefineSpace{AuthHandle: tpm2.TPMRHOwner, NVIndex: tpm2.NamedHandle{Handle: handle, Name: rp.NVName}}).Execute(t); err != nil {
			return tpm2.NamedHandle{}, fmt.Errorf("undefining NV index %#x: %w", d.NVIndex, err)
		}
	case !errors.Is(err, tpm2.TPMRCHandle):
		return tpm2.NamedHandle{}, fmt.Errorf("reading NV index %#x: %w", d.NVIndex, err)
	}
	if _, err := (&tpm2.NVDefineSpace{AuthHandle: tpm2.TPMRHOwner, PublicInfo: tpm2.New2B(want)}).Execute(t); err != nil {
		if errors.Is(err, tpm2.TPMRCNVSpace) {
			return tpm2.NamedHandle{}, errNVSpace
		}
		return tpm2.NamedHandle{}, fmt.Errorf("defining NV index %#x: %w", d.NVIndex, err)
	}
	return tpm2.NamedHandle{Handle: handle, Name: *wantName}, nil
}

// firstWriteNvPCR satisfies the init branch of the write policy and extends
// zeros, which sets TPMA_NV_WRITTEN. A PCR extend between the policy and the
// write invalidates the session, so it retries as systemd does.
func firstWriteNvPCR(t transport.TPM, nv tpm2.NamedHandle, init nvpcrInit) error {
	var err error
	for range nvpcrMaxInitRetries {
		if err = firstWriteNvPCROnce(t, nv, init); !errors.Is(err, tpm2.TPMRCPCRChanged) {
			return err
		}
	}
	return err
}

func firstWriteNvPCROnce(t transport.TPM, nv tpm2.NamedHandle, init nvpcrInit) error {
	sess, cleanup, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return err
	}
	defer func() { _ = cleanup() }()

	if init.key != nil {
		if err := policyAuthorizeSigned(t, sess.Handle(), init.sigs, "sha256", init.key, uint32(init.key.E), nvpcrInitPolicyRef, []int{pcrKernelBoot}, init.ticket); err != nil {
			return err
		}
	} else if err := policyPCR11(t, sess.Handle()); err != nil {
		return err
	}
	if _, err := (&tpm2.PolicyOr{PolicySession: sess.Handle(), PHashList: nvpcrBranches(init.digest)}).Execute(t); err != nil {
		return fmt.Errorf("PolicyOR: %w", err)
	}
	return nvExtend(t, nv.Handle, sess.Handle(), make([]byte, 32))
}

func writeNvPCRAuth(name string, digest []byte) error {
	if err := os.MkdirAll(nvpcrAuthDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(nvpcrAuthDir, name+".auth")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(digest)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// startNvPCRSetup runs setupNvPCRs in the background under nvpcrSetup.
func startNvPCRSetup() {
	nvpcrSetup.Add(1)
	go func() {
		defer nvpcrSetup.Done()
		setupNvPCRs()
	}()
}

// setupNvPCRs initializes every NvPCR bundled in the image, as
// systemd-tpm2-setup --early and systemd-pcrnvdone do in a systemd initrd. It
// runs before the TPM unlocks and the PCR 15 latch, which wait on nvpcrSetup.
func setupNvPCRs() {
	defs := loadNvPCRDefs(nvpcrDefDir)
	if len(defs) == 0 {
		return
	}
	if !measuredOS() {
		debug("nvpcr: not a measured boot, skipping NvPCR setup")
		return
	}
	<-plymouthInitDone
	if !tpmAwaitReady() {
		warning("nvpcr: no TPM found, NvPCRs not initialized")
		return
	}
	if err := ensureEnterInitrdBarrier(); err != nil {
		warning("nvpcr: %v", err)
		return
	}

	dev, err := openTPM()
	if err != nil {
		warning("nvpcr: %v", err)
		return
	}
	defer dev.Close()
	if err := initNvPCRs(dev, defs); err != nil {
		warning("nvpcr: %v", err)
	}
	if err := extendPCRWord(dev, pcrKernelInitrd, "nvpcr-separator"); err != nil {
		warning("nvpcr: extending the separator into PCR%d: %v", pcrKernelInitrd, err)
	}
}

func initNvPCRs(dev io.ReadWriter, defs []nvpcrDef) error {
	t := transport.FromReadWriter(dev)
	if nvpcrBrokenTPM(t) {
		info("nvpcr: this TPM does not support NvPCRs, skipping")
		return nil
	}
	init, err := chooseNvPCRInit(t)
	if err != nil {
		return err
	}
	writePolicy, err := nvpcrWritePolicy(init.digest)
	if err != nil {
		return err
	}

	var initialized, failed int
	for _, d := range defs {
		err := initNvPCR(dev, t, d, init, writePolicy)
		if errors.Is(err, errNVSpace) {
			if err := flagNVSpaceExhausted(d.orderly()); err != nil {
				warning("nvpcr: %v", err)
			}
			info("nvpcr: TPM NV space exhausted at %s, skipping it and less important NvPCRs", d.Name)
			break
		}
		if err != nil {
			warning("nvpcr: %s: %v", d.Name, err)
			failed++
			continue
		}
		initialized++
	}
	if failed > 0 {
		return fmt.Errorf("%d NvPCR(s) failed to initialize", failed)
	}
	if initialized > 0 {
		info("%d NvPCR(s) initialized", initialized)
	}
	return nil
}

// flagNVSpaceExhausted leaves the flag file systemd-tpm2-setup leaves when it
// runs out of NV space, which the host reports.
func flagNVSpaceExhausted(orderly bool) error {
	flag := "tpm2-nv-space-exhausted-non-orderly"
	if orderly {
		flag = "tpm2-nv-space-exhausted-orderly"
	}
	if err := os.MkdirAll(nvpcrExhaustedDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(nvpcrExhaustedDir, flag), nil, 0o644)
}

func initNvPCR(dev io.ReadWriter, t transport.TPM, d nvpcrDef, init nvpcrInit, writePolicy []byte) error {
	nv, err := defineNvPCR(t, d, writePolicy)
	if err != nil {
		return err
	}
	if err := firstWriteNvPCR(t, nv, init); err != nil {
		return fmt.Errorf("first write: %w", err)
	}
	if err := writeNvPCRAuth(d.Name, init.digest); err != nil {
		return err
	}
	// The Name changes when TPMA_NV_WRITTEN is set, so read it after the write.
	rp, err := (&tpm2.NVReadPublic{NVIndex: nv.Handle}).Execute(t)
	if err != nil {
		return err
	}
	word := fmt.Sprintf("nvpcr-init:%s:0x%x:%s", d.Name, d.NVIndex, hex.EncodeToString(rp.NVName.Buffer))
	return extendPCRWord(dev, pcrKernelInitrd, word)
}
