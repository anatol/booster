package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// systemd NvPCR contract (v262 tpm2_nvpcr_initialize):
//
//	policy ref "initrd" → SHA256("initrd")
//	write policy = PolicyOR(PolicyAuthorize(pubkey, ref), PolicyNvWritten(true))
//	first write = NV_Extend(zeros) under Authorize branch + PolicyOR
//	handoff = /run/systemd/nvpcr/<name>.auth (hex of Authorize branch digest)

const (
	nvpcrInitPolicyRef   = "initrd"
	nvpcrAuthDir         = "/run/systemd/nvpcr"
	nvpcrPriorityDefault = uint64(1000)
	pcrKernelInitrd      = 9
)

var (
	nvpcrDefDirs = []string{"/usr/lib/nvpcr", "/etc/nvpcr", "/run/nvpcr"}
	nvpcrPubKeyPaths = []string{
		"/.extra/tpm2-pcr-public-key.pem",
		"/run/systemd/tpm2-pcr-public-key.pem",
		"/etc/systemd/tpm2-pcr-public-key.pem",
	}
)

type nvpcrDef struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	NVIndex   uint32 `json:"nvIndex"`
	Priority  uint64 `json:"priority"`
	Orderly   *bool  `json:"orderly"`
}

var setupNvPCROnce sync.Once

// setupNvPCRsEarly mirrors systemd-tpm2-setup --early's NvPCR half.
// Skips when definitions or SignInitrdPCRs materials are missing.
// Idempotent: safe to call from boost() and again from the TPM unlock path.
func setupNvPCRsEarly() {
	setupNvPCROnce.Do(setupNvPCRsEarlyOnce)
}

func setupNvPCRsEarlyOnce() {
	defs, err := loadNvPCRDefinitions()
	if err != nil {
		warning("nvpcr: listing definitions: %v", err)
		return
	}
	if len(defs) == 0 {
		debug("nvpcr: no definitions in image, skipping")
		return
	}

	pubPEM, err := readFirstExisting(nvpcrPubKeyPaths...)
	if err != nil {
		debug("nvpcr: no PCR public key (%v), skipping", err)
		return
	}
	sigJSON, enabled, err := resolveSignature("")
	if err != nil || !enabled {
		debug("nvpcr: no initrd PCR signature, skipping")
		return
	}

	verifyKey, err := parsePCRpEM(pubPEM)
	if err != nil {
		warning("nvpcr: PCR public key: %v", err)
		return
	}

	// Match tpm2Unseal: wait for the udev TPM signal (or its timeout), then try
	// openTPM. A false from tpmAwaitReady only means udev did not fire — the
	// device may already be present.
	tpmAwaitReady()
	if err := ensureEnterInitrdBarrier(); err != nil {
		warning("nvpcr: enter-initrd barrier: %v", err)
		return
	}

	if err := os.MkdirAll(nvpcrAuthDir, 0o755); err != nil {
		warning("nvpcr: mkdir %s: %v", nvpcrAuthDir, err)
		return
	}

	dev, err := openTPM()
	if err != nil {
		warning("nvpcr: open TPM: %v", err)
		return
	}
	defer dev.Close()
	thetpm := transport.FromReadWriteCloser(dev)

	sort.SliceStable(defs, func(i, j int) bool {
		if defs[i].Priority != defs[j].Priority {
			return defs[i].Priority < defs[j].Priority
		}
		return defs[i].Name < defs[j].Name
	})

	var ok, failed int
	for _, d := range defs {
		authPath := filepath.Join(nvpcrAuthDir, d.Name+".auth")
		if _, err := os.Stat(authPath); err == nil {
			debug("nvpcr: %s already initialized", d.Name)
			ok++
			continue
		}
		if err := initializeOneNvPCR(thetpm, d, verifyKey, sigJSON); err != nil {
			if isNvSpaceExhausted(err) {
				warning("nvpcr: NV space exhausted at %s: %v", d.Name, err)
				break
			}
			warning("nvpcr: %s: %v", d.Name, err)
			failed++
			continue
		}
		ok++
	}
	if failed > 0 {
		warning("nvpcr: %d initialized, %d failed", ok, failed)
	} else if ok > 0 {
		info("nvpcr: %d NvPCR(s) initialized", ok)
	}
}

func loadNvPCRDefinitions() ([]nvpcrDef, error) {
	seen := map[string]nvpcrDef{}
	for _, dir := range nvpcrDefDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".nvpcr") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			var d nvpcrDef
			if err := json.Unmarshal(raw, &d); err != nil {
				warning("nvpcr: %s: %v", path, err)
				continue
			}
			if d.Name == "" {
				d.Name = strings.TrimSuffix(e.Name(), ".nvpcr")
			}
			if d.Priority == 0 {
				d.Priority = nvpcrPriorityDefault
			}
			if d.Algorithm == "" {
				d.Algorithm = "sha256"
			}
			if d.Algorithm != "sha256" {
				warning("nvpcr: %s: only sha256 supported, skipping", d.Name)
				continue
			}
			seen[d.Name] = d
		}
	}
	out := make([]nvpcrDef, 0, len(seen))
	for _, d := range seen {
		out = append(out, d)
	}
	return out, nil
}

func initializeOneNvPCR(t transport.TPM, d nvpcrDef, verifyKey *rsa.PublicKey, sigJSON []byte) error {
	orderly := true
	if d.Orderly != nil {
		orderly = *d.Orderly
	}

	var (
		authorize []byte
		keyName   tpm2.TPM2BName
		lastErr   error
	)
	for _, exp := range []uint32{0x10001, 0} {
		name, authBranch, writePol, err := nvpcrWritePolicy(verifyKey, exp)
		if err != nil {
			lastErr = err
			continue
		}
		if err := defineNvPCRIndex(t, d.NVIndex, orderly, writePol); err != nil {
			lastErr = err
			continue
		}
		if err := firstWriteNvPCR(t, d.NVIndex, verifyKey, exp, name, authBranch, sigJSON); err != nil {
			lastErr = err
			continue
		}
		authorize, keyName, lastErr = authBranch, name, nil
		_ = keyName
		break
	}
	if lastErr != nil {
		return lastErr
	}

	authPath := filepath.Join(nvpcrAuthDir, d.Name+".auth")
	if err := os.WriteFile(authPath, []byte(hex.EncodeToString(authorize)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", authPath, err)
	}

	pub, err := (&tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(d.NVIndex)}).Execute(t)
	if err == nil {
		word := fmt.Sprintf("nvpcr-init:%s:0x%x:%x", d.Name, d.NVIndex, pub.NVName.Buffer)
		if err := extendWordToPCR(pcrKernelInitrd, word); err != nil {
			debug("nvpcr: PCR9 trace for %s: %v", d.Name, err)
		}
	}
	return nil
}

// nvpcrWritePolicy returns key Name, Authorize-branch digest, and the PolicyOR
// write-policy digest used as the NV index authPolicy.
func nvpcrWritePolicy(pub *rsa.PublicKey, exp uint32) (tpm2.TPM2BName, []byte, []byte, error) {
	area := rsaPublicArea(pub, exp)
	name, err := tpm2.ObjectName(&area)
	if err != nil {
		return tpm2.TPM2BName{}, nil, nil, err
	}

	ref := sha256.Sum256([]byte(nvpcrInitPolicyRef))
	authPol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return tpm2.TPM2BName{}, nil, nil, err
	}
	if err := (&tpm2.PolicyAuthorize{
		KeySign:   *name,
		PolicyRef: tpm2.TPM2BDigest{Buffer: ref[:]},
	}).Update(authPol); err != nil {
		return tpm2.TPM2BName{}, nil, nil, err
	}
	authorize := append([]byte(nil), authPol.Hash().Digest...)

	nvPol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return tpm2.TPM2BName{}, nil, nil, err
	}
	if err := (&tpm2.PolicyNVWritten{WrittenSet: true}).Update(nvPol); err != nil {
		return tpm2.TPM2BName{}, nil, nil, err
	}
	nvWritten := nvPol.Hash().Digest

	orPol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return tpm2.TPM2BName{}, nil, nil, err
	}
	if err := (&tpm2.PolicyOr{PHashList: tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{
		{Buffer: authorize},
		{Buffer: nvWritten},
	}}}).Update(orPol); err != nil {
		return tpm2.TPM2BName{}, nil, nil, err
	}
	return *name, authorize, append([]byte(nil), orPol.Hash().Digest...), nil
}

func defineNvPCRIndex(t transport.TPM, nvIndex uint32, orderly bool, writePolicy []byte) error {
	want, err := nvpcrPublic(nvIndex, orderly, writePolicy)
	if err != nil {
		return err
	}
	wantName, err := tpm2.NVName(want)
	if err != nil {
		return err
	}

	if pubRsp, err := (&tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(nvIndex)}).Execute(t); err == nil {
		if bytes.Equal(wantName.Buffer, pubRsp.NVName.Buffer) {
			debug("nvpcr: reusing NV index 0x%x", nvIndex)
			return nil
		}
		_, _ = (&tpm2.NVUndefineSpace{
			AuthHandle: tpm2.TPMRHOwner,
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(nvIndex), Name: pubRsp.NVName},
		}).Execute(t)
	}

	_, err = (&tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B(*want),
	}).Execute(t)
	if err != nil {
		return fmt.Errorf("NV_DefineSpace 0x%x: %w", nvIndex, err)
	}
	return nil
}

func nvpcrPublic(nvIndex uint32, orderly bool, writePolicy []byte) (*tpm2.TPMSNVPublic, error) {
	attrs := tpm2.TPMANV{
		PolicyWrite:  true,
		OwnerRead:    true,
		AuthRead:     true,
		ClearSTClear: true,
		NT:           tpm2.TPMNTExtend,
	}
	if orderly {
		attrs.Orderly = true
	}
	return &tpm2.TPMSNVPublic{
		NVIndex:    tpm2.TPMHandle(nvIndex),
		NameAlg:    tpm2.TPMAlgSHA256,
		Attributes: attrs,
		AuthPolicy: tpm2.TPM2BDigest{Buffer: writePolicy},
		DataSize:   32,
	}, nil
}

func firstWriteNvPCR(t transport.TPM, nvIndex uint32, verifyKey *rsa.PublicKey, exp uint32, keyName tpm2.TPM2BName, authorizePolicy, sigJSON []byte) error {
	pubRsp, err := (&tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(nvIndex)}).Execute(t)
	if err != nil {
		return fmt.Errorf("NV_ReadPublic: %w", err)
	}
	nv := tpm2.NamedHandle{Handle: tpm2.TPMHandle(nvIndex), Name: pubRsp.NVName}

	sigs, err := parseSignatureJSON(sigJSON)
	if err != nil {
		return err
	}

	sess, cleanup, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return err
	}
	defer cleanup()

	sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcrKernelBoot)),
	}}}
	if _, err := (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel}).Execute(t); err != nil {
		return fmt.Errorf("PolicyPCR: %w", err)
	}
	pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(t)
	if err != nil {
		return err
	}
	approved := pgd.PolicyDigest.Buffer

	entry, err := selectSignature(sigs, "sha256", verifyKey, approved)
	if err != nil {
		return err
	}

	le, err := (&tpm2.LoadExternal{
		InPublic:  tpm2.New2B(rsaPublicArea(verifyKey, exp)),
		Hierarchy: tpm2.TPMRHOwner,
	}).Execute(t)
	if err != nil {
		return fmt.Errorf("LoadExternal: %w", err)
	}
	defer flushHandle(t, le.ObjectHandle)

	h := sha256.Sum256(approved)
	vs, err := (&tpm2.VerifySignature{
		KeyHandle: le.ObjectHandle,
		Digest:    tpm2.TPM2BDigest{Buffer: h[:]},
		Signature: rsassaSHA256Sig(entry.Sig),
	}).Execute(t)
	if err != nil {
		return fmt.Errorf("VerifySignature: %w", err)
	}

	ref := sha256.Sum256([]byte(nvpcrInitPolicyRef))
	if _, err := (&tpm2.PolicyAuthorize{
		PolicySession:  sess.Handle(),
		ApprovedPolicy: tpm2.TPM2BDigest{Buffer: approved},
		PolicyRef:      tpm2.TPM2BDigest{Buffer: ref[:]},
		KeySign:        keyName,
		CheckTicket:    vs.Validation,
	}).Execute(t); err != nil {
		return fmt.Errorf("PolicyAuthorize: %w", err)
	}

	nvPol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return err
	}
	if err := (&tpm2.PolicyNVWritten{WrittenSet: true}).Update(nvPol); err != nil {
		return err
	}
	if _, err := (&tpm2.PolicyOr{
		PolicySession: sess.Handle(),
		PHashList: tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{
			{Buffer: authorizePolicy},
			{Buffer: nvPol.Hash().Digest},
		}},
	}).Execute(t); err != nil {
		return fmt.Errorf("PolicyOR: %w", err)
	}

	zeros := make([]byte, 32)
	auth := tpm2.AuthHandle{Handle: nv.Handle, Name: nv.Name, Auth: sess}
	return nvExtend(t, auth, nv, zeros)
}

func extendWordToPCR(pcr int, word string) error {
	dev, err := openTPM()
	if err != nil {
		return err
	}
	defer dev.Close()
	banks, err := activePCRBanks(dev)
	if err != nil {
		return err
	}
	for _, bank := range banks {
		h, ok := cryptoHashForPCRBank(bank)
		if !ok {
			return fmt.Errorf("unsupported PCR bank %v", bank)
		}
		hh := h.New()
		hh.Write([]byte(word))
		if err := legacy.PCRExtend(dev, tpmutil.Handle(pcr), bank, hh.Sum(nil), ""); err != nil {
			return err
		}
	}
	return nil
}

func parsePCRpEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA")
	}
	return rsaPub, nil
}

func readFirstExisting(paths ...string) ([]byte, error) {
	var last error
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err == nil {
			return b, nil
		}
		last = err
	}
	if last == nil {
		last = os.ErrNotExist
	}
	return nil, last
}

func isNvSpaceExhausted(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "nv_space") || (strings.Contains(s, "insufficient") && strings.Contains(s, "nv"))
}
