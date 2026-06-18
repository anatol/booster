package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// pcrSignatureSearchPaths is the default location booster reads the PCR
// signature from when tpm2-signature= is unset: the file systemd-stub unpacks
// from the UKI's .pcrsig section into the initramfs (the kernel concatenates the
// stub's synthetic cpio, so it is present with no userspace). Overridable in tests.
var pcrSignatureSearchPaths = []string{
	"/.extra/tpm2-pcr-signature.json",
}

// resolveSignature loads the PCR signature JSON for the tpm2-signature= setting:
// "false" disables signed policy (enabled=false); an explicit path is read (and
// a read error is fatal — the admin asked for it); "" auto-discovers the
// standard locations and, if none exist, returns enabled=false so the caller
// falls through to the next unlock method.
func resolveSignature(opt string) (data []byte, enabled bool, err error) {
	switch {
	case opt == "false":
		return nil, false, nil
	case opt != "":
		data, err := os.ReadFile(opt)
		if err != nil {
			return nil, false, fmt.Errorf("tpm2-signature=%s: %v", opt, err)
		}
		return data, true, nil
	default:
		for _, p := range pcrSignatureSearchPaths {
			if data, err := os.ReadFile(p); err == nil {
				return data, true, nil
			}
		}
		return nil, false, nil
	}
}

// parseSignedToken extracts the signed (authorized) PCR policy fields from a
// systemd-tpm2 token payload. A token is "signed" when it carries tpm2_pubkey
// (written by `systemd-cryptenroll --tpm2-public-key`); such a token's sealed
// blob is bound to the key via TPM2_PolicyAuthorize rather than to literal PCR
// values, so the same blob keeps unsealing across kernel updates as long as a
// valid signature for the current PCRs is available.
//
// ok is false with a nil error when the token has no tpm2_pubkey — i.e. it is a
// literal-PCR token that the existing unseal path handles.
func parseSignedToken(payload []byte) (pub *rsa.PublicKey, pubkeyPCRs []int, ok bool, err error) {
	var node struct {
		Pubkey     string `json:"tpm2_pubkey"`
		PubkeyPCRs []int  `json:"tpm2_pubkey_pcrs"`
	}
	if err := json.Unmarshal(payload, &node); err != nil {
		return nil, nil, false, err
	}
	if node.Pubkey == "" {
		return nil, nil, false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(node.Pubkey)
	if err != nil {
		return nil, nil, false, fmt.Errorf("tpm2_pubkey: %v", err)
	}
	// systemd-cryptenroll stores the public key PEM-encoded (the token field is
	// base64 of the PEM text, decoded with PEM_read_PUBKEY); accept a raw DER
	// body too so callers that pass DER still work.
	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		der = block.Bytes
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, false, fmt.Errorf("tpm2_pubkey: %v", err)
	}
	rsaKey, isRSA := key.(*rsa.PublicKey)
	if !isRSA {
		// systemd's signed-policy verify path is RSA-only.
		return nil, nil, false, fmt.Errorf("tpm2_pubkey: unsupported key type %T (only RSA)", key)
	}
	return rsaKey, node.PubkeyPCRs, true, nil
}

// pcrSignature is one entry of systemd's PCR signature JSON (produced by
// systemd-measure). The top-level document maps a bank name ("sha256", …) to a
// list of these. Sig is standard base64 in the JSON and decodes into []byte
// automatically via encoding/json.
type pcrSignature struct {
	PCRs []int  `json:"pcrs"`
	Pkfp string `json:"pkfp"` // hex SHA256 of the PKCS#1 DER public key
	Pol  string `json:"pol"`  // hex of the signed PolicyPCR digest
	Sig  []byte `json:"sig"`  // RSA (RSASSA, SHA256) signature over Pol
}

// parseSignatureJSON parses systemd's {bank: [pcrSignature, …]} signature file.
func parseSignatureJSON(data []byte) (map[string][]pcrSignature, error) {
	var m map[string][]pcrSignature
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("PCR signature JSON: %v", err)
	}
	return m, nil
}

// rsaPublicKeyFingerprint returns systemd's "pkfp": the lowercase hex SHA256 of
// the PKCS#1 DER ("i2d_PublicKey") encoding of the RSA public key — NOT the SPKI
// form. This is what the signature entries are keyed by.
func rsaPublicKeyFingerprint(pub *rsa.PublicKey) string {
	sum := sha256.Sum256(x509.MarshalPKCS1PublicKey(pub))
	return hex.EncodeToString(sum[:])
}

// selectSignature returns the signature entry for bank whose public-key
// fingerprint matches pub and whose signed policy digest equals polDigest (the
// PolicyPCR digest computed for the current PCR values).
func selectSignature(sigs map[string][]pcrSignature, bank string, pub *rsa.PublicKey, polDigest []byte) (pcrSignature, error) {
	fp := rsaPublicKeyFingerprint(pub)
	want := hex.EncodeToString(polDigest)
	for _, e := range sigs[bank] {
		if strings.EqualFold(e.Pkfp, fp) && strings.EqualFold(e.Pol, want) {
			return e, nil
		}
	}
	return pcrSignature{}, fmt.Errorf("no PCR signature for bank %q matching key %s and policy %s", bank, fp, want)
}

// rsaPublicArea builds the TPM public area for an external RSA verification key,
// matching how systemd loads the signed-policy public key: SHA256 name algorithm,
// NULL scheme and symmetric, sign+decrypt+userWithAuth. The TPM derives the key
// Name from these exact fields, and that Name feeds the PolicyAuthorize digest, so
// it must byte-match systemd's. The RSA exponent is encoded ambiguously across TPM
// implementations: callers try 0x10001, then 0, because the Name differs between them.
func rsaPublicArea(pub *rsa.PublicKey, exponent uint32) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:  true,
			Decrypt:      true,
			UserWithAuth: true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
			Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
			Scheme:    tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
			KeyBits:   tpm2.TPMIRSAKeyBits(pub.N.BitLen()),
			Exponent:  exponent,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{
			Buffer: pub.N.Bytes(),
		}),
	}
}

// rsassaSHA256Sig wraps a raw RSA signature as a TPMT_SIGNATURE (RSASSA, SHA256)
// — the scheme systemd signs PCR policies with.
func rsassaSHA256Sig(sig []byte) tpm2.TPMTSignature {
	return tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgRSASSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgRSASSA, &tpm2.TPMSSignatureRSA{
			Hash: tpm2.TPMAlgSHA256,
			Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: sig},
		}),
	}
}

func flushHandle(t transport.TPM, h tpm2.TPMHandle) {
	_, _ = (&tpm2.FlushContext{FlushHandle: h}).Execute(t)
}

// signedTPM2Unseal unseals a blob whose authPolicy is PolicyAuthorize(verifyKey)
// — i.e. enrolled by systemd-cryptenroll --tpm2-public-key. It satisfies the
// authorized policy at runtime with a signature (from the systemd PCR signature
// JSON) over the *current* PolicyPCR digest, so the same blob keeps unsealing
// across kernel updates as long as a fresh signature for the new PCRs exists.
//
// bankName is systemd's bank string ("sha256", …); srk is the loaded storage
// parent the blob was sealed under. literalPCRs are any plain (unsigned) PCRs the
// token also binds (tpm2-pcrs, e.g. 7 or the 15 latch): systemd composes them as
// a PolicyPCR after the PolicyAuthorize, so the volume key can bind both a signed
// PCR 11 and literal PCRs in one token.
func signedTPM2Unseal(t transport.TPM, srk tpm2.NamedHandle, public tpm2.TPM2BPublic, private tpm2.TPM2BPrivate, verifyKey *rsa.PublicKey, pubkeyPCRs, literalPCRs []int, bankName string, sigJSON []byte, pin []byte) ([]byte, error) {
	if bankName == "" {
		return nil, fmt.Errorf("systemd-tpm2 token has no PCR bank")
	}
	sigs, err := parseSignatureJSON(sigJSON)
	if err != nil {
		return nil, err
	}

	loadRsp, err := (&tpm2.Load{ParentHandle: srk, InPrivate: private, InPublic: public}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("loading sealed object: %v", err)
	}
	defer flushHandle(t, loadRsp.ObjectHandle)
	obj := tpm2.NamedHandle{Handle: loadRsp.ObjectHandle, Name: loadRsp.Name}

	// The RSA exponent is encoded ambiguously across TPM implementations and it
	// feeds the key Name that PolicyAuthorize checks, so try 0x10001 then 0.
	var lastErr error
	for _, exp := range []uint32{0x10001, 0} {
		out, err := signedUnsealAttempt(t, obj, sigs, bankName, verifyKey, exp, pubkeyPCRs, literalPCRs, pin)
		if err == nil {
			return out, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func signedUnsealAttempt(t transport.TPM, obj tpm2.NamedHandle, sigs map[string][]pcrSignature, bankName string, verifyKey *rsa.PublicKey, exp uint32, pubkeyPCRs, literalPCRs []int, pin []byte) ([]byte, error) {
	// With a PIN, the session carries the object's auth value so the trailing
	// PolicyAuthValue (composed after PolicyAuthorize, matching systemd) is satisfied.
	var sessOpts []tpm2.AuthOption
	if len(pin) > 0 {
		sessOpts = append(sessOpts, tpm2.Auth(pin))
	}
	sess, cleanup, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, sessOpts...)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	pcrsU := make([]uint, len(pubkeyPCRs))
	for i, p := range pubkeyPCRs {
		pcrsU[i] = uint(p)
	}
	sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      pcrBankAlgID(bankName),
		PCRSelect: tpm2.PCClientCompatible.PCRs(pcrsU...),
	}}}
	if _, err := (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel}).Execute(t); err != nil {
		return nil, fmt.Errorf("PolicyPCR: %v", err)
	}

	pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(t)
	if err != nil {
		return nil, err
	}
	approved := pgd.PolicyDigest.Buffer

	entry, err := selectSignature(sigs, bankName, verifyKey, approved)
	if err != nil {
		return nil, err
	}

	le, err := (&tpm2.LoadExternal{InPublic: tpm2.New2B(rsaPublicArea(verifyKey, exp)), Hierarchy: tpm2.TPMRHOwner}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("loading verification key: %v", err)
	}
	defer flushHandle(t, le.ObjectHandle)

	h := sha256.Sum256(approved)
	vs, err := (&tpm2.VerifySignature{
		KeyHandle: le.ObjectHandle,
		Digest:    tpm2.TPM2BDigest{Buffer: h[:]},
		Signature: rsassaSHA256Sig(entry.Sig),
	}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("verifying PCR signature: %v", err)
	}

	if _, err := (&tpm2.PolicyAuthorize{
		PolicySession:  sess.Handle(),
		ApprovedPolicy: tpm2.TPM2BDigest{Buffer: approved},
		PolicyRef:      tpm2.TPM2BDigest{},
		KeySign:        le.Name,
		CheckTicket:    vs.Validation,
	}).Execute(t); err != nil {
		return nil, fmt.Errorf("PolicyAuthorize: %v", err)
	}

	// Literal (unsigned) PCRs are a plain PolicyPCR after the PolicyAuthorize,
	// matching systemd's order (PolicyAuthorize → PolicyPCR → PolicyAuthValue);
	// the live PCR values must equal what the token was sealed against.
	if len(literalPCRs) > 0 {
		lpcrsU := make([]uint, len(literalPCRs))
		for i, p := range literalPCRs {
			lpcrsU[i] = uint(p)
		}
		lsel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash:      pcrBankAlgID(bankName),
			PCRSelect: tpm2.PCClientCompatible.PCRs(lpcrsU...),
		}}}
		if _, err := (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: lsel}).Execute(t); err != nil {
			return nil, fmt.Errorf("PolicyPCR (literal): %v", err)
		}
	}

	if len(pin) > 0 {
		if _, err := (&tpm2.PolicyAuthValue{PolicySession: sess.Handle()}).Execute(t); err != nil {
			return nil, fmt.Errorf("PolicyAuthValue: %v", err)
		}
	}

	unseal, err := (&tpm2.Unseal{ItemHandle: tpm2.AuthHandle{
		Handle: obj.Handle,
		Name:   obj.Name,
		Auth:   sess,
	}}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("unseal: %v", err)
	}
	return unseal.OutData.Buffer, nil
}

// pcrBankAlgID maps a systemd tpm2-pcr-bank string to its TPM algorithm id,
// defaulting to SHA-256 (systemd's default bank).
func pcrBankAlgID(s string) tpm2.TPMAlgID {
	switch s {
	case "sha1":
		return tpm2.TPMAlgSHA1
	case "sha384":
		return tpm2.TPMAlgSHA384
	case "sha512":
		return tpm2.TPMAlgSHA512
	}
	return tpm2.TPMAlgSHA256
}

// loadSignedSRK resolves the storage parent the sealed blob lives under. A
// non-zero srkHandle is the persistent SRK (systemd v252+ tokens) — read its
// Name. A zero handle means derive the standard transient primary; the returned
// cleanup flushes it.
func loadSignedSRK(t transport.TPM, srkHandle uint32) (tpm2.NamedHandle, func(), error) {
	noop := func() {}
	if srkHandle != 0 {
		rp, err := (&tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(srkHandle)}).Execute(t)
		if err != nil {
			return tpm2.NamedHandle{}, noop, fmt.Errorf("reading SRK %#x: %v", srkHandle, err)
		}
		return tpm2.NamedHandle{Handle: tpm2.TPMHandle(srkHandle), Name: rp.Name}, noop, nil
	}
	cp, err := (&tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(t)
	if err != nil {
		return tpm2.NamedHandle{}, noop, fmt.Errorf("creating SRK: %v", err)
	}
	return tpm2.NamedHandle{Handle: cp.ObjectHandle, Name: cp.Name}, func() { flushHandle(t, cp.ObjectHandle) }, nil
}

// recoverSignedTPM2Password unseals a signed-policy systemd-tpm2 token. The
// caller supplies the parsed blob sections, SRK handle, bank, signing key, and
// the PIN auth value (nil when the token has no PIN); this builds the new-API
// types, opens the TPM, and runs the PolicyAuthorize unseal. Returns the raw
// volume key (the caller base64-encodes, matching the literal path).
func recoverSignedTPM2Password(public, private []byte, pcrBankName string, pubkeyPCRs, literalPCRs []int, verifyKey *rsa.PublicKey, srkHandle uint32, tpm2Signature string, pinAuth []byte) ([]byte, error) {
	sigJSON, enabled, err := resolveSignature(tpm2Signature)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, fmt.Errorf("signed systemd-tpm2 token but no PCR signature found (set tpm2-signature= or provide tpm2-pcr-signature.json)")
	}

	pubArea, err := tpm2.Unmarshal[tpm2.TPMTPublic](public)
	if err != nil {
		return nil, fmt.Errorf("parsing sealed object public area: %v", err)
	}

	dev, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer dev.Close()
	thetpm := transport.FromReadWriteCloser(dev)

	srk, flush, err := loadSignedSRK(thetpm, srkHandle)
	if err != nil {
		return nil, err
	}
	defer flush()

	key, err := signedTPM2Unseal(thetpm, srk, tpm2.New2B(*pubArea), tpm2.TPM2BPrivate{Buffer: private}, verifyKey, pubkeyPCRs, literalPCRs, pcrBankName, sigJSON, pinAuth)
	if err != nil {
		return nil, err
	}
	return key, nil
}
