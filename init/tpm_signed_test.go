package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

// Testing scope for the signed-policy path — read before trusting a green run.
//
// These swtpm tests prove two things faithfully: the TPM protocol chain
// (PolicyAuthorize -> VerifySignature over SHA256(approved) -> PolicyPCR ->
// PolicyAuthValue, the cross-PCR-change no-re-enroll property, tamper rejection,
// the RSA exponent retry) and the initrd boot timeline, which they model by
// manually extending the phase words booster uses (extendPhasePCR11, byte-checked
// against measurePhaseToPCR11 in TestMeasurePhaseToPCR11).
//
// They are deliberately NOT a substitute for two things swtpm cannot supply:
//
//  1. Byte-level interop with real systemd artifacts. Tests that build their own
//     token and sign their own policy are self-consistent — they match by
//     construction and cannot catch drift from a real systemd-cryptenroll token
//     or ukify .pcrsig (this is how the base64(PEM) tpm2_pubkey bug slipped past
//     a green suite). Real-artifact coverage lives in TestParseRealSystemdArtifacts
//     against init/testdata/systemd260-*.json.
//
//  2. The measured-boot software stack. swtpm is a faithful TPM but runs no
//     systemd-stub (UKI sections measured into PCR 11), no systemd-pcrphase, and
//     no systemd-pcrmachine/pcrfs (PCR 15 system-identity). A signed PCR 11
//     binding against a real UKI's measured value therefore cannot be exercised
//     here or in the QEMU harness (it boots a kernel directly, not a UKI). That
//     layer is validated only on real UKI hardware; the evidence is the boot-log
//     trace (enter-initrd barrier -> systemd-tpm2 token recovered, no fallback),
//     not a CI run.

func TestParseSignedToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	// Real systemd-cryptenroll format: tpm2_pubkey is base64 of the *PEM* text
	// (systemd stores the PEM and reads it back with PEM_read_PUBKEY). This is the
	// case a real on-disk token exercises.
	pemB64 := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	signed := []byte(`{"tpm2_pubkey":"` + pemB64 + `","tpm2_pubkey_pcrs":[11]}`)
	pub, pcrs, ok, err := parseSignedToken(signed)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []int{11}, pcrs)
	require.Equal(t, key.PublicKey.N, pub.N)
	require.Equal(t, key.PublicKey.E, pub.E)

	// Robustness: a raw-DER body (no PEM wrapper) is also accepted.
	derB64 := base64.StdEncoding.EncodeToString(spki)
	pub2, _, ok2, err := parseSignedToken([]byte(`{"tpm2_pubkey":"` + derB64 + `","tpm2_pubkey_pcrs":[11]}`))
	require.NoError(t, err)
	require.True(t, ok2)
	require.Equal(t, key.PublicKey.N, pub2.N)

	// Literal-PCR token: no tpm2_pubkey -> not signed (handled by the legacy path).
	literal := []byte(`{"tpm2-pcrs":[7]}`)
	_, _, ok, err = parseSignedToken(literal)
	require.NoError(t, err)
	require.False(t, ok)

	// Malformed base64 pubkey -> error.
	_, _, _, err = parseSignedToken([]byte(`{"tpm2_pubkey":"!!notb64!!"}`))
	require.Error(t, err)
}

// TestParseRealSystemdArtifacts runs booster's signed-policy parsers against
// fixtures captured from a REAL `systemd-cryptenroll --tpm2-public-key` token and
// a REAL ukify/systemd-measure `.pcrsig` (systemd 260, in init/testdata/). Unlike
// the synthetic tests, the input is bytes systemd actually wrote, so it catches
// interop format drift — it is exactly the test that would have caught the
// base64-of-PEM tpm2_pubkey bug that the DER-based synthetic test masked.
func TestParseRealSystemdArtifacts(t *testing.T) {
	tokenJSON, err := os.ReadFile("testdata/systemd260-signed-token.json")
	require.NoError(t, err)
	sigJSON, err := os.ReadFile("testdata/systemd260-pcrsig.json")
	require.NoError(t, err)

	// 1. the real token is recognized as signed and bound to PCR 11.
	pub, pubkeyPCRs, ok, err := parseSignedToken(tokenJSON)
	require.NoError(t, err, "real systemd tpm2_pubkey (base64 of PEM) must parse")
	require.True(t, ok)
	require.Equal(t, []int{11}, pubkeyPCRs)

	// 2. the literal PCR fields (hyphenated json tags) parse from the real token.
	var node struct {
		PCRs    []int  `json:"tpm2-pcrs"`
		PCRBank string `json:"tpm2-pcr-bank"`
	}
	require.NoError(t, json.Unmarshal(tokenJSON, &node))
	require.Equal(t, []int{7, 15}, node.PCRs)
	require.Equal(t, "sha256", node.PCRBank)

	// 3. the real signature parses, and the key booster decoded produces the same
	//    fingerprint systemd wrote into the .pcrsig (end-to-end pubkey+pkfp match).
	sigs, err := parseSignatureJSON(sigJSON)
	require.NoError(t, err)
	require.Len(t, sigs["sha256"], 4, "ukify default phase set is 4 sha256 entries")
	require.Equal(t, sigs["sha256"][0].Pkfp, rsaPublicKeyFingerprint(pub),
		"booster's key fingerprint must match systemd's pkfp in the real signature")

	// 4. selectSignature finds the real entry for the real key + its policy digest.
	pol, err := hex.DecodeString(sigs["sha256"][0].Pol)
	require.NoError(t, err)
	entry, err := selectSignature(sigs, "sha256", pub, pol)
	require.NoError(t, err)
	require.Equal(t, []int{11}, entry.PCRs)
	require.NotEmpty(t, entry.Sig)
}

func TestSelectSignature(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	fp := rsaPublicKeyFingerprint(&key.PublicKey)
	pol := sha256.Sum256([]byte("policy"))
	polHex := hex.EncodeToString(pol[:])

	// "YWJj" == base64("abc")
	js := []byte(`{"sha256":[{"pcrs":[11],"pkfp":"` + fp + `","pol":"` + polHex + `","sig":"YWJj"}]}`)
	sigs, err := parseSignatureJSON(js)
	require.NoError(t, err)

	e, err := selectSignature(sigs, "sha256", &key.PublicKey, pol[:])
	require.NoError(t, err)
	require.Equal(t, []int{11}, e.PCRs)
	require.Equal(t, []byte("abc"), e.Sig)

	// Wrong policy digest -> no match.
	other := sha256.Sum256([]byte("other"))
	_, err = selectSignature(sigs, "sha256", &key.PublicKey, other[:])
	require.Error(t, err)

	// Wrong bank -> no match.
	_, err = selectSignature(sigs, "sha384", &key.PublicKey, pol[:])
	require.Error(t, err)
}

func TestResolveSignature(t *testing.T) {
	dir := t.TempDir()
	sig := filepath.Join(dir, "sig.json")
	require.NoError(t, os.WriteFile(sig, []byte(`{"sha256":[]}`), 0600))

	// "false" -> disabled.
	_, enabled, err := resolveSignature("false")
	require.NoError(t, err)
	require.False(t, enabled)

	// Explicit path -> read it.
	data, enabled, err := resolveSignature(sig)
	require.NoError(t, err)
	require.True(t, enabled)
	require.Contains(t, string(data), "sha256")

	// Explicit missing path -> error.
	_, _, err = resolveSignature(filepath.Join(dir, "nope.json"))
	require.Error(t, err)

	old := pcrSignatureSearchPaths
	defer func() { pcrSignatureSearchPaths = old }()

	// Auto-discover finds the second candidate.
	pcrSignatureSearchPaths = []string{filepath.Join(dir, "nope.json"), sig}
	data, enabled, err = resolveSignature("")
	require.NoError(t, err)
	require.True(t, enabled)
	require.Contains(t, string(data), "sha256")

	// Auto-discover finds nothing -> not enabled, no error (caller falls through).
	pcrSignatureSearchPaths = []string{filepath.Join(dir, "nope.json")}
	_, enabled, err = resolveSignature("")
	require.NoError(t, err)
	require.False(t, enabled)
}

func TestRSAPublicArea(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// The RSA exponent is encoded ambiguously across TPM implementations, so the
	// two forms (0x10001 and 0) yield different key Names — the reason the unseal
	// path retries with 0 when the first Name doesn't match.
	require.NotEqual(t,
		tpm2.Marshal(rsaPublicArea(&key.PublicKey, 0x10001)),
		tpm2.Marshal(rsaPublicArea(&key.PublicKey, 0)))
}

// signedTestSecret is the volume key the signed-policy unseal tests seal and
// expect back.
const signedTestSecret = "super-secret-volume-key-0123456"

// signedRig is the shared swtpm fixture for the signed-policy unseal tests: a TPM
// connection, a transient SRK, and an external RSA signing key standing in for the
// user's --tpm2-public-key. The key's Name (exponent 0x10001, the first form
// signedTPM2Unseal tries) feeds the PolicyAuthorize the tests seal under.
// Per-test scenario — which policy, PIN, and PCRs — stays in each test.
type signedRig struct {
	t       *testing.T
	tpm     transport.TPM
	srk     tpm2.NamedHandle
	priv    *rsa.PrivateKey
	keyName tpm2.TPM2BName
}

func newSignedRig(t *testing.T) *signedRig {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	dev, err := openTPM()
	require.NoError(t, err)
	t.Cleanup(func() { dev.Close() })
	thetpm := transport.FromReadWriteCloser(dev)

	srkRsp, err := (&tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(thetpm)
	require.NoError(t, err)
	t.Cleanup(func() { flushHandle(thetpm, srkRsp.ObjectHandle) })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	le, err := (&tpm2.LoadExternal{InPublic: tpm2.New2B(rsaPublicArea(&key.PublicKey, 0x10001)), Hierarchy: tpm2.TPMRHOwner}).Execute(thetpm)
	require.NoError(t, err)
	flushHandle(thetpm, le.ObjectHandle)

	return &signedRig{
		t:       t,
		tpm:     thetpm,
		srk:     tpm2.NamedHandle{Handle: srkRsp.ObjectHandle, Name: srkRsp.Name},
		priv:    key,
		keyName: le.Name,
	}
}

func (r *signedRig) pub() *rsa.PublicKey { return &r.priv.PublicKey }

// authorizePolicy returns the digest for PolicyAuthorize(key) followed by any
// extra policy steps in order (e.g. PolicyAuthValue, PolicyPCR) — the authPolicy a
// blob is sealed under.
func (r *signedRig) authorizePolicy(extra ...func(*tpm2.PolicyCalculator)) []byte {
	pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	require.NoError(r.t, err)
	require.NoError(r.t, (&tpm2.PolicyAuthorize{KeySign: r.keyName, PolicyRef: tpm2.TPM2BDigest{}}).Update(pol))
	for _, step := range extra {
		step(pol)
	}
	return pol.Hash().Digest
}

// seal creates a keyedhash object holding signedTestSecret under authPolicy, with
// pin as its auth value (nil for none).
func (r *signedRig) seal(authPolicy, pin []byte) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate) {
	sens := &tpm2.TPMSSensitiveCreate{Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: []byte(signedTestSecret)})}
	if len(pin) > 0 {
		sens.UserAuth = tpm2.TPM2BAuth{Buffer: pin}
	}
	rsp, err := (&tpm2.Create{
		ParentHandle: r.srk,
		InSensitive:  tpm2.TPM2BSensitiveCreate{Sensitive: sens},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true},
			AuthPolicy:       tpm2.TPM2BDigest{Buffer: authPolicy},
		}),
	}).Execute(r.tpm)
	require.NoError(r.t, err)
	return rsp.OutPublic, rsp.OutPrivate
}

// policyPCRDigest is the live PolicyPCR digest over pcr in the sha256 bank — the
// value signedTPM2Unseal computes and selects a signature for.
func (r *signedRig) policyPCRDigest(pcr int) []byte {
	sess, cleanup, err := tpm2.PolicySession(r.tpm, tpm2.TPMAlgSHA256, 16)
	require.NoError(r.t, err)
	defer cleanup()
	sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcr)),
	}}}
	_, err = (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel}).Execute(r.tpm)
	require.NoError(r.t, err)
	pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(r.tpm)
	require.NoError(r.t, err)
	return pgd.PolicyDigest.Buffer
}

// signPolicy signs approved with the rig key (RSASSA over SHA256(approved),
// systemd's convention). sigJSON wraps a signature in systemd's signature JSON.
func (r *signedRig) signPolicy(approved []byte) []byte {
	hh := sha256.Sum256(approved)
	sig, err := rsa.SignPKCS1v15(rand.Reader, r.priv, crypto.SHA256, hh[:])
	require.NoError(r.t, err)
	return sig
}

func (r *signedRig) sigJSON(pcr int, approved, sig []byte) []byte {
	return []byte(fmt.Sprintf(`{"sha256":[{"pcrs":[%d],"pkfp":"%s","pol":"%s","sig":"%s"}]}`,
		pcr, rsaPublicKeyFingerprint(r.pub()), hex.EncodeToString(approved), base64.StdEncoding.EncodeToString(sig)))
}

// TestSignedUnsealSurvivesPCRChange is the headline proof: a blob whose authPolicy
// is PolicyAuthorize(key) unseals with a signature over the current PCR policy, and
// the SAME blob still unseals after a bound PCR changes (a kernel update) given a
// fresh signature — i.e. no re-enrollment. A tampered signature must fail.
func TestSignedUnsealSurvivesPCRChange(t *testing.T) {
	r := newSignedRig(t)
	pub, priv := r.seal(r.authorizePolicy(), nil)

	const debugPCR = 16
	pubkeyPCRs := []int{debugPCR}

	// 1. Unseal at the current PCR state.
	pol1 := r.policyPCRDigest(debugPCR)
	out, err := signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, nil, "sha256", r.sigJSON(debugPCR, pol1, r.signPolicy(pol1)), nil)
	require.NoError(t, err)
	require.Equal(t, []byte(signedTestSecret), out)

	// 2. Change the bound PCR (a kernel update), re-sign — the SAME blob still unseals.
	_, err = (&tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(debugPCR), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
			HashAlg: tpm2.TPMAlgSHA256, Digest: bytes.Repeat([]byte{0xab}, 32),
		}}},
	}).Execute(r.tpm)
	require.NoError(t, err)
	pol2 := r.policyPCRDigest(debugPCR)
	require.NotEqual(t, pol1, pol2, "extending the bound PCR must change the policy")
	out, err = signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, nil, "sha256", r.sigJSON(debugPCR, pol2, r.signPolicy(pol2)), nil)
	require.NoError(t, err)
	require.Equal(t, []byte(signedTestSecret), out, "same blob must unseal after the PCR change with a fresh signature")

	// 3. A tampered signature must not unseal.
	bad := r.signPolicy(pol2)
	bad[0] ^= 0xff
	_, err = signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, nil, "sha256", r.sigJSON(debugPCR, pol2, bad), nil)
	require.Error(t, err, "a tampered signature must not unseal")
}

// TestSignedUnsealWithPIN covers a signed policy combined with a PIN
// (TPM+PIN+PCR): the blob's authPolicy is PolicyAuthorize(key) then
// PolicyAuthValue, and the object carries the PIN as its auth value. The
// correct PIN unseals; a wrong PIN does not.
func TestSignedUnsealWithPIN(t *testing.T) {
	r := newSignedRig(t)
	pin := []byte("1234")
	// authPolicy = PolicyAuthorize(key) THEN PolicyAuthValue — systemd's order.
	authPolicy := r.authorizePolicy(func(pc *tpm2.PolicyCalculator) {
		require.NoError(t, (&tpm2.PolicyAuthValue{}).Update(pc))
	})
	pub, priv := r.seal(authPolicy, pin)

	const debugPCR = 16
	pubkeyPCRs := []int{debugPCR}
	approved := r.policyPCRDigest(debugPCR)
	sig := r.sigJSON(debugPCR, approved, r.signPolicy(approved))

	// Correct PIN unseals.
	out, err := signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, nil, "sha256", sig, pin)
	require.NoError(t, err)
	require.Equal(t, []byte(signedTestSecret), out)

	// Wrong PIN does not.
	_, err = signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, nil, "sha256", sig, []byte("9999"))
	require.Error(t, err, "a wrong PIN must not unseal")
}

// sigJSONEntries builds a systemd PCR signature JSON with multiple (approved
// policy digest, signature) entries for one bank/pcr — modeling a signature file
// that covers more than one boot phase.
func sigJSONEntries(pub *rsa.PublicKey, pcr int, entries [][2][]byte) []byte {
	fp := rsaPublicKeyFingerprint(pub)
	inner := ""
	for i, e := range entries {
		if i > 0 {
			inner += ","
		}
		inner += fmt.Sprintf(`{"pcrs":[%d],"pkfp":"%s","pol":"%s","sig":"%s"}`,
			pcr, fp, hex.EncodeToString(e[0]), base64.StdEncoding.EncodeToString(e[1]))
	}
	return []byte(fmt.Sprintf(`{"sha256":[%s]}`, inner))
}

// TestLeaveInitrdForwardLockDefeatedByDefaultPhaseSignature demonstrates the
// limit of the PCR11 leave-initrd forward-lock against a SIGNED policy: it only
// locks the key when the signature is restricted to the enter-initrd phase.
//
// systemd-measure's default --phases signs the progression enter-initrd,
// enter-initrd:leave-initrd, …:sysinit, …:ready. So the signature file (readable,
// in the UKI) contains an entry for the enter-initrd:leave-initrd state — exactly
// the PCR11 value L that applyBootPhaseForwardLock advances to. selectSignature
// matches the live PCR11, so at L it finds that entry and the key unseals: the
// forward-lock does NOT deny it. Only an enter-initrd-restricted signature leaves
// L unsigned, so advancing to L makes the key unreachable.
//
// This is why a literal PCR15 latch (bound to the all-zero value, which no
// signature can satisfy once dirtied) is the robust LUKS forward-lock, while the
// phase lock depends on how the UKI was signed.
func TestLeaveInitrdForwardLockDefeatedByDefaultPhaseSignature(t *testing.T) {
	r := newSignedRig(t)
	pub, priv := r.seal(r.authorizePolicy(), nil)
	pubkeyPCRs := []int{pcrKernelBoot}

	// Genuine initrd reaches the enter-initrd phase (PCR11 == E); sign that state.
	extendPhasePCR11(t, r.tpm, phaseEnterInitrd)
	polE := r.policyPCRDigest(pcrKernelBoot)
	sigE := r.signPolicy(polE)

	// The forward-lock advances to leave-initrd (PCR11 == L). Sign that state too,
	// as systemd-measure's default phases do.
	extendPhasePCR11(t, r.tpm, phaseLeaveInitrd)
	polL := r.policyPCRDigest(pcrKernelBoot)
	sigL := r.signPolicy(polL)
	require.NotEqual(t, polE, polL, "enter-initrd and leave-initrd must be distinct PCR11 states")

	// PCR11 is now at L — exactly where applyBootPhaseForwardLock leaves it before
	// handing off to the attacker's init.

	// Default-phase signature (E and L both signed): the post-pivot init at L finds
	// the leave-initrd entry, so the key UNSEALS — the forward-lock is defeated.
	defaultSig := sigJSONEntries(r.pub(), pcrKernelBoot, [][2][]byte{{polE, sigE}, {polL, sigL}})
	out, err := signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, nil, "sha256", defaultSig, nil)
	require.NoError(t, err,
		"default full-phase signature signs the leave-initrd state, so advancing PCR11 to L does NOT deny the key")
	require.Equal(t, []byte(signedTestSecret), out, "key leaks at L when leave-initrd is among the signed phases")

	// enter-initrd-restricted signature (only E signed): at L no signature matches
	// the live PCR11, so the key is DENIED — the forward-lock actually locks.
	restrictedSig := sigJSONEntries(r.pub(), pcrKernelBoot, [][2][]byte{{polE, sigE}})
	_, err = signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, nil, "sha256", restrictedSig, nil)
	require.Error(t, err,
		"with an enter-initrd-restricted signature, no entry matches PCR11 == L, so the forward-lock denies the key")
}

// TestPCR15LatchDeniesAtLeaveInitrd pins that the literal PCR15 latch denies
// the key in the case the PCR11 phase walk does not — a default-phase signature
// where the leave-initrd state (PCR11 == L) is itself signed.
//
// The key binds signed PCR11 (PolicyAuthorize) AND literal PCR15 == 0 — the
// recommended 7+11+15 shape minus PCR7 (which swtpm can't measure). At PCR11 == L
// the leave-initrd signature satisfies the signed half, so the key unseals (see
// TestLeaveInitrdForwardLockDefeatedByDefaultPhaseSignature). Once PCR15 is
// dirtied, the literal 15 == 0 clause no longer holds — no signature can satisfy
// a literal PCR — so the same unseal is denied.
func TestPCR15LatchDeniesAtLeaveInitrd(t *testing.T) {
	r := newSignedRig(t)

	const literalPCR = pcrSystemIdentity // 15
	sel15 := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(uint(literalPCR)),
	}}}
	composite := sha256.Sum256(make([]byte, 32)) // PolicyPCR digest for an all-zero PCR15
	authPolicy := r.authorizePolicy(func(pc *tpm2.PolicyCalculator) {
		require.NoError(t, (&tpm2.PolicyPCR{Pcrs: sel15, PcrDigest: tpm2.TPM2BDigest{Buffer: composite[:]}}).Update(pc))
	})
	pub, priv := r.seal(authPolicy, nil)

	pubkeyPCRs := []int{pcrKernelBoot}
	literalPCRs := []int{literalPCR}

	// Default-phase signature: BOTH enter-initrd (E) and leave-initrd (L) signed.
	extendPhasePCR11(t, r.tpm, phaseEnterInitrd)
	polE := r.policyPCRDigest(pcrKernelBoot)
	sigE := r.signPolicy(polE)
	extendPhasePCR11(t, r.tpm, phaseLeaveInitrd)
	polL := r.policyPCRDigest(pcrKernelBoot)
	sigL := r.signPolicy(polL)
	defaultSig := sigJSONEntries(r.pub(), pcrKernelBoot, [][2][]byte{{polE, sigE}, {polL, sigL}})

	// PCR11 at L (forward-locked) and PCR15 still 0: the leave-initrd signature
	// satisfies the signed half, so the key UNSEALS — the hole the phase lock can't
	// close.
	out, err := signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, literalPCRs, "sha256", defaultSig, nil)
	require.NoError(t, err, "at PCR11 == L with leave-initrd signed, the signed half is satisfiable")
	require.Equal(t, []byte(signedTestSecret), out, "the phase lock alone does not deny the key here")

	// The PCR15 latch dirties PCR15 (any extension breaks the literal 15 == 0).
	// Extended on the shared connection, as measureVolumeKeyToPCR15 would in the
	// initrd. Now the key is DENIED at L despite the valid leave-initrd signature.
	d := sha256.Sum256([]byte("cryptsetup:cryptroot:uuid"))
	_, err = (&tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(literalPCR), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d[:]}}},
	}).Execute(r.tpm)
	require.NoError(t, err)
	_, err = signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, literalPCRs, "sha256", defaultSig, nil)
	require.Error(t, err,
		"once PCR15 is dirtied, the literal 15 == 0 clause denies the key even though leave-initrd is signed")
}

// extendPhasePCR11 extends PCR 11 with a phase word on the shared test TPM
// connection, byte-identical to measurePhaseToPCR11 (SHA256(word), proven in
// TestMeasurePhaseToPCR11). Used to model the initrd timeline without opening the
// barrier's own connection to the single-client swtpm.
func extendPhasePCR11(t *testing.T, thetpm transport.TPM, word string) {
	t.Helper()
	d := sha256.Sum256([]byte(word))
	_, err := (&tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcrKernelBoot), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d[:]}}},
	}).Execute(thetpm)
	require.NoError(t, err)
}

// TestSignedUnsealWithLiteralPCRComposition pins the combined token: a signed
// PCR 11 policy AND a literal PCR (here PCR 15, the latch) in one token. systemd
// composes them as PolicyAuthorize THEN PolicyPCR (src/shared/tpm2-util.c), so
// booster must replay the same order. The blob unseals while the literal PCR
// holds its bound value, and stops once that PCR moves — so the PCR 15 latch,
// firing after unseal, blocks a re-unseal exactly as it does for literal tokens.
func TestSignedUnsealWithLiteralPCRComposition(t *testing.T) {
	r := newSignedRig(t)

	const literalPCR = pcrSystemIdentity // 15, the latch PCR
	sel15 := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(uint(literalPCR)),
	}}}
	// authPolicy = PolicyAuthorize(key) THEN PolicyPCR(15 = uninitialized) — the
	// systemd order. The PCR 15 composite for an all-zero PCR is SHA256(zeros).
	composite := sha256.Sum256(make([]byte, 32))
	authPolicy := r.authorizePolicy(func(pc *tpm2.PolicyCalculator) {
		require.NoError(t, (&tpm2.PolicyPCR{Pcrs: sel15, PcrDigest: tpm2.TPM2BDigest{Buffer: composite[:]}}).Update(pc))
	})
	pub, priv := r.seal(authPolicy, nil)

	pubkeyPCRs := []int{pcrKernelBoot}
	literalPCRs := []int{literalPCR}

	// Sign the signed half (PCR 11 at the enter-initrd value).
	extendPhasePCR11(t, r.tpm, phaseEnterInitrd)
	approved := r.policyPCRDigest(pcrKernelBoot)
	sig := r.sigJSON(pcrKernelBoot, approved, r.signPolicy(approved))

	// Combined unseal succeeds: signed PCR 11 matches, literal PCR 15 still zero.
	out, err := signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, literalPCRs, "sha256", sig, nil)
	require.NoError(t, err)
	require.Equal(t, []byte(signedTestSecret), out, "signed PCR 11 + literal PCR 15 must unseal in one token")

	// The PCR 15 latch fires after unseal. The signed PCR 11 half is unchanged,
	// but the literal PCR 15 binding no longer holds, so a re-unseal is blocked.
	d := sha256.Sum256([]byte("cryptsetup:cryptroot:uuid"))
	_, err = (&tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(literalPCR), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d[:]}}},
	}).Execute(r.tpm)
	require.NoError(t, err)
	_, err = signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, literalPCRs, "sha256", sig, nil)
	require.Error(t, err, "once the PCR 15 latch extends, the literal binding must block re-unseal")
}

// TestSignedUnsealLiteralPCR15MustBindZero is the executable form of the
// enrollment recipe: a literal PCR 15 ("system-identity") binding must use the
// all-zero reset value, not the live value read on a running host.
// systemd-cryptenroll snapshots PCR 15 as it stands when the operator runs it;
// by then systemd-pcrmachine (machine-id) and systemd-pcrfs (filesystem
// identity) have already extended it to a non-zero value. Booster unseals
// earlier — in the initrd, before any of those services run and before its own
// latch fires — so it always presents PCR 15 at zero. A token that bound the
// live (non-zero) value therefore can never be satisfied at unseal; one that
// bound zero can. This pins both directions so a future doc or code change that
// reintroduces a live PCR 15 binding (the `--tpm2-pcrs=15` recipe bug) fails here
// rather than only on real hardware, which swtpm cannot reproduce.
func TestSignedUnsealLiteralPCR15MustBindZero(t *testing.T) {
	r := newSignedRig(t)

	const literalPCR = pcrSystemIdentity // 15
	sel15 := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(uint(literalPCR)),
	}}}
	// sealPCR15 seals the secret under PolicyAuthorize(key) THEN PolicyPCR(15) for
	// the given PCR-15 composite — i.e. what systemd-cryptenroll would compute from
	// the PCR-15 value it reads at enroll.
	sealPCR15 := func(composite []byte) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate) {
		return r.seal(r.authorizePolicy(func(pc *tpm2.PolicyCalculator) {
			require.NoError(t, (&tpm2.PolicyPCR{Pcrs: sel15, PcrDigest: tpm2.TPM2BDigest{Buffer: composite}}).Update(pc))
		}), nil)
	}

	// PCR 15 is at its all-zero reset value here, exactly as booster sees it in the
	// initrd. Sign the signed PCR 11 half so PolicyAuthorize is always satisfied —
	// isolating PCR 15 as the variable.
	pubkeyPCRs := []int{pcrKernelBoot}
	literalPCRs := []int{literalPCR}
	extendPhasePCR11(t, r.tpm, phaseEnterInitrd)
	approved := r.policyPCRDigest(pcrKernelBoot)
	sig := r.sigJSON(pcrKernelBoot, approved, r.signPolicy(approved))

	// Correct recipe — PCR 15 bound to its all-zero reset value (`15:sha256=<zeros>`).
	zero := sha256.Sum256(make([]byte, 32))
	pubZero, privZero := sealPCR15(zero[:])
	out, err := signedTPM2Unseal(r.tpm, r.srk, pubZero, privZero, r.pub(), pubkeyPCRs, literalPCRs, "sha256", sig, nil)
	require.NoError(t, err)
	require.Equal(t, []byte(signedTestSecret), out, "a PCR 15 binding to all-zeros must unseal in the initrd")

	// The recipe bug — `--tpm2-pcrs=15` on a running host snapshots a non-zero
	// PCR 15. Model it as a binding to an arbitrary non-zero value; booster,
	// presenting PCR 15 = 0, must NOT satisfy it.
	live := sha256.Sum256(bytes.Repeat([]byte{0x5a}, 32))
	pubHost, privHost := sealPCR15(live[:])
	_, err = signedTPM2Unseal(r.tpm, r.srk, pubHost, privHost, r.pub(), pubkeyPCRs, literalPCRs, "sha256", sig, nil)
	require.Error(t, err, "a PCR 15 binding to the live (non-zero) host value must NOT unseal when booster presents PCR 15 = 0")
}

// TestSignedUnsealAtEnterInitrdBarrier is the end-to-end proof of the fix, bound
// to the REAL PCR 11. A signed policy is signed for systemd's "enter-initrd"
// boot phase, and systemd unlocks the root only after PCR 11 has been extended
// with that word (systemd-pcrphase-initrd runs Before=cryptsetup.target). Booster
// runs no pcrphase, so it applies the same barrier itself. This test pins both
// halves: a signature for the BARE PCR 11 (what our earlier implementation
// matched) does NOT unseal once the barrier is applied — that was the bug — and a
// signature for the post-barrier enter-initrd value DOES.
func TestSignedUnsealAtEnterInitrdBarrier(t *testing.T) {
	r := newSignedRig(t)
	pub, priv := r.seal(r.authorizePolicy(), nil)

	pubkeyPCRs := []int{pcrKernelBoot} // bind to the REAL PCR 11

	// Signature for the BARE PCR 11 value (pre-barrier) — what the earlier
	// implementation would have matched.
	bare := r.policyPCRDigest(pcrKernelBoot)
	bareSig := r.sigJSON(pcrKernelBoot, bare, r.signPolicy(bare))

	// Extend "enter-initrd" so PCR 11 holds systemd's enter-initrd phase value,
	// exactly as in a real initrd before unlock.
	extendPhasePCR11(t, r.tpm, phaseEnterInitrd)

	// The bare-value signature must NOT unseal now: the barrier advanced PCR 11.
	_, err := signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, nil, "sha256", bareSig, nil)
	require.Error(t, err, "a bare-PCR11 signature must not unseal after the enter-initrd barrier")

	// A signature for the post-barrier (enter-initrd) value unseals — the standard case.
	enter := r.policyPCRDigest(pcrKernelBoot)
	out, err := signedTPM2Unseal(r.tpm, r.srk, pub, priv, r.pub(), pubkeyPCRs, nil, "sha256", r.sigJSON(pcrKernelBoot, enter, r.signPolicy(enter)), nil)
	require.NoError(t, err)
	require.Equal(t, []byte(signedTestSecret), out, "a signature for the enter-initrd PCR11 value must unseal")
}
