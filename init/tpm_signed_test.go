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

	area := rsaPublicArea(&key.PublicKey, 0x10001)
	require.Equal(t, tpm2.TPMAlgRSA, area.Type)
	require.Equal(t, tpm2.TPMAlgSHA256, area.NameAlg)
	require.True(t, area.ObjectAttributes.SignEncrypt)
	require.True(t, area.ObjectAttributes.Decrypt)
	require.True(t, area.ObjectAttributes.UserWithAuth)

	// The modulus is embedded and the area marshals.
	marshaled := tpm2.Marshal(area)
	require.NotEmpty(t, marshaled)
	require.True(t, bytes.Contains(marshaled, key.PublicKey.N.Bytes()), "modulus must be embedded in the public area")

	// Exponent 0x10001 vs 0 marshal differently — the reason the unseal path retries
	// with 0 when the key Name doesn't match.
	require.NotEqual(t,
		tpm2.Marshal(rsaPublicArea(&key.PublicKey, 0x10001)),
		tpm2.Marshal(rsaPublicArea(&key.PublicKey, 0)))
}

// TestSignedUnsealSurvivesPCRChange is the headline proof: a blob whose authPolicy
// is PolicyAuthorize(key) unseals with a signature over the current PCR policy, and
// the SAME blob still unseals after a bound PCR changes (a kernel update) given a
// fresh signature — i.e. no re-enrollment. A tampered signature must fail.
func TestSignedUnsealSurvivesPCRChange(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	dev, err := openTPM()
	require.NoError(t, err)
	defer dev.Close()
	thetpm := transport.FromReadWriteCloser(dev)

	// SRK — a transient primary; stays loaded for this single connection.
	srkRsp, err := (&tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}).Execute(thetpm)
	require.NoError(t, err)
	srk := tpm2.NamedHandle{Handle: srkRsp.ObjectHandle, Name: srkRsp.Name}
	defer flushHandle(thetpm, srkRsp.ObjectHandle)

	// RSA signing key — stands in for the user's --tpm2-public-key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// The key's Name (exp 0x10001 = signedTPM2Unseal's first attempt) feeds the
	// PolicyAuthorize authPolicy the blob is sealed under.
	le, err := (&tpm2.LoadExternal{
		InPublic:  tpm2.New2B(rsaPublicArea(&key.PublicKey, 0x10001)),
		Hierarchy: tpm2.TPMRHOwner,
	}).Execute(thetpm)
	require.NoError(t, err)
	keyName := le.Name
	flushHandle(thetpm, le.ObjectHandle)

	pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	require.NoError(t, (&tpm2.PolicyAuthorize{KeySign: keyName, PolicyRef: tpm2.TPM2BDigest{}}).Update(pol))
	authPolicy := pol.Hash().Digest

	secret := []byte("super-secret-volume-key-0123456")
	createRsp, err := (&tpm2.Create{
		ParentHandle: srk,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
			},
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:    true,
				FixedParent: true,
			},
			AuthPolicy: tpm2.TPM2BDigest{Buffer: authPolicy},
		}),
	}).Execute(thetpm)
	require.NoError(t, err)

	const debugPCR = 16
	pubkeyPCRs := []int{debugPCR}
	bank := tpm2.TPMAlgSHA256

	currentPolicy := func() []byte {
		sess, cleanup, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 16)
		require.NoError(t, err)
		defer cleanup()
		sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash: bank, PCRSelect: tpm2.PCClientCompatible.PCRs(debugPCR),
		}}}
		_, err = (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel}).Execute(thetpm)
		require.NoError(t, err)
		pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(thetpm)
		require.NoError(t, err)
		return pgd.PolicyDigest.Buffer
	}
	// systemd signs RSASSA over SHA256(policyDigest); VerifySignature gets the same.
	signFor := func(policy []byte) []byte {
		hh := sha256.Sum256(policy)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hh[:])
		require.NoError(t, err)
		return sig
	}
	sigJSON := func(policy, sig []byte) []byte {
		return []byte(fmt.Sprintf(`{"sha256":[{"pcrs":[%d],"pkfp":"%s","pol":"%s","sig":"%s"}]}`,
			debugPCR, rsaPublicKeyFingerprint(&key.PublicKey),
			hex.EncodeToString(policy), base64.StdEncoding.EncodeToString(sig)))
	}

	// 1. Unseal at the current PCR state.
	pol1 := currentPolicy()
	out, err := signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, nil, "sha256", sigJSON(pol1, signFor(pol1)), nil)
	require.NoError(t, err)
	require.Equal(t, secret, out)

	// 2. Change the bound PCR (a kernel update), re-sign — the SAME blob still unseals.
	_, err = (&tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(debugPCR), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
			HashAlg: tpm2.TPMAlgSHA256, Digest: bytes.Repeat([]byte{0xab}, 32),
		}}},
	}).Execute(thetpm)
	require.NoError(t, err)
	pol2 := currentPolicy()
	require.NotEqual(t, pol1, pol2, "extending the bound PCR must change the policy")
	out, err = signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, nil, "sha256", sigJSON(pol2, signFor(pol2)), nil)
	require.NoError(t, err)
	require.Equal(t, secret, out, "same blob must unseal after the PCR change with a fresh signature")

	// 3. A tampered signature must not unseal.
	bad := signFor(pol2)
	bad[0] ^= 0xff
	_, err = signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, nil, "sha256", sigJSON(pol2, bad), nil)
	require.Error(t, err, "a tampered signature must not unseal")
}

// TestSignedUnsealWithPIN covers a signed policy combined with a PIN
// (TPM+PIN+PCR): the blob's authPolicy is PolicyAuthorize(key) then
// PolicyAuthValue, and the object carries the PIN as its auth value. The
// correct PIN unseals; a wrong PIN does not.
func TestSignedUnsealWithPIN(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	dev, err := openTPM()
	require.NoError(t, err)
	defer dev.Close()
	thetpm := transport.FromReadWriteCloser(dev)

	srkRsp, err := (&tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(thetpm)
	require.NoError(t, err)
	srk := tpm2.NamedHandle{Handle: srkRsp.ObjectHandle, Name: srkRsp.Name}
	defer flushHandle(thetpm, srkRsp.ObjectHandle)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	le, err := (&tpm2.LoadExternal{InPublic: tpm2.New2B(rsaPublicArea(&key.PublicKey, 0x10001)), Hierarchy: tpm2.TPMRHOwner}).Execute(thetpm)
	require.NoError(t, err)
	keyName := le.Name
	flushHandle(thetpm, le.ObjectHandle)

	// authPolicy = PolicyAuthorize(key) THEN PolicyAuthValue — systemd's order.
	pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	require.NoError(t, (&tpm2.PolicyAuthorize{KeySign: keyName, PolicyRef: tpm2.TPM2BDigest{}}).Update(pol))
	require.NoError(t, (&tpm2.PolicyAuthValue{}).Update(pol))
	authPolicy := pol.Hash().Digest

	pin := []byte("1234")
	secret := []byte("super-secret-volume-key-0123456")
	createRsp, err := (&tpm2.Create{
		ParentHandle: srk,
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			UserAuth: tpm2.TPM2BAuth{Buffer: pin},
			Data:     tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true},
			AuthPolicy:       tpm2.TPM2BDigest{Buffer: authPolicy},
		}),
	}).Execute(thetpm)
	require.NoError(t, err)

	const debugPCR = 16
	pubkeyPCRs := []int{debugPCR}
	bank := tpm2.TPMAlgSHA256

	// Sign the current PolicyPCR digest.
	sess, cleanup, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 16)
	require.NoError(t, err)
	sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: bank, PCRSelect: tpm2.PCClientCompatible.PCRs(debugPCR)}}}
	_, err = (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel}).Execute(thetpm)
	require.NoError(t, err)
	pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(thetpm)
	require.NoError(t, err)
	approved := pgd.PolicyDigest.Buffer
	require.NoError(t, cleanup())
	hh := sha256.Sum256(approved)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hh[:])
	require.NoError(t, err)
	sigJSON := []byte(fmt.Sprintf(`{"sha256":[{"pcrs":[%d],"pkfp":"%s","pol":"%s","sig":"%s"}]}`,
		debugPCR, rsaPublicKeyFingerprint(&key.PublicKey), hex.EncodeToString(approved), base64.StdEncoding.EncodeToString(sig)))

	// Correct PIN unseals.
	out, err := signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, nil, "sha256", sigJSON, pin)
	require.NoError(t, err)
	require.Equal(t, secret, out)

	// Wrong PIN does not.
	_, err = signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, nil, "sha256", sigJSON, []byte("9999"))
	require.Error(t, err, "a wrong PIN must not unseal")
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
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	dev, err := openTPM()
	require.NoError(t, err)
	defer dev.Close()
	thetpm := transport.FromReadWriteCloser(dev)

	srkRsp, err := (&tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(thetpm)
	require.NoError(t, err)
	srk := tpm2.NamedHandle{Handle: srkRsp.ObjectHandle, Name: srkRsp.Name}
	defer flushHandle(thetpm, srkRsp.ObjectHandle)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	le, err := (&tpm2.LoadExternal{InPublic: tpm2.New2B(rsaPublicArea(&key.PublicKey, 0x10001)), Hierarchy: tpm2.TPMRHOwner}).Execute(thetpm)
	require.NoError(t, err)
	keyName := le.Name
	flushHandle(thetpm, le.ObjectHandle)

	const literalPCR = pcrSystemIdentity // 15, the latch PCR
	// authPolicy = PolicyAuthorize(key) THEN PolicyPCR(15 = uninitialized) — the
	// systemd order. The PCR 15 composite for an all-zero PCR is SHA256(zeros).
	composite := sha256.Sum256(make([]byte, 32))
	sel15 := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(uint(literalPCR)),
	}}}
	pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	require.NoError(t, (&tpm2.PolicyAuthorize{KeySign: keyName, PolicyRef: tpm2.TPM2BDigest{}}).Update(pol))
	require.NoError(t, (&tpm2.PolicyPCR{Pcrs: sel15, PcrDigest: tpm2.TPM2BDigest{Buffer: composite[:]}}).Update(pol))
	authPolicy := pol.Hash().Digest

	secret := []byte("super-secret-volume-key-0123456")
	createRsp, err := (&tpm2.Create{
		ParentHandle: srk,
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true},
			AuthPolicy:       tpm2.TPM2BDigest{Buffer: authPolicy},
		}),
	}).Execute(thetpm)
	require.NoError(t, err)

	pubkeyPCRs := []int{pcrKernelBoot}
	literalPCRs := []int{literalPCR}

	// Sign the signed half (PCR 11 at the enter-initrd value).
	extendPhasePCR11(t, thetpm, phaseEnterInitrd)
	sess, cleanup, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 16)
	require.NoError(t, err)
	sel11 := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcrKernelBoot)),
	}}}
	_, err = (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel11}).Execute(thetpm)
	require.NoError(t, err)
	pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(thetpm)
	require.NoError(t, err)
	approved := pgd.PolicyDigest.Buffer
	require.NoError(t, cleanup())
	hh := sha256.Sum256(approved)
	rawSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hh[:])
	require.NoError(t, err)
	sigJSON := []byte(fmt.Sprintf(`{"sha256":[{"pcrs":[%d],"pkfp":"%s","pol":"%s","sig":"%s"}]}`,
		pcrKernelBoot, rsaPublicKeyFingerprint(&key.PublicKey),
		hex.EncodeToString(approved), base64.StdEncoding.EncodeToString(rawSig)))

	// Combined unseal succeeds: signed PCR 11 matches, literal PCR 15 still zero.
	out, err := signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, literalPCRs, "sha256", sigJSON, nil)
	require.NoError(t, err)
	require.Equal(t, secret, out, "signed PCR 11 + literal PCR 15 must unseal in one token")

	// The PCR 15 latch fires after unseal. The signed PCR 11 half is unchanged,
	// but the literal PCR 15 binding no longer holds, so a re-unseal is blocked.
	d := sha256.Sum256([]byte("cryptsetup:cryptroot:uuid"))
	_, err = (&tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(literalPCR), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d[:]}}},
	}).Execute(thetpm)
	require.NoError(t, err)
	_, err = signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, literalPCRs, "sha256", sigJSON, nil)
	require.Error(t, err, "once the PCR 15 latch extends, the literal binding must block re-unseal")
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
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	dev, err := openTPM()
	require.NoError(t, err)
	defer dev.Close()
	thetpm := transport.FromReadWriteCloser(dev)

	srkRsp, err := (&tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(thetpm)
	require.NoError(t, err)
	srk := tpm2.NamedHandle{Handle: srkRsp.ObjectHandle, Name: srkRsp.Name}
	defer flushHandle(thetpm, srkRsp.ObjectHandle)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	le, err := (&tpm2.LoadExternal{InPublic: tpm2.New2B(rsaPublicArea(&key.PublicKey, 0x10001)), Hierarchy: tpm2.TPMRHOwner}).Execute(thetpm)
	require.NoError(t, err)
	keyName := le.Name
	flushHandle(thetpm, le.ObjectHandle)

	pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	require.NoError(t, (&tpm2.PolicyAuthorize{KeySign: keyName, PolicyRef: tpm2.TPM2BDigest{}}).Update(pol))
	authPolicy := pol.Hash().Digest

	secret := []byte("super-secret-volume-key-0123456")
	createRsp, err := (&tpm2.Create{
		ParentHandle: srk,
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true},
			AuthPolicy:       tpm2.TPM2BDigest{Buffer: authPolicy},
		}),
	}).Execute(thetpm)
	require.NoError(t, err)

	pubkeyPCRs := []int{pcrKernelBoot} // bind to the REAL PCR 11
	bank := tpm2.TPMAlgSHA256

	policyDigestNow := func() []byte {
		sess, cleanup, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 16)
		require.NoError(t, err)
		defer cleanup()
		sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash: bank, PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcrKernelBoot)),
		}}}
		_, err = (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel}).Execute(thetpm)
		require.NoError(t, err)
		pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(thetpm)
		require.NoError(t, err)
		return pgd.PolicyDigest.Buffer
	}
	sigJSON := func(policy []byte) []byte {
		hh := sha256.Sum256(policy)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hh[:])
		require.NoError(t, err)
		return []byte(fmt.Sprintf(`{"sha256":[{"pcrs":[%d],"pkfp":"%s","pol":"%s","sig":"%s"}]}`,
			pcrKernelBoot, rsaPublicKeyFingerprint(&key.PublicKey),
			hex.EncodeToString(policy), base64.StdEncoding.EncodeToString(sig)))
	}

	// Signature for the BARE PCR 11 value (pre-barrier) — what the earlier
	// implementation would have matched.
	bareSig := sigJSON(policyDigestNow())

	// Extend "enter-initrd" into PCR 11 over the shared connection (swtpm's TCP
	// server is single-client, so the barrier's own connection can't be opened
	// while holding thetpm). This is byte-identical to measurePhaseToPCR11,
	// proven in TestMeasurePhaseToPCR11. PCR 11 now equals systemd's enter-initrd
	// phase value, exactly as in a real initrd before unlock.
	extendPhasePCR11(t, thetpm, phaseEnterInitrd)

	// The bare-value signature must NOT unseal now: the barrier advanced PCR 11.
	_, err = signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, nil, "sha256", bareSig, nil)
	require.Error(t, err, "a bare-PCR11 signature must not unseal after the enter-initrd barrier")

	// A signature for the post-barrier (enter-initrd) value unseals — the
	// standard systemd case.
	out, err := signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, nil, "sha256", sigJSON(policyDigestNow()), nil)
	require.NoError(t, err)
	require.Equal(t, secret, out, "a signature for the enter-initrd PCR11 value must unseal")
}

// TestLeaveInitrdForwardLock pins the forward-lock booster applies at
// switch_root. A root key signed only for the "enter-initrd" phase (as
// systemd-measure --phase=enter-initrd produces for an initrd-only secret)
// unseals while PCR 11 holds the enter-initrd value, but once "leave-initrd" is
// extended the same signature no longer matches the advanced PCR 11 — so the key
// cannot be unsealed after the host takes over. PolicyAuthorize would accept any
// signed value, so the lock is enforced by the absence of a signature for later
// phases, exactly as in systemd.
func TestLeaveInitrdForwardLock(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	dev, err := openTPM()
	require.NoError(t, err)
	defer dev.Close()
	thetpm := transport.FromReadWriteCloser(dev)

	srkRsp, err := (&tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InPublic: tpm2.New2B(tpm2.ECCSRKTemplate)}).Execute(thetpm)
	require.NoError(t, err)
	srk := tpm2.NamedHandle{Handle: srkRsp.ObjectHandle, Name: srkRsp.Name}
	defer flushHandle(thetpm, srkRsp.ObjectHandle)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	le, err := (&tpm2.LoadExternal{InPublic: tpm2.New2B(rsaPublicArea(&key.PublicKey, 0x10001)), Hierarchy: tpm2.TPMRHOwner}).Execute(thetpm)
	require.NoError(t, err)
	keyName := le.Name
	flushHandle(thetpm, le.ObjectHandle)

	pol, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	require.NoError(t, err)
	require.NoError(t, (&tpm2.PolicyAuthorize{KeySign: keyName, PolicyRef: tpm2.TPM2BDigest{}}).Update(pol))
	authPolicy := pol.Hash().Digest

	secret := []byte("super-secret-volume-key-0123456")
	createRsp, err := (&tpm2.Create{
		ParentHandle: srk,
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
		}},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true},
			AuthPolicy:       tpm2.TPM2BDigest{Buffer: authPolicy},
		}),
	}).Execute(thetpm)
	require.NoError(t, err)

	pubkeyPCRs := []int{pcrKernelBoot}
	bank := tpm2.TPMAlgSHA256
	policyDigestNow := func() []byte {
		sess, cleanup, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 16)
		require.NoError(t, err)
		defer cleanup()
		sel := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
			Hash: bank, PCRSelect: tpm2.PCClientCompatible.PCRs(uint(pcrKernelBoot)),
		}}}
		_, err = (&tpm2.PolicyPCR{PolicySession: sess.Handle(), Pcrs: sel}).Execute(thetpm)
		require.NoError(t, err)
		pgd, err := (&tpm2.PolicyGetDigest{PolicySession: sess.Handle()}).Execute(thetpm)
		require.NoError(t, err)
		return pgd.PolicyDigest.Buffer
	}

	// enter-initrd: sign the root key for this phase only, and unseal succeeds.
	extendPhasePCR11(t, thetpm, phaseEnterInitrd)
	enterPolicy := policyDigestNow()
	hh := sha256.Sum256(enterPolicy)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hh[:])
	require.NoError(t, err)
	enterSig := []byte(fmt.Sprintf(`{"sha256":[{"pcrs":[%d],"pkfp":"%s","pol":"%s","sig":"%s"}]}`,
		pcrKernelBoot, rsaPublicKeyFingerprint(&key.PublicKey),
		hex.EncodeToString(enterPolicy), base64.StdEncoding.EncodeToString(sig)))

	out, err := signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, nil, "sha256", enterSig, nil)
	require.NoError(t, err)
	require.Equal(t, secret, out, "the enter-initrd-signed key unseals during the initrd")

	// switch_root extends leave-initrd; the enter-initrd-only signature — the
	// only one that exists for this key — can no longer satisfy the policy.
	extendPhasePCR11(t, thetpm, phaseLeaveInitrd)
	_, err = signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, nil, "sha256", enterSig, nil)
	require.Error(t, err, "after leave-initrd the enter-initrd-only signature must not unseal (forward-lock)")
}
