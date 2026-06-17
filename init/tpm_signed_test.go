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
	b64 := base64.StdEncoding.EncodeToString(spki)

	// Signed token: has tpm2_pubkey + tpm2_pubkey_pcrs.
	signed := []byte(`{"tpm2_pubkey":"` + b64 + `","tpm2_pubkey_pcrs":[11]}`)
	pub, pcrs, ok, err := parseSignedToken(signed)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []int{11}, pcrs)
	require.Equal(t, key.PublicKey.N, pub.N)
	require.Equal(t, key.PublicKey.E, pub.E)

	// Literal-PCR token: no tpm2_pubkey -> not signed (handled by the legacy path).
	literal := []byte(`{"tpm2-pcrs":[7]}`)
	_, _, ok, err = parseSignedToken(literal)
	require.NoError(t, err)
	require.False(t, ok)

	// Malformed base64 pubkey -> error.
	_, _, _, err = parseSignedToken([]byte(`{"tpm2_pubkey":"!!notb64!!"}`))
	require.Error(t, err)
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
	out, err := signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, "sha256", sigJSON(pol1, signFor(pol1)), nil)
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
	out, err = signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, "sha256", sigJSON(pol2, signFor(pol2)), nil)
	require.NoError(t, err)
	require.Equal(t, secret, out, "same blob must unseal after the PCR change with a fresh signature")

	// 3. A tampered signature must not unseal.
	bad := signFor(pol2)
	bad[0] ^= 0xff
	_, err = signedTPM2Unseal(thetpm, srk, createRsp.OutPublic, createRsp.OutPrivate, &key.PublicKey, pubkeyPCRs, "sha256", sigJSON(pol2, bad), nil)
	require.Error(t, err, "a tampered signature must not unseal")
}
