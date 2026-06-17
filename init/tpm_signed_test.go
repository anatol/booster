package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

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
