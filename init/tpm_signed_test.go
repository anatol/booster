package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
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
