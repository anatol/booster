package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/anatol/luks.go"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

// Known answers for systemd v262's Argon2id TPM2 PIN mode, produced outside Go
// with the same OpenSSL KDFs systemd calls (OpenSSL 3.6.5):
//
//	openssl kdf -keylen 64 -kdfopt pass:1234 -kdfopt hexsalt:<salt> \
//	    -kdfopt memcost:1024 -kdfopt iter:3 -kdfopt lanes:4 ARGON2ID
//	openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt hexkey:<key1> \
//	    -kdfopt hexsalt:<secret> -kdfopt info:systemd-tpm2-argon2id-lock HKDF
//
// The Argon2id output also matches the reference argon2 CLI
// (argon2 <salt> -id -t 3 -k 1024 -p 4 -l 64 -r). The auth value is
// sha256sum of the base64 of the second half, the passphrase base64 of the HKDF.
const (
	argon2idTestPIN    = "1234"
	argon2idTestSalt   = "booster-argon2id-test-salt-32byt"
	argon2idTestSecret = "booster-unsealed-tpm2-secret-32b"
	// 1 MiB plus 512 bytes: systemd's kdf_argon2id_derive hands OpenSSL
	// memcost_bytes/1024 KiB, so the stray 512 bytes must be dropped.
	argon2idTestMemcost    = 1024*1024 + 512
	argon2idTestIterations = 3
	argon2idTestLanes      = 4

	argon2idTestKey1       = "14bfa95593c4cede01ed8198fb2f43af58e04efd03ce3af1989576e88881a785"
	argon2idTestAuth       = "5d1cf6c4ccf44a493b8e47215460715ab521dad257200d8f919602dc2e4e3264"
	argon2idTestPassphrase = "3phVuxdKytDDhDEgjvdpEnHc/IY+B6NhSPJa5MSDYIo="
)

var argon2idTestParams = tpm2Argon2id{
	memcostBytes: argon2idTestMemcost,
	iterations:   argon2idTestIterations,
	lanes:        argon2idTestLanes,
}

// TestTPM2Argon2idKnownAnswer pins booster's Argon2id PIN derivation to
// systemd's: which half of the Argon2id output becomes the TPM PIN, which half
// feeds the HKDF, and the HKDF salt and info string. A mismatch here means
// tokens enrolled by systemd-cryptenroll --tpm2-with-pin=yes stop unlocking.
func TestTPM2Argon2idKnownAnswer(t *testing.T) {
	t.Parallel()

	auth, key1 := tpm2Argon2idPIN([]byte(argon2idTestPIN), []byte(argon2idTestSalt), argon2idTestParams)
	require.Equal(t, argon2idTestKey1, hex.EncodeToString(key1))
	require.Equal(t, argon2idTestAuth, hex.EncodeToString(auth))

	vk, err := tpm2Argon2idVolumeKey(key1, []byte(argon2idTestSecret))
	require.NoError(t, err)
	require.Equal(t, argon2idTestPassphrase, base64.StdEncoding.EncodeToString(vk))
}

// TestTPM2Argon2idParams pins the token validation, mirrored from systemd's
// tpm2_parse_luks2_json and kdf_argon2id_derive: no fields means
// the classic PIN mode, a partial set is an error, and so is a set booster's
// Argon2id cannot compute. It runs before any TPM access, so a bad token fails
// fast without a PIN prompt.
func TestTPM2Argon2idParams(t *testing.T) {
	t.Parallel()

	tok := func(extra string) string {
		return `{"tpm2-pin":true,"tpm2_salt":"c2FsdA=="` + extra + `}`
	}

	for _, tc := range []struct {
		name, payload string
		want          *tpm2Argon2id
		errSub        string
	}{
		{"absent", tok(""), nil, ""},
		{"complete", tok(`,"tpm2_argon2id_memcost":65536,"tpm2_argon2id_iterations":2,"tpm2_argon2id_lanes":1`), &tpm2Argon2id{65536, 2, 1}, ""},
		{"partial", tok(`,"tpm2_argon2id_memcost":65536`), nil, "incomplete"},
		{"no salt", `{"tpm2-pin":true,"tpm2_argon2id_memcost":65536,"tpm2_argon2id_iterations":2,"tpm2_argon2id_lanes":1}`, nil, "salt"},
		{"too many lanes", tok(`,"tpm2_argon2id_memcost":65536,"tpm2_argon2id_iterations":2,"tpm2_argon2id_lanes":256`), nil, "lanes"},
		// 2 TiB: representable in KiB as a uint32, but beyond any test host's RAM.
		{"more memory than the machine", tok(`,"tpm2_argon2id_memcost":2199023255552,"tpm2_argon2id_iterations":2,"tpm2_argon2id_lanes":1`), nil, "memory"},
		{"memory beyond a uint32 of KiB", tok(`,"tpm2_argon2id_memcost":4398046511104,"tpm2_argon2id_iterations":2,"tpm2_argon2id_lanes":1`), nil, "too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var node struct {
				Salt string `json:"tpm2_salt"`
				tpm2Argon2idFields
			}
			require.NoError(t, json.Unmarshal([]byte(tc.payload), &node))
			got, err := node.params(node.Salt != "")
			if tc.errSub != "" {
				require.ErrorContains(t, err, tc.errSub)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestRecoverSystemdTPM2Argon2idPIN unlocks a token laid out the way systemd
// v262 enrolls --tpm2-with-pin=yes (cryptenroll-tpm2.c enroll_tpm2): the TPM object's auth is the Argon2id-derived PIN, and the LUKS
// passphrase is base64 of HKDF(key1, unsealed secret), not of the secret
// itself. The auth value and expected passphrase are the OpenSSL vectors above,
// so the test does not lean on booster's own derivation.
func TestRecoverSystemdTPM2Argon2idPIN(t *testing.T) {
	startSwtpmTCPForTest(t)
	enableSwEmulator = true
	t.Cleanup(func() { enableSwEmulator = false })

	tpmReady = sync.Once{}
	tpmReadyWg = sync.WaitGroup{}

	auth, err := hex.DecodeString(argon2idTestAuth)
	require.NoError(t, err)
	blob, policyHash := sealPINBlobForTest(t, auth, []byte(argon2idTestSecret))

	payload := fmt.Sprintf(`{"type":"systemd-tpm2","keyslots":["1"],"tpm2-blob":%q,"tpm2-pcrs":[],"tpm2-pcr-bank":"sha256",`+
		`"tpm2-primary-alg":"ecc","tpm2-policy-hash":%q,"tpm2-pin":true,"tpm2_salt":%q,`+
		`"tpm2_argon2id_memcost":%d,"tpm2_argon2id_iterations":%d,"tpm2_argon2id_lanes":%d}`,
		base64.StdEncoding.EncodeToString(blob), hex.EncodeToString(policyHash),
		base64.StdEncoding.EncodeToString([]byte(argon2idTestSalt)),
		argon2idTestMemcost, argon2idTestIterations, argon2idTestLanes)

	prompts := 0
	askKeyboardPassword = func(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
		prompts++
		return []byte(argon2idTestPIN), nil
	}
	t.Cleanup(func() { askKeyboardPassword = askPasswordWithFallback })

	got, err := recoverSystemdTPM2Password(context.Background(), luks.Token{Type: "systemd-tpm2", Payload: []byte(payload)}, "cryptroot", "")
	require.NoError(t, err)
	require.Equal(t, argon2idTestPassphrase, string(got))
	require.Equal(t, 1, prompts, "the right PIN must unlock on the first attempt")
}

// sealPINBlobForTest seals secret under the transient ECC primary booster
// derives for a token without tpm2_srk, with auth as the object's auth value
// and a PolicyAuthValue-only policy (a PIN token bound to no PCRs). It returns
// the systemd tpm2-blob (sized private then sized public) and the policy hash.
func sealPINBlobForTest(t *testing.T, auth, secret []byte) (blob, policyHash []byte) {
	t.Helper()
	dev, err := openTPM()
	require.NoError(t, err)
	defer dev.Close()

	parent, _, err := tpm2.CreatePrimary(dev, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", tpm2.Public{
		Type:          tpm2.AlgECC,
		NameAlg:       tpm2.AlgSHA256,
		Attributes:    tpm2.FlagStorageDefault,
		ECCParameters: defaultECCParams,
		RSAParameters: defaultRSAParams,
	})
	require.NoError(t, err)
	defer tpm2.FlushContext(dev, parent)

	sess, _, err := tpm2.StartAuthSession(dev, tpm2.HandleNull, tpm2.HandleNull, make([]byte, 32), nil, tpm2.SessionTrial, tpm2.AlgNull, tpm2.AlgSHA256)
	require.NoError(t, err)
	require.NoError(t, tpm2.PolicyPassword(dev, sess))
	policyHash, err = tpm2.PolicyGetDigest(dev, sess)
	require.NoError(t, err)
	require.NoError(t, tpm2.FlushContext(dev, sess))

	private, public, err := tpm2.Seal(dev, parent, "", string(auth), policyHash, secret)
	require.NoError(t, err)

	blob = binary.BigEndian.AppendUint16(nil, uint16(len(private)))
	blob = append(blob, private...)
	blob = binary.BigEndian.AppendUint16(blob, uint16(len(public)))
	blob = append(blob, public...)
	return blob, policyHash
}
