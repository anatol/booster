package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNvPCRWritePolicyStable(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	name1, auth1, write1, err := nvpcrWritePolicy(&key.PublicKey, 0x10001)
	require.NoError(t, err)
	require.Len(t, auth1, 32)
	require.Len(t, write1, 32)
	require.NotEmpty(t, name1.Buffer)

	name2, auth2, write2, err := nvpcrWritePolicy(&key.PublicKey, 0x10001)
	require.NoError(t, err)
	require.Equal(t, name1.Buffer, name2.Buffer)
	require.Equal(t, auth1, auth2)
	require.Equal(t, write1, write2)

	// Exponent 0 changes the TPM key Name, so the Authorize branch (and OR) move.
	_, auth0, write0, err := nvpcrWritePolicy(&key.PublicKey, 0)
	require.NoError(t, err)
	require.NotEqual(t, hex.EncodeToString(auth1), hex.EncodeToString(auth0))
	require.NotEqual(t, hex.EncodeToString(write1), hex.EncodeToString(write0))
}

func TestLoadNvPCRDefinitionsMerge(t *testing.T) {
	dir := t.TempDir()
	lib := filepath.Join(dir, "lib")
	etc := filepath.Join(dir, "etc")
	require.NoError(t, os.MkdirAll(lib, 0o755))
	require.NoError(t, os.MkdirAll(etc, 0o755))

	write := func(dir, name, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644))
	}
	write(lib, "verity.nvpcr", `{"name":"verity","algorithm":"sha256","nvIndex":1,"priority":300}`)
	write(lib, "login.nvpcr", `{"name":"login","algorithm":"sha256","nvIndex":2,"priority":800}`)
	write(etc, "login.nvpcr", `{"name":"login","algorithm":"sha256","nvIndex":99,"priority":100}`)

	old := nvpcrDefDirs
	nvpcrDefDirs = []string{lib, etc}
	t.Cleanup(func() { nvpcrDefDirs = old })

	defs, err := loadNvPCRDefinitions()
	require.NoError(t, err)
	require.Len(t, defs, 2)

	byName := map[string]nvpcrDef{}
	for _, d := range defs {
		byName[d.Name] = d
	}
	require.Equal(t, uint32(1), byName["verity"].NVIndex)
	require.Equal(t, uint32(99), byName["login"].NVIndex) // later path wins
	require.Equal(t, uint64(100), byName["login"].Priority)
}

func TestNvPCRPublicAttrs(t *testing.T) {
	pol := make([]byte, 32)
	p, err := nvpcrPublic(0x1d11000, true, pol)
	require.NoError(t, err)
	require.True(t, p.Attributes.PolicyWrite)
	require.True(t, p.Attributes.OwnerRead)
	require.True(t, p.Attributes.AuthRead)
	require.True(t, p.Attributes.ClearSTClear)
	require.True(t, p.Attributes.Orderly)
	require.Equal(t, uint16(32), p.DataSize)

	p2, err := nvpcrPublic(0x1d11000, false, pol)
	require.NoError(t, err)
	require.False(t, p2.Attributes.Orderly)
}

func TestHostNvPCRJSONShape(t *testing.T) {
	// Sanity-check against the system definitions when present (Arch/systemd 262).
	raw, err := os.ReadFile("/usr/lib/nvpcr/cryptsetup.nvpcr")
	if err != nil {
		t.Skip("no host /usr/lib/nvpcr")
	}
	var d nvpcrDef
	require.NoError(t, json.Unmarshal(raw, &d))
	require.Equal(t, "cryptsetup", d.Name)
	require.Equal(t, "sha256", d.Algorithm)
	require.NotZero(t, d.NVIndex)
}
