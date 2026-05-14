package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadEmptyConfig(t *testing.T) {
	t.Parallel()

	c, err := readGeneratorConfig("")
	require.NoError(t, err)
	require.Equal(t, "zstd", c.compression)
}

func TestParseCommaList(t *testing.T) {
	t.Parallel()

	require.Equal(t, []string{"mod1", "mod2"}, parseCommaList(" mod1, ,mod2 ,, "))
	require.Nil(t, parseCommaList(" , , "))
}

func TestReadConfigNormalizesCommaSeparatedFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "booster.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
modules: " dm_mod, , nvme "
modules_force_load: " usbhid, hid_generic "
extra_files: " /bin/ls, , /bin/cat "
network:
  dhcp: true
  interfaces: " aa:bb:cc:dd:ee:ff, , 11:22:33:44:55:66 "
`), 0o644))

	c, err := readGeneratorConfig(cfgPath)
	require.NoError(t, err)
	require.Equal(t, []string{"dm_mod", "nvme"}, c.modules)
	require.Equal(t, []string{"usbhid", "hid_generic"}, c.modulesForceLoad)
	require.Equal(t, []string{"/bin/ls", "/bin/cat"}, c.extraFiles)
	require.Len(t, c.networkActiveInterfaces, 2)
}

// writeSshFixtures creates a host key + authorized_keys pair in tmp and
// returns their paths. Tests that need a *valid* SSH config can rely on
// these files existing on disk so readGeneratorConfig can read them.
func writeSshFixtures(t *testing.T) (hostKey, authKeys string) {
	t.Helper()
	dir := t.TempDir()
	hostKey = filepath.Join(dir, "host_key")
	authKeys = filepath.Join(dir, "authorized_keys")
	// Real ed25519 PEM so any future parsing in the generator stays green;
	// content of authorized_keys is only validated by init, not the generator.
	require.NoError(t, os.WriteFile(hostKey, []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA6u0iSOLuwKGJ0oMlOvuT8lbDHDlHptyebFZpDx48pfgAAAJgQJZmvECWZ
rwAAAAtzc2gtZWQyNTUxOQAAACA6u0iSOLuwKGJ0oMlOvuT8lbDHDlHptyebFZpDx48pfg
AAAEALEOT+7djjMoPheTuZeoYdZ34c7Gt+9r+eiMuurYRZ5jq7SJI4u7AoYnSgyU6+5PyV
sMcOUem3J5sVmkPHjyl+AAAAEWJvb3N0ZXItdGVzdC1ob3N0AQIDBA==
-----END OPENSSH PRIVATE KEY-----
`), 0o600))
	require.NoError(t, os.WriteFile(authKeys, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINHwZ1qsGgu31resaunq1bwZOM++27lQyeCsI4lCYBTh test@example\n"), 0o600))
	return
}

func TestReadConfigAcceptsValidSshConfig(t *testing.T) {
	t.Parallel()
	hostKey, authKeys := writeSshFixtures(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "booster.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
network:
  dhcp: true
  ssh_host_key: `+hostKey+`
  ssh_authorized_keys: `+authKeys+`
  ssh_listen: ":2222"
`), 0o644))

	c, err := readGeneratorConfig(cfgPath)
	require.NoError(t, err)
	require.NotEmpty(t, c.sshHostKey)
	require.NotEmpty(t, c.sshAuthorizedKeys)
	require.Equal(t, ":2222", c.sshListen)
}

func TestReadConfigRejectsSshHostKeyWithoutAuthorizedKeys(t *testing.T) {
	t.Parallel()
	hostKey, _ := writeSshFixtures(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "booster.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
network:
  dhcp: true
  ssh_host_key: `+hostKey+`
`), 0o644))

	_, err := readGeneratorConfig(cfgPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ssh_host_key and network.ssh_authorized_keys must both be set")
}

func TestReadConfigRejectsSshAuthorizedKeysWithoutHostKey(t *testing.T) {
	t.Parallel()
	_, authKeys := writeSshFixtures(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "booster.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
network:
  dhcp: true
  ssh_authorized_keys: `+authKeys+`
`), 0o644))

	_, err := readGeneratorConfig(cfgPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ssh_host_key and network.ssh_authorized_keys must both be set")
}

func TestReadConfigRejectsSshWithoutNetwork(t *testing.T) {
	t.Parallel()
	hostKey, authKeys := writeSshFixtures(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "booster.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
network:
  ssh_host_key: `+hostKey+`
  ssh_authorized_keys: `+authKeys+`
`), 0o644))

	_, err := readGeneratorConfig(cfgPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "network.ssh_* requires network.dhcp or network.ip")
}

func TestReadConfigRejectsMissingSshHostKeyFile(t *testing.T) {
	t.Parallel()
	_, authKeys := writeSshFixtures(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "booster.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
network:
  dhcp: true
  ssh_host_key: `+filepath.Join(dir, "does-not-exist")+`
  ssh_authorized_keys: `+authKeys+`
`), 0o644))

	_, err := readGeneratorConfig(cfgPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "network.ssh_host_key")
}

const validSshPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINHwZ1qsGgu31resaunq1bwZOM++27lQyeCsI4lCYBTh test@example"

// TestValidateAuthorizedKeys pins the build-time gate that mirrors
// init/ssh.go:parseAuthorizedKeys (item 1: fail at build, not as a
// locked-out boot).
func TestValidateAuthorizedKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"single valid key", validSshPubKey + "\n", false},
		{"two valid keys", validSshPubKey + "\n" + validSshPubKey + "\n", false},
		{"comment then valid key", "# my key\n" + validSshPubKey + "\n", false},
		{"empty", "", true},
		{"whitespace only", "  \n\t\n", true},
		{"comments only", "# just a comment\n# another\n", true},
		{"garbage only", "this is not a key\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateAuthorizedKeys([]byte(tc.input))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// TestReadConfigRejectsEmptyAuthorizedKeys exercises item 1 end-to-end: an
// authorized_keys file with no usable keys must fail the build rather than
// silently disable the SSH server at boot.
func TestReadConfigRejectsEmptyAuthorizedKeys(t *testing.T) {
	t.Parallel()
	hostKey, _ := writeSshFixtures(t)

	dir := t.TempDir()
	emptyAuth := filepath.Join(dir, "authorized_keys")
	require.NoError(t, os.WriteFile(emptyAuth, []byte("   \n\t\n"), 0o600))
	cfgPath := filepath.Join(dir, "booster.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
network:
  dhcp: true
  ssh_host_key: `+hostKey+`
  ssh_authorized_keys: `+emptyAuth+`
`), 0o644))

	_, err := readGeneratorConfig(cfgPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "network.ssh_authorized_keys")
	require.Contains(t, err.Error(), "no SSH public keys")
}

// TestReadConfigRejectsGarbageAuthorizedKeys covers the unparseable-content
// variant of item 1.
func TestReadConfigRejectsGarbageAuthorizedKeys(t *testing.T) {
	t.Parallel()
	hostKey, _ := writeSshFixtures(t)

	dir := t.TempDir()
	garbageAuth := filepath.Join(dir, "authorized_keys")
	require.NoError(t, os.WriteFile(garbageAuth, []byte("not a valid ssh key at all\n"), 0o600))
	cfgPath := filepath.Join(dir, "booster.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
network:
  dhcp: true
  ssh_host_key: `+hostKey+`
  ssh_authorized_keys: `+garbageAuth+`
`), 0o644))

	_, err := readGeneratorConfig(cfgPath)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no parseable SSH public key")
}

// TestReadConfigAcceptsLooseHostKeyPerms exercises item 2: a group/other
// readable host key triggers a warning but must NOT fail the build —
// the warning is advisory, the config still loads.
func TestReadConfigAcceptsLooseHostKeyPerms(t *testing.T) {
	t.Parallel()
	hostKey, authKeys := writeSshFixtures(t)
	require.NoError(t, os.Chmod(hostKey, 0o644))

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "booster.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
network:
  dhcp: true
  ssh_host_key: `+hostKey+`
  ssh_authorized_keys: `+authKeys+`
`), 0o644))

	c, err := readGeneratorConfig(cfgPath)
	require.NoError(t, err)
	require.NotEmpty(t, c.sshHostKey)
}
