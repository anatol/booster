package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCrypttabPassphrase verifies that a crypttab entry drives LUKS unlock
// without any rd.luks.* kernel parameters.
func TestCrypttabPassphrase(t *testing.T) {
	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID=639b8fdd-36ba-443e-be3e-e5b335935502 none x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.img",
		crypttabFile: crypttabPath,
		kernelArgs:   []string{"root=/dev/mapper/cryptroot"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestCrypttabNofail verifies that a nofail entry for an absent device does
// not prevent the system from booting.
func TestCrypttabNofail(t *testing.T) {
	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptfake UUID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee none nofail,x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/ext4.img",
		crypttabFile: crypttabPath,
		kernelArgs:   []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestCrypttabKeyfileOffsetSize verifies that keyfile-offset= and keyfile-size=
// correctly slice a keyfile embedded in the initramfs.
// The luks2 password "1234" is stored at offset 8 of a padded keyfile.
func TestCrypttabKeyfileOffsetSize(t *testing.T) {
	keyfilePath := filepath.Join(t.TempDir(), "luks2.key")
	require.NoError(t, os.WriteFile(keyfilePath, []byte("PADDINGx1234"), 0o600))

	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, fmt.Appendf(nil,
		"cryptroot UUID=639b8fdd-36ba-443e-be3e-e5b335935502 %s keyfile-offset=8,keyfile-size=4,x-initrd.attach\n",
		keyfilePath,
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.img",
		crypttabFile: crypttabPath,
		kernelArgs:   []string{"root=/dev/mapper/cryptroot"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestCrypttabTries verifies that tries=N allows up to N passphrase attempts.
// Root is on the LUKS device so there is no concurrent root-mount race: the
// first attempt is wrong, the second (within the tries=2 budget) is correct.
func TestCrypttabTries(t *testing.T) {
	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID=639b8fdd-36ba-443e-be3e-e5b335935502 none tries=2,x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.img",
		crypttabFile: crypttabPath,
		kernelArgs:   []string{"root=/dev/mapper/cryptroot"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("wrong\n"))
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestCrypttabKeySlot verifies that key-slot= restricts unlock to the specified
// keyslot. Uses slot 0 which holds the "1234" password in luks2.img.
func TestCrypttabKeySlot(t *testing.T) {
	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID=639b8fdd-36ba-443e-be3e-e5b335935502 none key-slot=0,x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.img",
		crypttabFile: crypttabPath,
		kernelArgs:   []string{"root=/dev/mapper/cryptroot"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestCrypttabCmdlinePrecedence verifies that rd.luks.* kernel parameters take
// precedence over crypttab entries for the same device. The crypttab names the
// device "cryptroot" but the cmdline overrides it to "cmdroot"; the passphrase
// prompt should name the device "cmdroot" confirming the crypttab entry was skipped.
func TestCrypttabCmdlinePrecedence(t *testing.T) {
	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID=639b8fdd-36ba-443e-be3e-e5b335935502 none x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.img",
		crypttabFile: crypttabPath,
		kernelArgs: []string{
			"rd.luks.name=639b8fdd-36ba-443e-be3e-e5b335935502=cmdroot",
			"root=/dev/mapper/cmdroot",
		},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cmdroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
