package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

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

const (
	keyfileDevLuksUUID   = "7c2a39be-15d1-4b71-9f2e-5c4d1a3b8e6f"
	keyfileDevFsUUID     = "a3d8e2c1-4f7b-4e9c-b2a1-6d5f3c8e1a7b"
	keyfileDevKeydevUUID = "f1e2d3c4-b5a6-4789-8abc-def123456789"
)

// TestCrypttabKeyfileDevice verifies that booster can unlock a LUKS2 volume
// whose keyfile lives on a separate block device configured via the crypttab
// keyfile field (/keyfile:UUID=<keydev>).  The key device is presented as a
// second virtio disk; no passphrase prompt is expected.
func TestCrypttabKeyfileDevice(t *testing.T) {
	require.NoError(t, checkAsset("assets/luks2.keyfile_device.img"))

	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID="+keyfileDevLuksUUID+" /keyfile:UUID="+keyfileDevKeydevUUID+" x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.keyfile_device.img",
		params:       []string{"-drive", "file=assets/luks2.keyfile_device.keydev.img,if=virtio,format=raw"},
		kernelArgs:   []string{"root=UUID=" + keyfileDevFsUUID},
		crypttabFile: crypttabPath,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestCrypttabHeader verifies that booster can unlock a LUKS2 volume with a
// detached header referenced via the crypttab header= option.  The generator
// bundles the header file into the initramfs automatically.
func TestCrypttabHeader(t *testing.T) {
	require.NoError(t, checkAsset("assets/luks2.detached_header.img"))

	headerPath, err := filepath.Abs("assets/luks2.detached_header.hdr")
	require.NoError(t, err)

	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID="+detachedHeaderLuksUUID+" none header="+headerPath+",x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/luks2.detached_header.img",
		kernelArgs:   []string{"root=UUID=" + detachedHeaderFsUUID},
		crypttabFile: crypttabPath,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestCrypttabFido2 verifies that a crypttab entry with fido2-device=auto
// causes the generator to auto-bundle fido2plugin.so and the init to attempt
// FIDO2 token unlock before falling back to keyboard.
//
// Requires a physical FIDO2 device and BOOSTER_TEST_FIDO2_PIN to be set.
// A fresh LUKS image is created for each run enrolling the connected device,
// so the test works for any FIDO2 device without pre-built assets.
func TestCrypttabFido2(t *testing.T) {
	pin := os.Getenv("BOOSTER_TEST_FIDO2_PIN")
	if pin == "" {
		t.Skip("BOOSTER_TEST_FIDO2_PIN not set")
	}

	yubikeys, err := detectYubikeys()
	require.NoError(t, err)
	if len(yubikeys) == 0 {
		t.Skip("no Yubikeys detected")
	}

	if !fileExists(binariesDir + "/fido2plugin.so") {
		t.Skip("fido2plugin.so not built (libfido2 may not be installed)")
	}

	luksUUID, fsUUID, imgPath := createFido2LuksImage(t, pin)

	params := make([]string, 0)
	for _, y := range yubikeys {
		params = append(params, y.toQemuParams()...)
	}

	// The crypttab entry specifies fido2-device=auto; the generator auto-detects
	// this and bundles fido2plugin.so without needing enable_fido2: true in config.
	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID="+luksUUID+" none fido2-device=auto,x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         imgPath,
		params:       params,
		kernelArgs:   []string{"root=UUID=" + fsUUID},
		crypttabFile: crypttabPath,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	re, err := regexp.Compile(`(Enter FIDO2 PIN for |Hello, booster!)`)
	require.NoError(t, err)
	for {
		matches, err := vm.ConsoleExpectRE(re)
		require.NoError(t, err)
		if matches[0] == "Hello, booster!" {
			break
		}
		require.NoError(t, vm.ConsoleWrite(pin+"\n"))
	}
}

// TestCrypttabFido2NoDevice verifies that when fido2-device=auto is set in
// crypttab and the LUKS volume has a FIDO2 token enrolled but no physical key
// is present, init waits token-timeout seconds then falls back to the keyboard
// passphrase prompt.
//
// Uses systemd-fido2-nodev.img which has a fake systemd-fido2 token with a
// random credential — it will never match any real device, so no hardware is
// required.  The default token-timeout of 30s applies.
func TestCrypttabFido2NoDevice(t *testing.T) {
	if !fileExists(binariesDir + "/fido2plugin.so") {
		t.Skip("fido2plugin.so not built (libfido2 may not be installed)")
	}

	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID=a6cdb03e-ad77-440a-8a93-28ad97de3b00 none fido2-device=auto,x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/systemd-fido2-nodev.img",
		kernelArgs:   []string{"root=UUID=0cb4665f-65a0-4acc-9710-05163af16f19"},
		crypttabFile: crypttabPath,
		// tokenTimeout defaults to 30s; allow enough time for that plus boot
		vmTimeout: 90 * time.Second,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// No FIDO2 device is present, so init waits token-timeout then falls back.
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("567\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestCrypttabTPM2 verifies that a crypttab entry with tpm2-device=auto causes
// the init to attempt TPM2 token unlock.  Uses the swtpm software emulator.
func TestCrypttabTPM2(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID=5cbc48ce-0e78-4c6b-ac90-a8a540514b90 none tpm2-device=auto,x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/systemd-tpm2.img",
		params:       params,
		kernelArgs:   []string{"root=UUID=d8673e36-d4a3-4408-a87d-be0cb79f91a2"},
		crypttabFile: crypttabPath,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
