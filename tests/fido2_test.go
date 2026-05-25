package tests

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

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

// TestCtxAwareFido2CancelOnFallback verifies that when a systemd-fido2 token
// finds no matching device and keyboard fallback unlocks the volume, the FIDO2
// goroutine observes ctx cancellation and exits via the ctx-aware waitForUsbhid
// path — rather than pinning on a non-ctx-aware sync.WaitGroup.Wait() until
// switch_root.
//
// Asserts the info log emitted from the cancel branch of waitForUsbhid in
// recoverSystemdFido2Password. Without the ctx-aware primitives that log can
// never fire and the goroutine leaks.
func TestCtxAwareFido2CancelOnFallback(t *testing.T) {
	if !fileExists(binariesDir + "/fido2plugin.so") {
		t.Skip("fido2plugin.so not built (libfido2 may not be installed)")
	}

	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	// token-timeout=5 fires keyboard fallback fast, keeping test runtime short.
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID=a6cdb03e-ad77-440a-8a93-28ad97de3b00 none fido2-device=auto,token-timeout=5,x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         "assets/systemd-fido2-nodev.img",
		kernelArgs:   []string{"root=UUID=0cb4665f-65a0-4acc-9710-05163af16f19"},
		crypttabFile: crypttabPath,
		vmTimeout:    30 * time.Second,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// Keyboard fallback opens after the token-timeout.
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("567\n"))

	// Unlock cancels parent ctx; the FIDO2 goroutine's waitForUsbhid returns
	// ctx.Err() and logs from its cancel branch. This is the leak-fix proof.
	require.NoError(t, vm.ConsoleExpect("FIDO2 unlock for cryptroot cancelled before USB HID ready"))

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestCtxAwareFido2CancelMultiToken verifies that with multiple systemd-fido2
// tokens enrolled, every FIDO2 unlock goroutine observes ctx cancellation when
// keyboard fallback wins — not just one. Each token's recoverSystemdFido2Password
// runs in its own goroutine (non-PIN systemd-fido2 fans out in parallel) and
// blocks on waitForUsbhid; the cancel-path log must fire for each one.
//
// The 3-token image is built at test time by copying the 1-token
// systemd-fido2-nodev.img fixture and adding two more fake systemd-fido2 tokens
// via cryptsetup token import directly against the regular file (no sudo
// required since cryptsetup doesn't need root for token JSON metadata mutation
// on a user-owned LUKS file).
func TestCtxAwareFido2CancelMultiToken(t *testing.T) {
	if !fileExists(binariesDir + "/fido2plugin.so") {
		t.Skip("fido2plugin.so not built (libfido2 may not be installed)")
	}

	// Copy the base 1-token fixture so we don't mutate it.
	src := "assets/systemd-fido2-nodev.img"
	dst := filepath.Join(t.TempDir(), "fido2-nodev-multi.img")
	_, err := copyFile(src, dst)
	require.NoError(t, err)

	// Add 2 additional fake systemd-fido2 tokens with random credentials.
	// fido2-clientPin-required:false so they fan out in parallel (PIN tokens
	// would serialize, which we don't want — the point is to exercise
	// concurrent waitForUsbhid cancellation).
	for i := 0; i < 2; i++ {
		var cred, salt [32]byte
		_, err := rand.Read(cred[:])
		require.NoError(t, err)
		_, err = rand.Read(salt[:])
		require.NoError(t, err)
		tokenJSON := fmt.Sprintf(
			`{"type":"systemd-fido2","keyslots":["0"],"fido2-credential":"%s","fido2-salt":"%s","fido2-rp":"io.systemd.cryptsetup","fido2-clientPin-required":false,"fido2-up-required":true,"fido2-uv-required":false}`,
			base64.StdEncoding.EncodeToString(cred[:]),
			base64.StdEncoding.EncodeToString(salt[:]),
		)
		cmd := exec.Command("cryptsetup", "token", "import", "--json-file=-", dst)
		cmd.Stdin = strings.NewReader(tokenJSON)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "cryptsetup token import failed: %s", out)
	}

	crypttabPath := filepath.Join(t.TempDir(), "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID=a6cdb03e-ad77-440a-8a93-28ad97de3b00 none fido2-device=auto,token-timeout=5,x-initrd.attach\n",
	), 0o644))

	vm, err := buildVmInstance(t, Opts{
		disk:         dst,
		kernelArgs:   []string{"root=UUID=0cb4665f-65a0-4acc-9710-05163af16f19"},
		crypttabFile: crypttabPath,
		vmTimeout:    45 * time.Second,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// Keyboard fallback opens after token-timeout=5s.
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("567\n"))

	// All 3 FIDO2 goroutines (one per token) hit the cancel branch and log.
	// Each ConsoleExpect blocks until the next occurrence of the substring,
	// so 3 successive expects assert that the line appears at least 3 times
	// in the transcript before "Hello, booster!".
	for i := 0; i < 3; i++ {
		require.NoError(t, vm.ConsoleExpect("FIDO2 unlock for cryptroot cancelled before USB HID ready"))
	}
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
