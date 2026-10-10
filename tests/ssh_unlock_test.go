package tests

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anatol/vmtest"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

// pickFreePort asks the kernel for an unused TCP port. We close the listener
// immediately and hand the number to QEMU, so there is an inherent race between
// the close and QEMU's bind. The window is tiny, and the kernel does not hand
// the same ephemeral port out twice in quick succession, but with tests running
// concurrently it is no longer a theoretical concern — a bind failure here is
// worth suspecting before anything in the test itself.
func pickFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// sshForwardParams returns the qemu params forwarding a free host port to the
// guest's sshd, along with the address to dial.
func sshForwardParams(t *testing.T) (params []string, addr string) {
	t.Helper()
	port := strconv.Itoa(pickFreePort(t))
	return []string{"-net", "user,hostfwd=tcp:127.0.0.1:" + port + "-:22", "-net", "nic"},
		"127.0.0.1:" + port
}

// dialSSHWithRetry keeps dialling until the guest's sshd answers.  QEMU accepts
// a forwarded connection before the guest is listening and then resets it, so a
// single dial races the boot.
func dialSSHWithRetry(t *testing.T, addr string, config *gossh.ClientConfig, timeout time.Duration) *gossh.Client {
	t.Helper()

	// Count what each attempt hit: "refused" means qemu is not forwarding yet,
	// "reset" means it forwarded to a guest port with nothing listening, and a
	// handshake error means sshd answered but did not finish.
	kinds := map[string]int{}
	attempts := 0
	started := time.Now()

	deadline := started.Add(timeout)
	for {
		conn, err := gossh.Dial("tcp", addr, config)
		if err == nil {
			if attempts > 0 {
				t.Logf("ssh.Dial to %s succeeded after %d retries in %v %v", addr, attempts, time.Since(started).Round(time.Second), kinds)
			}
			return conn
		}
		attempts++
		kinds[classifyDialError(err)]++

		if time.Now().After(deadline) {
			// One last plain TCP connect: it separates "nothing is listening on
			// the host side" from "the forward works and the guest is not
			// answering", which the ssh error alone cannot distinguish.
			tcpState := "connect ok"
			if c, tcpErr := net.DialTimeout("tcp", addr, 5*time.Second); tcpErr != nil {
				tcpState = tcpErr.Error()
			} else {
				_ = c.Close()
			}
			require.NoError(t, err, "ssh.Dial to %s never succeeded within %v: %d attempts %v, raw tcp: %s",
				addr, timeout, attempts, kinds, tcpState)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// classifyDialError buckets a dial failure by what it says about the guest.
func classifyDialError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "connection reset"):
		return "reset"
	case strings.Contains(msg, "handshake"):
		return "handshake"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "EOF"):
		return "eof"
	default:
		return "other"
	}
}

// generateSSHKeyPair returns PEM-encoded private key bytes plus the
// OpenSSH authorized_keys line for the matching public key. Both halves of
// the pair are ed25519.
func generateSSHKeyPair(t *testing.T) (privPEM, authKeyLine []byte, signer gossh.Signer) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	block, err := gossh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	privPEM = pem.EncodeToMemory(block)

	sshPub, err := gossh.NewPublicKey(pub)
	require.NoError(t, err)
	authKeyLine = gossh.MarshalAuthorizedKey(sshPub)

	signer, err = gossh.NewSignerFromKey(priv)
	require.NoError(t, err)
	return
}

// TestSSHRemoteUnlock boots a LUKS2 root with SSH remote unlock enabled,
// connects from the host through a QEMU port forward, sends the passphrase,
// and verifies both the "Unlocked:" handshake and a normal boot completion.
func TestSSHRemoteUnlock(t *testing.T) {
	t.Parallel()

	require.NoError(t, checkAsset("assets/luks2.img"))

	tmp := t.TempDir()

	// Server-side host key + client public key (written as authorized_keys).
	hostPriv, _, _ := generateSSHKeyPair(t)
	_, clientAuthLine, clientSigner := generateSSHKeyPair(t)

	hostKeyPath := filepath.Join(tmp, "host_ed25519")
	require.NoError(t, os.WriteFile(hostKeyPath, hostPriv, 0o600))
	authKeysPath := filepath.Join(tmp, "authorized_keys")
	require.NoError(t, os.WriteFile(authKeysPath, clientAuthLine, 0o600))

	hostPort := pickFreePort(t)
	const guestPort = 2222

	vm, err := buildVmInstance(t, Opts{
		disk: "assets/luks2.img",
		// e1000 gives us a NIC inside early userspace; the booster init
		// only includes network modules when they're explicitly requested
		// or auto-detected, and we don't want to depend on host hardware.
		modules:       "e1000",
		enableNetwork: true,
		useDhcp:       true,
		params: []string{
			"-nic", "user,id=n1,hostfwd=tcp:127.0.0.1:" + strconv.Itoa(hostPort) + "-:" + strconv.Itoa(guestPort),
		},
		sshHostKeyPath:        hostKeyPath,
		sshAuthorizedKeysPath: authKeysPath,
		sshListen:             ":" + strconv.Itoa(guestPort),
		kernelArgs: []string{
			"rd.luks.name=639b8fdd-36ba-443e-be3e-e5b335935502=cryptroot",
			"root=/dev/mapper/cryptroot",
		},
		// Network bring-up + DHCP can take noticeably longer than the
		// 40s default before the SSH server is reachable.
		vmTimeout: 90 * time.Second,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// Wait for the LUKS prompt to appear on the console: that's our signal
	// that the device is registered as "pending" and the SSH server has
	// almost certainly bound its listener too.
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))

	clientCfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(clientSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Retry until QEMU's hostfwd is wired up and the guest is listening.
	addr := "127.0.0.1:" + strconv.Itoa(hostPort)
	var conn *gossh.Client
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn, err = gossh.Dial("tcp", addr, clientCfg)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			require.NoError(t, err, "ssh.Dial never succeeded")
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())

	// The server writes "Enter passphrase for <device>: " then reads a
	// CR/LF-terminated line. Read until we see the prompt, send the
	// passphrase, then look for "Unlocked: cryptroot" on the same channel.
	br := bufio.NewReader(stdout)
	require.NoError(t, readUntil(br, "Enter passphrase for ", 15*time.Second))
	_, err = io.WriteString(stdin, "1234\n")
	require.NoError(t, err)
	require.NoError(t, readUntil(br, "Unlocked: cryptroot", 15*time.Second))

	// The session ends as soon as the server reports success, so we don't
	// need to explicitly close stdin. The boot then proceeds to switch_root.
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestSSHRemoteUnlockMultiDeviceSharedPassphrase boots two LUKS volumes
// with the same passphrase and verifies that a single SSH submission
// unlocks both.
func TestSSHRemoteUnlockMultiDeviceSharedPassphrase(t *testing.T) {
	t.Parallel()

	require.NoError(t, checkAsset("assets/luks1.img"))
	require.NoError(t, checkAsset("assets/luks2.img"))

	tmp := t.TempDir()

	hostPriv, _, _ := generateSSHKeyPair(t)
	_, clientAuthLine, clientSigner := generateSSHKeyPair(t)

	hostKeyPath := filepath.Join(tmp, "host_ed25519")
	require.NoError(t, os.WriteFile(hostKeyPath, hostPriv, 0o600))
	authKeysPath := filepath.Join(tmp, "authorized_keys")
	require.NoError(t, os.WriteFile(authKeysPath, clientAuthLine, 0o600))

	hostPort := pickFreePort(t)
	const guestPort = 2222

	vm, err := buildVmInstance(t, Opts{
		disks: []vmtest.QemuDisk{
			{Path: "assets/luks2.img", Format: "raw"},
			{Path: "assets/luks1.img", Format: "raw"},
		},
		modules:       "e1000",
		enableNetwork: true,
		useDhcp:       true,
		params: []string{
			"-nic", "user,id=n1,hostfwd=tcp:127.0.0.1:" + strconv.Itoa(hostPort) + "-:" + strconv.Itoa(guestPort),
		},
		sshHostKeyPath:        hostKeyPath,
		sshAuthorizedKeysPath: authKeysPath,
		sshListen:             ":" + strconv.Itoa(guestPort),
		kernelArgs: []string{
			"rd.luks.name=639b8fdd-36ba-443e-be3e-e5b335935502=cryptroot",
			"rd.luks.name=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415=cryptdata",
			"root=/dev/mapper/cryptroot",
		},
		vmTimeout: 90 * time.Second,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// Wait until at least one device is prompting. Both should register
	// in pendingPrompts before SSH submits, but we only need to observe
	// one prompt to know the unlock path is live.
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for"))

	clientCfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(clientSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := "127.0.0.1:" + strconv.Itoa(hostPort)
	var conn *gossh.Client
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn, err = gossh.Dial("tcp", addr, clientCfg)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			require.NoError(t, err, "ssh.Dial never succeeded")
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())

	br := bufio.NewReader(stdout)
	require.NoError(t, readUntil(br, "Enter passphrase for ", 15*time.Second))
	_, err = io.WriteString(stdin, "1234\n")
	require.NoError(t, err)

	// One submission should produce two "Unlocked:" lines, one per
	// registered device. Order is non-deterministic (map iteration).
	require.NoError(t, readUntil(br, "Unlocked: ", 15*time.Second))
	require.NoError(t, readUntil(br, "Unlocked: ", 15*time.Second))

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestSSHRemoteUnlockBtrfsRaid1SharedPassphrase boots a btrfs RAID1 root
// whose two members are each wrapped in LUKS2 with the same passphrase.
// A single SSH submission unlocks both members via the broadcast path; the
// boot sequence must then poll BTRFS_IOC_DEVICES_READY (init/main.go's
// waitForBtrfsDevicesReady) until both mapper devices are present and the
// kernel reports the array assembled, before mountRootFs proceeds. The SSH
// listener must stay alive across that wait; if cleanup()/sshShutdown()
// fired early the second member's mapper-creation event would race against
// process replacement.
//
// Verifies the btrfs-multi-device wait gate: switch_root does NOT fire
// when *root* is unlocked, only when *root mount succeeds*, which for
// multi-device btrfs requires every member assembled.
func TestSSHRemoteUnlockBtrfsRaid1SharedPassphrase(t *testing.T) {
	t.Parallel()

	require.NoError(t, checkAsset("assets/luks2.btrfs_raid1.img"))

	tmp := t.TempDir()

	hostPriv, _, _ := generateSSHKeyPair(t)
	_, clientAuthLine, clientSigner := generateSSHKeyPair(t)

	hostKeyPath := filepath.Join(tmp, "host_ed25519")
	require.NoError(t, os.WriteFile(hostKeyPath, hostPriv, 0o600))
	authKeysPath := filepath.Join(tmp, "authorized_keys")
	require.NoError(t, os.WriteFile(authKeysPath, clientAuthLine, 0o600))

	// Mark both members x-initrd.attach so the generator includes them in
	// the image's /etc/crypttab. The SSH unlock then targets both via the
	// pendingPrompts broadcast.
	crypttabPath := filepath.Join(tmp, "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"luks-btrfs1 UUID=d7fb15c9-4e6a-4901-cd3f-3a579bdf1357 none x-initrd.attach\n"+
			"luks-btrfs2 UUID=e8ac26da-5f7b-4012-de40-4b68ace02468 none x-initrd.attach\n",
	), 0o644))

	hostPort := pickFreePort(t)
	const guestPort = 2222

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/luks2.btrfs_raid1.img",
		modules:       "e1000",
		enableNetwork: true,
		useDhcp:       true,
		crypttabFile:  crypttabPath,
		params: []string{
			"-nic", "user,id=n1,hostfwd=tcp:127.0.0.1:" + strconv.Itoa(hostPort) + "-:" + strconv.Itoa(guestPort),
		},
		sshHostKeyPath:        hostKeyPath,
		sshAuthorizedKeysPath: authKeysPath,
		sshListen:             ":" + strconv.Itoa(guestPort),
		kernelArgs:            []string{"root=UUID=f9bd37eb-607c-4123-ef51-5c79bdf13579"},
		vmTimeout:             120 * time.Second,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for"))

	clientCfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(clientSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := "127.0.0.1:" + strconv.Itoa(hostPort)
	var conn *gossh.Client
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn, err = gossh.Dial("tcp", addr, clientCfg)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			require.NoError(t, err, "ssh.Dial never succeeded")
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())

	br := bufio.NewReader(stdout)
	require.NoError(t, readUntil(br, "Enter passphrase for ", 15*time.Second))
	_, err = io.WriteString(stdin, "1234\n")
	require.NoError(t, err)

	// One submission unlocks both members via broadcast — two "Unlocked:"
	// lines, order non-deterministic. After both unlock, the SSH server's
	// next iteration finds pendingPrompts empty and emits the drain line.
	// The boot then blocks in waitForBtrfsDevicesReady until btrfs sees
	// both members; SSH stays alive throughout.
	require.NoError(t, readUntil(br, "Unlocked: ", 15*time.Second))
	require.NoError(t, readUntil(br, "Unlocked: ", 15*time.Second))
	require.NoError(t, readUntil(br, "All devices unlocked.", 15*time.Second))

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestSSHRemoteUnlockBtrfsRaid1DistinctPassphrase boots a btrfs RAID1 root
// whose two LUKS members carry DIFFERENT passphrases. Sequential SSH
// unlocks must both complete before btrfs assembles: the broadcast path
// only unlocks one member per submission (the passphrase cache cannot
// help cross-member here — distinct keys), so the SSH session must stay
// alive across two prompts. waitForBtrfsDevicesReady (init/main.go:606)
// is what keeps the boot sequence parked between the first and second
// unlock — without it, switch_root would fire as soon as the first LUKS
// member's mapper appeared (it never would in practice with btrfs, but
// the gate is what makes the multi-device case work cleanly).
//
// This is the legitimate-multi-device-in-initramfs case the boot
// sequence handles correctly. Non-root LUKS volumes on a non-multi-
// device root (e.g. ext4 root + extra ext4-shaped LUKS partition) are
// abandoned at switch_root and should be configured via post-boot
// userspace crypttab instead — outside the scope of this test.
func TestSSHRemoteUnlockBtrfsRaid1DistinctPassphrase(t *testing.T) {
	t.Parallel()

	require.NoError(t, checkAsset("assets/luks2.btrfs_raid1_distinct.img"))

	tmp := t.TempDir()

	hostPriv, _, _ := generateSSHKeyPair(t)
	_, clientAuthLine, clientSigner := generateSSHKeyPair(t)

	hostKeyPath := filepath.Join(tmp, "host_ed25519")
	require.NoError(t, os.WriteFile(hostKeyPath, hostPriv, 0o600))
	authKeysPath := filepath.Join(tmp, "authorized_keys")
	require.NoError(t, os.WriteFile(authKeysPath, clientAuthLine, 0o600))

	crypttabPath := filepath.Join(tmp, "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"luks-btrfs1 UUID=9b5d8ac8-342b-423d-b253-3d3a5403fee8 none x-initrd.attach\n"+
			"luks-btrfs2 UUID=461f9179-04f9-4def-9731-ac1598824026 none x-initrd.attach\n",
	), 0o644))

	hostPort := pickFreePort(t)
	const guestPort = 2222

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/luks2.btrfs_raid1_distinct.img",
		modules:       "e1000",
		enableNetwork: true,
		useDhcp:       true,
		crypttabFile:  crypttabPath,
		params: []string{
			"-nic", "user,id=n1,hostfwd=tcp:127.0.0.1:" + strconv.Itoa(hostPort) + "-:" + strconv.Itoa(guestPort),
		},
		sshHostKeyPath:        hostKeyPath,
		sshAuthorizedKeysPath: authKeysPath,
		sshListen:             ":" + strconv.Itoa(guestPort),
		kernelArgs:            []string{"root=UUID=aef9c3f8-2fbe-476f-b732-99f31226d601"},
		vmTimeout:             180 * time.Second,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for"))

	clientCfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(clientSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := "127.0.0.1:" + strconv.Itoa(hostPort)
	var conn *gossh.Client
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn, err = gossh.Dial("tcp", addr, clientCfg)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			require.NoError(t, err, "ssh.Dial never succeeded")
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())

	br := bufio.NewReader(stdout)

	// First prompt should name both members (order: alphabetical via
	// pendingDeviceNames' sort). luks-btrfs1 < luks-btrfs2.
	require.NoError(t, readUntil(br, "Enter passphrase for luks-btrfs1, luks-btrfs2:", 15*time.Second))

	// Submit passphrase for member 1 ("1111"). Broadcast tries against
	// both; only member 1's slot matches. SSH session continues
	// (cb07ce3 + cancel-on-success), reprompts with just member 2.
	_, err = io.WriteString(stdin, "1111\n")
	require.NoError(t, err)
	require.NoError(t, readUntil(br, "Unlocked: luks-btrfs1", 30*time.Second))
	require.NoError(t, readUntil(br, "Enter passphrase for luks-btrfs2:", 15*time.Second))

	// Submit member 2's passphrase ("2222"). Both members now unlocked;
	// btrfs's BTRFS_IOC_DEVICES_READY ioctl transitions to ready; root
	// mounts; switch_root fires.
	_, err = io.WriteString(stdin, "2222\n")
	require.NoError(t, err)
	require.NoError(t, readUntil(br, "Unlocked: luks-btrfs2", 30*time.Second))

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestSSHRemoteUnlockRejectsWrongClientKey verifies that a client whose
// public key isn't in authorized_keys cannot complete SSH auth — pubkey-only
// gate has to actually reject unknown keys, not just prefer authorized ones.
func TestSSHRemoteUnlockRejectsWrongClientKey(t *testing.T) {
	t.Parallel()

	require.NoError(t, checkAsset("assets/luks2.img"))

	tmp := t.TempDir()
	hostPriv, _, _ := generateSSHKeyPair(t)
	// Only the *first* client's public key is written into authorized_keys.
	_, authorizedAuthLine, _ := generateSSHKeyPair(t)
	// The *second* client (signer) is unauthorized; this is the one we dial.
	_, _, unauthorizedSigner := generateSSHKeyPair(t)

	hostKeyPath := filepath.Join(tmp, "host_ed25519")
	require.NoError(t, os.WriteFile(hostKeyPath, hostPriv, 0o600))
	authKeysPath := filepath.Join(tmp, "authorized_keys")
	require.NoError(t, os.WriteFile(authKeysPath, authorizedAuthLine, 0o600))

	hostPort := pickFreePort(t)
	const guestPort = 2222

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/luks2.img",
		modules:       "e1000",
		enableNetwork: true,
		useDhcp:       true,
		params: []string{
			"-nic", "user,id=n1,hostfwd=tcp:127.0.0.1:" + strconv.Itoa(hostPort) + "-:" + strconv.Itoa(guestPort),
		},
		sshHostKeyPath:        hostKeyPath,
		sshAuthorizedKeysPath: authKeysPath,
		sshListen:             ":" + strconv.Itoa(guestPort),
		kernelArgs: []string{
			"rd.luks.name=639b8fdd-36ba-443e-be3e-e5b335935502=cryptroot",
			"root=/dev/mapper/cryptroot",
		},
		vmTimeout: 60 * time.Second,
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))

	clientCfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(unauthorizedSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := "127.0.0.1:" + strconv.Itoa(hostPort)
	deadline := time.Now().Add(45 * time.Second)
	var dialErr error
	for {
		_, dialErr = gossh.Dial("tcp", addr, clientCfg)
		// We expect failure; once we see a "permission denied" / "no auth
		// methods" error we know the guest server rejected us properly.
		if dialErr != nil && (bytes.Contains([]byte(dialErr.Error()), []byte("unable to authenticate")) ||
			bytes.Contains([]byte(dialErr.Error()), []byte("no supported methods")) ||
			bytes.Contains([]byte(dialErr.Error()), []byte("handshake failed"))) {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.Error(t, dialErr, "ssh.Dial unexpectedly succeeded with an unauthorized client key")
	require.Failf(t, "auth rejection check exhausted", "last error: %v", dialErr)
}

// TestSSHRemoteUnlockRetryThenUnlock walks the prompt-loop retry paths:
// empty submission reprompts, wrong passphrase is reported, then the
// correct passphrase unlocks. All in a single SSH session.
func TestSSHRemoteUnlockRetryThenUnlock(t *testing.T) {
	t.Parallel()

	require.NoError(t, checkAsset("assets/luks2.img"))

	tmp := t.TempDir()
	hostPriv, _, _ := generateSSHKeyPair(t)
	_, clientAuthLine, clientSigner := generateSSHKeyPair(t)

	hostKeyPath := filepath.Join(tmp, "host_ed25519")
	require.NoError(t, os.WriteFile(hostKeyPath, hostPriv, 0o600))
	authKeysPath := filepath.Join(tmp, "authorized_keys")
	require.NoError(t, os.WriteFile(authKeysPath, clientAuthLine, 0o600))

	hostPort := pickFreePort(t)
	const guestPort = 2222

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/luks2.img",
		modules:       "e1000",
		enableNetwork: true,
		useDhcp:       true,
		params: []string{
			"-nic", "user,id=n1,hostfwd=tcp:127.0.0.1:" + strconv.Itoa(hostPort) + "-:" + strconv.Itoa(guestPort),
		},
		sshHostKeyPath:        hostKeyPath,
		sshAuthorizedKeysPath: authKeysPath,
		sshListen:             ":" + strconv.Itoa(guestPort),
		kernelArgs: []string{
			"rd.luks.name=639b8fdd-36ba-443e-be3e-e5b335935502=cryptroot",
			"root=/dev/mapper/cryptroot",
		},
		vmTimeout: 90 * time.Second,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))

	clientCfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(clientSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := "127.0.0.1:" + strconv.Itoa(hostPort)
	var conn *gossh.Client
	deadline := time.Now().Add(60 * time.Second)
	for {
		conn, err = gossh.Dial("tcp", addr, clientCfg)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			require.NoError(t, err, "ssh.Dial never succeeded")
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())

	br := bufio.NewReader(stdout)
	require.NoError(t, readUntil(br, "Enter passphrase for ", 15*time.Second))

	// Empty submission — server's prompt-loop should treat zero-length input
	// as a no-op and reprompt without trying to unlock anything.
	_, err = io.WriteString(stdin, "\n")
	require.NoError(t, err)
	require.NoError(t, readUntil(br, "Enter passphrase for ", 10*time.Second))

	// Wrong passphrase — KDF runs but no slot matches; expect the "no
	// pending devices matched" line plus another prompt.
	_, err = io.WriteString(stdin, "wrongpass\n")
	require.NoError(t, err)
	require.NoError(t, readUntil(br, "Passphrase did not unlock any device", 30*time.Second))
	require.NoError(t, readUntil(br, "Enter passphrase for ", 10*time.Second))

	// Correct passphrase unlocks.
	_, err = io.WriteString(stdin, "1234\n")
	require.NoError(t, err)
	require.NoError(t, readUntil(br, "Unlocked: cryptroot", 30*time.Second))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// TestSSHRemoteUnlockFido2Pending boots a LUKS volume whose only keyslot
// carries both a passphrase and a fake systemd-fido2 token. The init starts
// the FIDO2 attempt (which can't progress — no hidraw device matches the
// random credential) while the SSH server listens. The host SSHes in mid-
// FIDO2-wait and submits the passphrase; the concurrent passphrase path
// (init/luks.go: registerPendingPrompt runs at luksOpen entry, not gated
// behind tokenWg.Wait()) unlocks the slot and ctx-cancels the in-flight
// FIDO2 goroutine. Hardware-independent: same fixture as TestCrypttabFido2NoDevice.
func TestSSHRemoteUnlockFido2Pending(t *testing.T) {
	t.Parallel()

	if !fileExists(binariesDir + "/fido2plugin.so") {
		t.Skip("fido2plugin.so not built (libfido2 may not be installed)")
	}
	require.NoError(t, checkAsset("assets/systemd-fido2-nodev.img"))

	tmp := t.TempDir()

	hostPriv, _, _ := generateSSHKeyPair(t)
	_, clientAuthLine, clientSigner := generateSSHKeyPair(t)

	hostKeyPath := filepath.Join(tmp, "host_ed25519")
	require.NoError(t, os.WriteFile(hostKeyPath, hostPriv, 0o600))
	authKeysPath := filepath.Join(tmp, "authorized_keys")
	require.NoError(t, os.WriteFile(authKeysPath, clientAuthLine, 0o600))

	// crypttab fido2-device=auto triggers the generator to auto-bundle
	// fido2plugin.so and the init to attempt FIDO2 token unlock against the
	// device. With no real key plugged in, recoverSystemdFido2Password blocks
	// waiting for hidraw devices — that's the "pending" state we need.
	//
	// token-timeout is far beyond the test's lifetime on purpose: keyboard
	// fallback then cannot happen, so an unlock over SSH is necessarily
	// concurrent with the token attempt.
	crypttabPath := filepath.Join(tmp, "crypttab")
	require.NoError(t, os.WriteFile(crypttabPath, []byte(
		"cryptroot UUID=a6cdb03e-ad77-440a-8a93-28ad97de3b00 none fido2-device=auto,token-timeout=300,x-initrd.attach\n",
	), 0o644))

	hostPort := pickFreePort(t)
	const guestPort = 2222

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/systemd-fido2-nodev.img",
		modules:       "e1000",
		enableNetwork: true,
		useDhcp:       true,
		params: []string{
			"-nic", "user,id=n1,hostfwd=tcp:127.0.0.1:" + strconv.Itoa(hostPort) + "-:" + strconv.Itoa(guestPort),
		},
		sshHostKeyPath:        hostKeyPath,
		sshAuthorizedKeysPath: authKeysPath,
		sshListen:             ":" + strconv.Itoa(guestPort),
		crypttabFile:          crypttabPath,
		kernelArgs:            []string{"root=UUID=0cb4665f-65a0-4acc-9710-05163af16f19"},
		// Headroom for DHCP and the FIDO2 attempt warming up before we dial.
		vmTimeout: 90 * time.Second,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	clientCfg := &gossh.ClientConfig{
		User:            "root",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(clientSigner)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	addr := "127.0.0.1:" + strconv.Itoa(hostPort)
	var conn *gossh.Client
	deadline := time.Now().Add(20 * time.Second)
	for {
		conn, err = gossh.Dial("tcp", addr, clientCfg)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			require.NoError(t, err, "ssh.Dial never succeeded")
		}
		time.Sleep(500 * time.Millisecond)
	}
	defer conn.Close()

	sess, err := conn.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	require.NoError(t, err)
	stdout, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())

	br := bufio.NewReader(stdout)
	require.NoError(t, readUntil(br, "Enter passphrase for ", 15*time.Second))
	// systemd-fido2-nodev.img's keyslot 0 was formatted with passphrase 567.
	_, err = io.WriteString(stdin, "567\n")
	require.NoError(t, err)
	require.NoError(t, readUntil(br, "Unlocked: cryptroot", 15*time.Second))

	// The unlock cancels the in-flight FIDO2 attempt.  Assert the goroutine
	// said so rather than inferring it from the boot finishing: with
	// token-timeout at 300s a leaked goroutine would not delay switch_root, so
	// reaching "Hello, booster!" on its own proves nothing about cancellation.
	require.NoError(t, vm.ConsoleExpect("FIDO2 unlock for cryptroot cancelled while waiting for a device"))

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// readUntil drains the reader byte-by-byte until the needle appears as a
// substring, or until the timeout fires. The SSH channel may pack the
// prompt and response into the same read, so we can't rely on
// ReadString('\n'). The read blocks if the server stalls — we guard
// against that with a watchdog goroutine that closes the underlying
// session via the passed-in cancel.
func readUntil(br *bufio.Reader, needle string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	needleBytes := []byte(needle)
	var seen []byte

	for {
		if time.Now().After(deadline) {
			return io.EOF
		}
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		seen = append(seen, b)
		if bytes.Contains(seen, needleBytes) {
			return nil
		}
	}
}
