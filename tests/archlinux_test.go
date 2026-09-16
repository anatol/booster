package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/anatol/vmtest"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestArchLinuxExt4(t *testing.T) {
	// boot Arch userspace (with systemd) against all installed linux packages
	for pkg, ver := range kernelVersions {
		t.Run(pkg, func(t *testing.T) {
			compression := "zstd"
			if pkg == "linux-lts" {
				compression = "gzip"
			}

			controller := ""
			ext4RootDevice := "/dev/sda"
			if pkg == "linux-xanmod" {
				// xanmod compiles nvme as a standalone module
				// use it as an opportunity to verify 'nvme as a root device' functionality
				controller = "nvme,serial=boostfoo"
				ext4RootDevice = "/dev/nvme0n1"
			}
			testArchLinux(t, Opts{
				kernelVersion: ver,
				modules:       "e1000",
				compression:   compression,
				disks:         []vmtest.QemuDisk{{Path: "assets/archlinux.ext4.raw", Format: "raw", Controller: controller}},
				// If you need more debug logs append kernel args: "systemd.log_level=debug", "udev.log-priority=debug", "systemd.log_target=console", "log_buf_len=8M"
				kernelArgs: []string{"root=" + ext4RootDevice, "rw"},
			}, "", "")
		})
	}
}

// more complex setup with LUKS and btrfs subvolumes
func TestArchLinuxBtrfSubvolumes(t *testing.T) {
	// boot Arch userspace (with systemd) against all installed linux packages
	for pkg, ver := range kernelVersions {
		t.Run(pkg, func(t *testing.T) {
			compression := "zstd"
			if pkg == "linux-lts" {
				compression = "gzip"
			}

			testArchLinux(t, Opts{
				kernelVersion: ver,
				modules:       "e1000",
				compression:   compression,
				disk:          "assets/archlinux.btrfs.raw",
				kernelArgs:    []string{"rd.luks.uuid=724151bb-84be-493c-8e32-53e123c8351b", "root=UUID=15700169-8c12-409d-8781-37afa98442a8", "rootflags=subvol=@", "rw", "nmi_watchdog=0", "kernel.unprivileged_userns_clone=0", "net.core.bpf_jit_harden=2", "apparmor=1", "lsm=lockdown,yama,apparmor", "systemd.unified_cgroup_hierarchy=1", "add_efi_memmap"},
			},
				"Enter passphrase for luks-724151bb-84be-493c-8e32-53e123c8351b:", "hello")
		})
	}
}

func testArchLinux(t *testing.T, opts Opts, prompt, password string) {
	sshParams, sshAddr := sshForwardParams(t)
	opts.params = append(opts.params, sshParams...)

	// A full distro userspace booting to sshd, not just an initramfs: ~9s idle,
	// well past the 40s default once several VMs run at once.
	if opts.vmTimeout == 0 {
		opts.vmTimeout = 120 * time.Second
	}

	vm, err := buildVmInstance(t, opts)
	require.NoError(t, err)

	defer vm.Shutdown()

	if prompt != "" {
		require.NoError(t, vm.ConsoleExpect(prompt))
		require.NoError(t, vm.ConsoleWrite(password+"\n"))
	}

	// Gate on the guest saying sshd is listening.  This has to follow the
	// passphrase: an encrypted root sits in the initramfs until it is typed, so
	// waiting for sshd first would deadlock.  A resumed VM does not repeat the
	// message, so only a fresh boot can be gated on it.
	require.NoError(t, vm.ConsoleExpect("Started OpenSSH Daemon"))

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		// Without a timeout, a dial made before the guest's sshd exists blocks
		// for the whole boot and the retry loop never gets to retry.
		Timeout: 10 * time.Second,
	}

	conn := dialSSHWithRetry(t, sshAddr, config, opts.vmTimeout)
	defer conn.Close()

	sess, err := conn.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	out, err := sess.CombinedOutput("systemd-analyze")
	require.NoError(t, err)

	require.Contains(t, string(out), "(initrd)", "expect initrd time stats in systemd-analyze")

	// check writing to kmesg works
	sess3, err := conn.NewSession()
	require.NoError(t, err)
	defer sess3.Close()
	out, err = sess3.CombinedOutput("dmesg | grep -i booster")
	require.NoError(t, err)
	require.Contains(t, string(out), "Switching to the new userspace now", "expected to see debug output from booster")

	sessShutdown, err := conn.NewSession()
	require.NoError(t, err)
	defer sessShutdown.Close()
	// Arch Linux 5.4 does not shutdown with QEMU's 'shutdown' event for some reason. Force shutdown from ssh session.
	_ = sessShutdown.Run("shutdown now")
}

func TestArchLinuxHibernate(t *testing.T) {
	// boot Arch userspace (with systemd) against all installed linux packages
	for pkg, ver := range kernelVersions {
		t.Run(pkg, func(t *testing.T) {
			compression := "zstd"
			if pkg == "linux-lts" {
				compression = "gzip"
			}

			controller := ""
			if pkg == "linux-xanmod" {
				// xanmod compiles nvme as a standalone module
				// use it as an opportunity to verify 'nvme as a root device' functionality
				controller = "nvme,serial=boostfoo"
			}
			sshParams, sshAddr := sshForwardParams(t)
			// This test attaches a second disk for swap, and the two race for
			// /dev/sda: when the swap disk wins, root= names a swap partition
			// and the boot waits for a root filesystem that never appears.
			// Name the root by UUID, which does not depend on probe order.
			rootDisk := writableOverlay(t, "assets/archlinux.ext4.raw")
			// Read the UUID from the asset, not the overlay: blkid sees a qcow2
			// container there, not the filesystem inside it.
			rootRef := "UUID=" + fsUUID(t, "assets/archlinux.ext4.raw")
			opts := Opts{
				kernelVersion: ver,
				modules:       "e1000",
				compression:   compression,
				params:        sshParams,
				disks: []vmtest.QemuDisk{
					{Path: rootDisk, Format: "qcow2", Controller: controller},
					{Path: writableOverlay(t, "assets/swap.raw"), Format: "qcow2"},
				},
				// Full distro userspace, and it boots twice; see testArchLinux.
				vmTimeout: 120 * time.Second,
				// The second VM resumes from the hibernation image the first one
				// wrote, so these writes have to reach the disk rather than a
				// discarded overlay.
				persistent: true,
				kernelArgs: []string{"root=" + rootRef, "resume=UUID=5ec330f5-ac5e-48d2-98b6-87fd3e9b272f", "rw"},
			}

			vm, err := buildVmInstance(t, opts)
			require.NoError(t, err)
			// The guest powers itself off when it hibernates, so this is a no-op
			// on the happy path.  It matters when the test fails before that:
			// without it the VM outlives the test, holding the host port its
			// forward is bound to and the disks it was given.
			defer vm.Kill()

			// See testArchLinux: gate the dial on the guest, not on a timer.
			require.NoError(t, vm.ConsoleExpect("Started OpenSSH Daemon"))

			config := &ssh.ClientConfig{
				User:            "root",
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				// See the note in testArchLinux.
				Timeout: 10 * time.Second,
			}

			conn := dialSSHWithRetry(t, sshAddr, config, opts.vmTimeout)
			defer conn.Close()

			sess, err := conn.NewSession()
			require.NoError(t, err)
			defer sess.Close()
			out, err := sess.CombinedOutput("swapon -U 5ec330f5-ac5e-48d2-98b6-87fd3e9b272f -v")
			require.NoError(t, err, string(out))

			require.NoError(t, vm.ConsoleExpect("swap on /dev/sd"))

			sess2, err := conn.NewSession()
			require.NoError(t, err)
			defer sess2.Close()
			require.NoError(t, sess2.Run("systemctl hibernate"))

			require.NoError(t, vm.ConsoleExpect("PM: Image saving done"))

			// The resumed VM reuses this one's forwarded port, so wait for its
			// qemu to exit rather than assuming the guest powering itself off
			// has already released it.  Kill blocks until the process is gone
			// and is a no-op once it has.
			vm.Kill()

			// wakeing it up
			vm2, err := buildVmInstance(t, opts)
			require.NoError(t, err)
			defer vm2.Shutdown()

			require.NoError(t, vm2.ConsoleExpect("PM: Image loading done"))

			// Image loading done only means the image is in memory: tasks are
			// still frozen for another ~400ms and sshd cannot answer until they
			// thaw.  hibernation exit follows the thaw by ~6ms, so waiting for
			// it closes that window for nothing.
			require.NoError(t, vm2.ConsoleExpect("PM: hibernation: hibernation exit"))

			conn = dialSSHWithRetry(t, sshAddr, config, opts.vmTimeout)
			defer conn.Close()

			sess, err = conn.NewSession()
			require.NoError(t, err)
			defer sess.Close()
			// What matters after the resume is which kernel came back, not what
			// the image calls itself: asserting the hostname too made this fail
			// on any rootfs not built by the arch image these assets came from.
			out, err = sess.CombinedOutput("uname -sr")
			require.NoError(t, err, string(out))
			require.Equal(t, "Linux "+ver, strings.TrimSpace(string(out)),
				"resumed VM should be running the kernel it hibernated on")
		})
	}
}
