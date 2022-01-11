package tests

import (
	"testing"

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
				params:        []string{"-net", "user,hostfwd=tcp::10022-:22", "-net", "nic"},
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
				params:        []string{"-net", "user,hostfwd=tcp::10022-:22", "-net", "nic"},
				disk:          "assets/archlinux.btrfs.raw",
				kernelArgs:    []string{"rd.luks.uuid=724151bb-84be-493c-8e32-53e123c8351b", "root=UUID=15700169-8c12-409d-8781-37afa98442a8", "rootflags=subvol=@", "rw", "nmi_watchdog=0", "kernel.unprivileged_userns_clone=0", "net.core.bpf_jit_harden=2", "apparmor=1", "lsm=lockdown,yama,apparmor", "systemd.unified_cgroup_hierarchy=1", "add_efi_memmap"},
			},
				"Enter passphrase for luks-724151bb-84be-493c-8e32-53e123c8351b:", "hello")
		})
	}
}

func testArchLinux(t *testing.T, opts Opts, prompt, password string) {
	vm, err := buildVmInstance(t, opts)
	require.NoError(t, err)
	defer vm.Shutdown()

	if prompt != "" {
		require.NoError(t, vm.ConsoleExpect(prompt))
		require.NoError(t, vm.ConsoleWrite(password+"\n"))
	}

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", ":10022", config)
	require.NoError(t, err)
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
			ext4RootDevice := "/dev/sda"
			if pkg == "linux-xanmod" {
				// xanmod compiles nvme as a standalone module
				// use it as an opportunity to verify 'nvme as a root device' functionality
				controller = "nvme,serial=boostfoo"
				ext4RootDevice = "/dev/nvme0n1"
			}
			opts := Opts{
				kernelVersion: ver,
				modules:       "e1000",
				compression:   compression,
				params:        []string{"-net", "user,hostfwd=tcp::10022-:22", "-net", "nic"},
				disks: []vmtest.QemuDisk{
					{Path: "assets/archlinux.ext4.raw", Format: "raw", Controller: controller},
					{Path: "assets/swap.raw", Format: "raw"},
				},
				kernelArgs: []string{"root=" + ext4RootDevice, "resume=UUID=5ec330f5-ac5e-48d2-98b6-87fd3e9b272f", "rw"},
			}

			vm, err := buildVmInstance(t, opts)
			require.NoError(t, err)
			// defer vm.Shutdown()

			config := &ssh.ClientConfig{
				User:            "root",
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}

			conn, err := ssh.Dial("tcp", ":10022", config)
			require.NoError(t, err)
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

			// wakeing it up
			vm2, err := buildVmInstance(t, opts)
			require.NoError(t, err)
			defer vm2.Shutdown()

			require.NoError(t, vm2.ConsoleExpect("PM: Image loading done"))

			conn, err = ssh.Dial("tcp", ":10022", config)
			require.NoError(t, err)
			defer conn.Close()

			sess, err = conn.NewSession()
			require.NoError(t, err)
			defer sess.Close()
			out, err = sess.CombinedOutput("uname -a")
			require.NoError(t, err, string(out))
			require.Contains(t, string(out), "Linux archlinux "+ver)
		})
	}
}
