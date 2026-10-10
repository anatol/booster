package tests

import (
	"flag"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/anatol/vmtest"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// defaultToSequential keeps an unflagged run one test at a time.  The tests call
// t.Parallel(), and -parallel defaults to GOMAXPROCS, so without this a plain
// `go test` would boot as many VMs as the machine has cores and interleave
// their console output.  Concurrency stays available, it just has to be asked
// for: -parallel N.
func defaultToSequential() {
	asked := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "test.parallel" {
			asked = true
		}
	})
	if asked {
		return
	}
	if err := flag.Set("test.parallel", "1"); err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	defaultToSequential()

	var err error
	kernelVersions, err = detectKernelVersion()
	if err != nil {
		panic(err)
	}

	binariesDir, err = os.MkdirTemp("", "")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(binariesDir)

	if err := compileBinaries(binariesDir); err != nil {
		panic(err)
	}

	if *bootstrapAssets {
		code := generateAllAssets()
		os.RemoveAll(binariesDir)
		os.Exit(code)
	}

	os.Exit(m.Run())
}

func TestExt4UUID(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		compression: "zstd",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370", "rootflags=user_xattr,nobarrier"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestExt4MountFlags(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		compression: "none",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370", "rootflags=user_xattr,noatime,nobarrier,nodev,dirsync,lazytime,nolazytime,dev,rw,ro", "rw"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestExt4Label(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		compression: "gzip",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=LABEL=atestlabel12"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestExt4Wwid(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/ext4.img",
		kernelArgs: []string{"root=WWID=scsi-QEMU_QEMU_HARDDISK_-0:0"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

// See TestGptHwpath for why ata_piix is excluded: it fixes the SCSI host
// number the virtio HBA receives, which the HWPATH= below hardcodes.
func TestExt4Hwpath(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/ext4.img",
		modules:    "-ata_piix",
		kernelArgs: []string{"root=HWPATH=pci-0000:00:04.0-scsi-0:0:0:0"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestInvalidInitBinary(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/ext4.img",
		kernelArgs: []string{"root=/dev/sda", "init=/foo/bar", "rw"},
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("booster: init binary /foo/bar does not exist in the user's chroot"))
}

// verifies module force loading + modprobe command-line parameters
func TestVfio(t *testing.T) {
	t.Parallel()

	sshParams, sshAddr := sshForwardParams(t)
	opts := Opts{
		modules:          "e1000", // add network module needed for ssh
		modulesForceLoad: "vfio_pci,vfio,vfio_iommu_type1",
		params:           sshParams,
		disk:             "assets/archlinux.ext4.raw",
		// log_buf_len: the assertions below grep dmesg for lines booster logs
		// from the initramfs, and the default 128K ring buffer wraps during a
		// full distro boot with booster.log=debug, dropping them.
		kernelArgs: []string{"root=/dev/sda", "rw", "vfio-pci.ids=1002:67df,1002:aaf0", "log_buf_len=8M"},
		// Boots a full distro userspace and waits for sshd, so the 40s default
		// is not enough once several VMs run at once.
		vmTimeout: 120 * time.Second,
	}
	vm, err := buildVmInstance(t, opts)
	require.NoError(t, err)
	defer vm.Shutdown()

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn := dialSSHWithRetry(t, sshAddr, config, opts.vmTimeout)
	defer conn.Close()

	// sshd can answer before booster's lines reach the ring buffer, so poll for
	// the module-load line rather than reading dmesg once.
	const loadLine = `loading module vfio_pci params="ids=1002:67df,1002:aaf0"`
	var dmesg string
	require.Eventually(t, func() bool {
		out, err := trySSHCommand(conn, "dmesg")
		if err != nil {
			return false // session hiccup under load; try again
		}
		dmesg = out
		return strings.Contains(dmesg, loadLine)
	}, 60*time.Second, 500*time.Millisecond, "expecting vfio_pci module loading")

	require.Contains(t, dmesg, "vfio_pci: add [1002:67df[ffffffff:ffffffff]] class 0x000000/00000000", "expecting vfio_pci 1002:67df device")
	require.Contains(t, dmesg, "vfio_pci: add [1002:aaf0[ffffffff:ffffffff]] class 0x000000/00000000", "expecting vfio_pci 1002:aaf0 device")
}

func TestNonFormattedDrive(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		compression: "none",
		disks: []vmtest.QemuDisk{
			{ /* represents non-formatted drive */ Path: "integration_test.go", Format: "raw"},
			{Path: "assets/ext4.img", Format: "raw"},
		},
		kernelArgs: []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestMountTimeout(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		kernelArgs:   []string{"root=/dev/nonexistent"},
		compression:  "xz",
		mountTimeout: 1,
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("Timeout waiting for root filesystem"))
}

func TestMountTimeoutWithAllModaliases(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		kernelArgs:          []string{"root=/dev/sda"},
		modules:             "-*",
		mountTimeout:        1,
		appendAllModAliases: true,
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("Timeout waiting for root filesystem"))
	require.NoError(t, vm.ConsoleExpect("Following modules were requested by kernel but not present in the image: ["))
}

func TestFsck(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		compression: "none",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=LABEL=atestlabel12"},
		extraFiles:  "fsck,fsck.ext4",
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestVirtualConsole(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		compression:          "none",
		disk:                 "assets/ext4.img",
		kernelArgs:           []string{"root=LABEL=atestlabel12"},
		enableVirtualConsole: true,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestStripBinaries(t *testing.T) {
	t.Parallel()

	swtpm, params, err := startSwtpm(t)
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/luks2.clevis.tpm2.img",
		params:        params,
		stripBinaries: true,
		kernelArgs:    []string{"rd.luks.uuid=3756ba2c-1505-4283-8f0b-b1d1bd7b844f", "root=UUID=c3cc0321-fba8-42c3-ad73-d13f8826d8d7"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestStripKeepsModuleSignatures(t *testing.T) {
	t.Parallel()

	// the booting kernel trusts these modules' signatures; sig_enforce rejects any that lost one
	kernelVersion := defaultKernelVersion(t)
	if !hostSignsModules(kernelVersion) {
		t.Skip("host kernel modules are unsigned, signature enforcement proves nothing here")
	}

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/ext4.img",
		stripBinaries: true,
		kernelVersion: kernelVersion,
		kernelArgs:    []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370", "module.sig_enforce=1"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestNvme(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		disks:      []vmtest.QemuDisk{{Path: "assets/gpt.img", Format: "raw", Controller: "nvme,serial=boostfoo"}},
		kernelArgs: []string{"root=/dev/nvme0n1p3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestUsb(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		disks:      []vmtest.QemuDisk{{Path: "assets/gpt.img", Format: "raw", Controller: "usb-storage,bus=ehci.0"}},
		params:     []string{"-device", "usb-ehci,id=ehci"},
		kernelArgs: []string{"root=/dev/sda3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLoadExtraModules(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/ext4.img",
		kernelArgs: []string{"root=LABEL=atestlabel12", "rd.modules_force_load=foo,xfs"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// Modules load concurrently, so the failure for the missing module and the
	// success for xfs arrive in either order.  ConsoleExpect only moves forward,
	// so asserting a fixed order fails whenever the boot picks the other one.
	const (
		missing = "booster: finit(foo): open /usr/lib/modules/foo.ko: no such file or directory"
		loaded  = "booster: loading module xfs"
	)
	either := regexp.MustCompile(`(` + regexp.QuoteMeta(missing) + `|` + regexp.QuoteMeta(loaded) + `)`)
	matches, err := vm.ConsoleExpectRE(either)
	require.NoError(t, err)
	if strings.Contains(matches[0], "finit(foo)") {
		require.NoError(t, vm.ConsoleExpect(loaded))
	} else {
		require.NoError(t, vm.ConsoleExpect(missing))
	}
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestISO(t *testing.T) {
	t.Parallel()

	vm, err := buildVmInstance(t, Opts{
		asIso:            true,
		modules:          "iso9660",
		modulesForceLoad: "iso9660",
		kernelArgs:       []string{"root=/dev/sr0", "ro"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("booster: mounting /dev/sr0->/booster.root, fs=iso9660, flags=0x1, options="))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}
