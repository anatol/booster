package tests

import (
	"flag"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/anatol/vmtest"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) {
	flag.Parse()

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
	sshParams, sshAddr := sshForwardParams(t)
	vm, err := buildVmInstance(t, Opts{
		modules:          "e1000", // add network module needed for ssh
		modulesForceLoad: "vfio_pci,vfio,vfio_iommu_type1",
		params:           sshParams,
		disk:             "assets/archlinux.ext4.raw",
		kernelArgs:       []string{"root=/dev/sda", "rw", "vfio-pci.ids=1002:67df,1002:aaf0"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", sshAddr, config)
	require.NoError(t, err)
	defer conn.Close()

	dmesg := runSSHCommand(t, conn, "dmesg")
	require.Contains(t, dmesg, "loading module vfio_pci params=\"ids=1002:67df,1002:aaf0\"", "expecting vfio_pci module loading")
	require.Contains(t, dmesg, "vfio_pci: add [1002:67df[ffffffff:ffffffff]] class 0x000000/00000000", "expecting vfio_pci 1002:67df device")
	require.Contains(t, dmesg, "vfio_pci: add [1002:aaf0[ffffffff:ffffffff]] class 0x000000/00000000", "expecting vfio_pci 1002:aaf0 device")

	re := regexp.MustCompile(`booster: udev event {Action:add KObj:/bus/pci/drivers/vfio-pci Env:map\[ACTION:add DEVPATH:/bus/pci/drivers/vfio-pci SEQNUM:\d+ SUBSYSTEM:drivers]}`)
	require.Regexp(t, re, dmesg, "expecting vfio_pci module loading udev event")
}

func TestNonFormattedDrive(t *testing.T) {
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
	swtpm, params, err := startSwtpm()
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
	vm, err := buildVmInstance(t, Opts{
		disks:      []vmtest.QemuDisk{{Path: "assets/gpt.img", Format: "raw", Controller: "nvme,serial=boostfoo"}},
		kernelArgs: []string{"root=/dev/nvme0n1p3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestUsb(t *testing.T) {
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
