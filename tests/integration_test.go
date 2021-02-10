package tests

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anatol/vmtest"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const kernelsDir = "/usr/lib/modules"

var (
	binariesDir    string
	kernelVersions map[string]string
)

func detectKernelVersion() (map[string]string, error) {
	files, err := ioutil.ReadDir(kernelsDir)
	if err != nil {
		return nil, err
	}
	kernels := make(map[string]string)
	for _, f := range files {
		ver := f.Name()
		vmlinux := filepath.Join(kernelsDir, ver, "vmlinuz")
		if _, err := os.Stat(vmlinux); err != nil {
			continue
		}
		pkgbase, err := ioutil.ReadFile(filepath.Join(kernelsDir, ver, "pkgbase"))
		if err != nil {
			return nil, err
		}
		pkgbase = bytes.TrimSpace(pkgbase)

		kernels[string(pkgbase)] = ver
	}
	return kernels, nil
}

func generateInitRamfs(opts Opts) (string, error) {
	file, err := ioutil.TempFile("", "booster.img")
	if err != nil {
		return "", err
	}
	output := file.Name()
	if err := file.Close(); err != nil {
		return "", err
	}

	config, err := generateBoosterConfig(opts)
	if err != nil {
		return "", err
	}
	defer os.Remove(config)

	cmd := exec.Command(binariesDir+"/generator", "-force", "-initBinary", binariesDir+"/init", "-kernelVersion", opts.kernelVersion, "-output", output, "-config", config)
	if testing.Verbose() {
		log.Print("Create booster.img")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Cannot generate booster.img: %v", err)
	}

	// check generated image integrity
	var verifyCmd *exec.Cmd
	switch opts.compression {
	case "none":
		verifyCmd = exec.Command("/usr/bin/cpio", "-i", "--only-verify-crc", "--file", output)
	case "zstd", "":
		verifyCmd = exec.Command("/usr/bin/zstd", "--test", output)
	case "gzip":
		verifyCmd = exec.Command("/usr/bin/gzip", "--test", output)
	default:
		return "", fmt.Errorf("Unknown compression: %s", opts.compression)
	}
	if testing.Verbose() {
		verifyCmd.Stdout = os.Stdout
		verifyCmd.Stderr = os.Stderr
	}
	if err := verifyCmd.Run(); err != nil {
		return "", fmt.Errorf("unable to verify integrity of the output image %s: %v", output, err)
	}

	return output, nil
}

type NetworkConfig struct {
	Dhcp    bool   `yaml:",omitempty"`
	Ip      string `yaml:",omitempty"` // e.g. 10.0.2.15/24
	Gateway string `yaml:",omitempty"` // e.g. 10.0.2.255
}
type GeneratorConfig struct {
	Network      *NetworkConfig `yaml:",omitempty"`
	Universal    bool           `yaml:",omitempty"`
	Modules      string         `yaml:",omitempty"`
	Compression  string         `yaml:",omitempty"`
	MountTimeout string         `yaml:"mount_timeout,omitempty"`
	ExtraFiles   string         `yaml:"extra_files,omitempty"`
}

func generateBoosterConfig(opts Opts) (string, error) {
	file, err := ioutil.TempFile("", "booster.yaml")
	if err != nil {
		return "", err
	}

	var conf GeneratorConfig

	if opts.enableTangd { // tang requires network enabled
		net := &NetworkConfig{}
		conf.Network = net

		if opts.useDhcp {
			net.Dhcp = true
		} else {
			net.Ip = "10.0.2.15/24"
		}
	}
	conf.Universal = true
	conf.Compression = opts.compression
	conf.MountTimeout = strconv.Itoa(opts.mountTimeout) + "s"
	conf.ExtraFiles = opts.extraFiles

	data, err := yaml.Marshal(&conf)
	if err != nil {
		return "", err
	}
	if _, err = file.Write(data); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return file.Name(), nil
}

type Opts struct {
	params        []string
	compression   string
	prompt        string
	password      string
	enableTangd   bool
	useDhcp       bool
	enableTpm2    bool
	kernelVersion string // kernel version
	kernelArgs    []string
	disk          string
	disks         []vmtest.QemuDisk
	mountTimeout  int // in seconds
	extraFiles    string
	checkVmState  func(vm *vmtest.Qemu, t *testing.T)
	forceKill     bool // if true then kill VM rather than do a graceful shutdown
}

func boosterTest(opts Opts) func(*testing.T) {
	if opts.checkVmState == nil {
		// default simple check
		opts.checkVmState = func(vm *vmtest.Qemu, t *testing.T) {
			if err := vm.ConsoleExpect("Hello, booster!"); err != nil {
				t.Fatal(err)
			}
		}
	}
	const defaultLuksPassword = "1234"
	if opts.prompt != "" && opts.password == "" {
		opts.password = defaultLuksPassword
	}

	return func(t *testing.T) {
		// TODO: make this test run in parallel

		if kernel, ok := kernelVersions["linux"]; ok {
			opts.kernelVersion = kernel
		} else {
			t.Fatal("System does not have 'linux' package installed needed for the integration tests")
		}

		initRamfs, err := generateInitRamfs(opts)
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(initRamfs)

		params := []string{"-m", "8G", "-smp", strconv.Itoa(runtime.NumCPU())}
		if os.Getenv("TEST_DISABLE_KVM") != "1" {
			params = append(params, "-enable-kvm", "-cpu", "host")
		}

		kernelArgs := opts.kernelArgs
		if testing.Verbose() {
			kernelArgs = append(kernelArgs, "booster.debug=1")
		}

		if opts.enableTangd {
			tangd, err := NewTangServer("assets/tang")
			if err != nil {
				t.Fatal(err)
			}
			defer tangd.Stop()
			// using command directly like one below does not work as extra info is printed to stderr and QEMU incorrectly
			// assumes it is a part of HTTP reply
			// guestfwd=tcp:10.0.2.100:5697-cmd:/usr/lib/tangd ./assets/tang 2>/dev/null

			params = append(params, "-nic", fmt.Sprintf("user,id=n1,restrict=on,guestfwd=tcp:10.0.2.100:5697-tcp:localhost:%d", tangd.port))
		}

		if opts.enableTpm2 {
			cmd := exec.Command("swtpm", "socket", "--tpmstate", "dir=assets/tpm2", "--tpm2", "--ctrl", "type=unixio,path=assets/swtpm-sock", "--flags", "not-need-init")
			if testing.Verbose() {
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer cmd.Process.Kill()

			// wait till swtpm really starts
			if err := waitForFile("assets/swtpm-sock", 5*time.Second); err != nil {
				t.Fatal(err)
			}

			params = append(params, "-chardev", "socket,id=chrtpm,path=assets/swtpm-sock", "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0")
		}

		// to enable network dump
		// params = append(params, "-object", "filter-dump,id=f1,netdev=n1,file=network.dat")

		if opts.disk != "" && len(opts.disks) != 0 {
			t.Fatal("Opts.disk and Opts.disks cannot be specified together")
		}
		var disks []vmtest.QemuDisk
		if opts.disk != "" {
			disks = []vmtest.QemuDisk{{opts.disk, "raw"}}
		} else {
			disks = opts.disks
		}

		params = append(params, opts.params...)

		options := vmtest.QemuOptions{
			OperatingSystem: vmtest.OS_LINUX,
			Kernel:          filepath.Join(kernelsDir, opts.kernelVersion, "vmlinuz"),
			InitRamFs:       initRamfs,
			Params:          params,
			Append:          kernelArgs,
			Disks:           disks,
			Verbose:         testing.Verbose(),
			Timeout:         40 * time.Second,
		}
		vm, err := vmtest.NewQemu(&options)
		if err != nil {
			t.Fatal(err)
		}
		if opts.forceKill {
			defer vm.Kill()
		} else {
			defer vm.Shutdown()
		}

		if opts.prompt != "" {
			if err := vm.ConsoleExpect(opts.prompt); err != nil {
				t.Fatal(err)
			}
			if err := vm.ConsoleWrite(opts.password + "\n"); err != nil {
				t.Fatal(err)
			}
		}
		opts.checkVmState(vm, t)
	}
}

func waitForFile(filename string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		_, err := os.Stat(filename)
		if err == nil {
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("waitForFile: %v", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %v", filename)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func compileBinaries(dir string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	// Build init binary
	if err := os.Chdir("../init"); err != nil {
		return err
	}
	cmd := exec.Command("go", "build", "-o", dir+"/init")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if testing.Verbose() {
		log.Print("Call 'go build' for init")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Cannot build init binary: %v", err)
	}

	// Generate initramfs
	if err := os.Chdir("../generator"); err != nil {
		return err
	}
	cmd = exec.Command("go", "build", "-o", dir+"/generator")
	if testing.Verbose() {
		log.Print("Call 'go build' for generator")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Cannot build generator binary: %v", err)
	}

	return os.Chdir(cwd)
}

func createAssets() error {
	if _, err := os.Stat("assets"); !os.IsNotExist(err) {
		return err
	}
	fmt.Println("Creating test assets and disk image files, sudo may be required")

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	if err := os.Chdir("assets_generator"); err != nil {
		return err
	}
	if err := exec.Command("go", "build").Run(); err != nil {
		return err
	}

	args := []string{}
	if testing.Verbose() {
		args = append(args, "-verbose")
	}
	generator := exec.Command("./assets_generator", args...)
	if testing.Verbose() {
		generator.Stdout = os.Stdout
		generator.Stderr = os.Stderr
	}
	if err := generator.Run(); err != nil {
		return err
	}

	return os.Chdir(cwd)
}

func TestBooster(t *testing.T) {
	var err error
	kernelVersions, err = detectKernelVersion()
	if err != nil {
		t.Fatalf("unable to detect current Linux version: %v", err)
	}

	binariesDir = t.TempDir()
	if err := compileBinaries(binariesDir); err != nil {
		t.Fatal(err)
	}

	if err := createAssets(); err != nil {
		t.Fatal(err)
	}

	// TODO: add a test to verify the emergency shell functionality
	// VmTest uses sockets for console and it seems does not like the shell we launch

	// note that assets are generated using ./assets_generator tool
	t.Run("Ext4.UUID", boosterTest(Opts{
		compression: "zstd",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370", "rootflags=user_xattr,nobarrier"},
	}))
	t.Run("Ext4.Label", boosterTest(Opts{
		compression: "gzip",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=LABEL=atestlabel12"},
	}))

	t.Run("NonFormattedDrive", boosterTest(Opts{
		compression: "none",
		disks: []vmtest.QemuDisk{
			{ /* represents non-formatted drive */ "integration_test.go", "raw"},
			{"assets/ext4.img", "raw"},
		},
		kernelArgs: []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	}))

	t.Run("MountTimeout", boosterTest(Opts{
		mountTimeout: 1,
		forceKill:    true,
		checkVmState: func(vm *vmtest.Qemu, t *testing.T) {
			if err := vm.ConsoleExpect("Timeout waiting for root filesystem"); err != nil {
				t.Fatal(err)
			}
		},
	}))

	t.Run("LUKS1.WithName", boosterTest(Opts{
		disk:       "assets/luks1.img",
		prompt:     "Enter passphrase for cryptroot:",
		kernelArgs: []string{"rd.luks.name=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415=cryptroot", "root=/dev/mapper/cryptroot", "rd.luks.options=discard"},
	}))
	t.Run("LUKS1.WithUUID", boosterTest(Opts{
		disk:       "assets/luks1.img",
		prompt:     "Enter passphrase for luks-f0c89fd5-7e1e-4ecc-b310-8cd650bd5415:",
		kernelArgs: []string{"rd.luks.uuid=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415", "root=UUID=ec09a1ea-d43c-4262-b701-bf2577a9ab27"},
	}))

	t.Run("LUKS2.WithName", boosterTest(Opts{
		disk:       "assets/luks2.img",
		prompt:     "Enter passphrase for cryptroot:",
		kernelArgs: []string{"rd.luks.name=639b8fdd-36ba-443e-be3e-e5b335935502=cryptroot", "root=/dev/mapper/cryptroot"},
	}))
	t.Run("LUKS2.WithUUID", boosterTest(Opts{
		disk:       "assets/luks2.img",
		prompt:     "Enter passphrase for luks-639b8fdd-36ba-443e-be3e-e5b335935502:",
		kernelArgs: []string{"rd.luks.uuid=639b8fdd-36ba-443e-be3e-e5b335935502", "root=UUID=7bbf9363-eb42-4476-8c1c-9f1f4d091385"},
	}))

	t.Run("LUKS1.Clevis.Tang", boosterTest(Opts{
		disk:        "assets/luks1.clevis.tang.img",
		enableTangd: true,
		kernelArgs:  []string{"rd.luks.uuid=4cdaa447-ef43-42a6-bfef-89ebb0c61b05", "root=UUID=c23aacf4-9e7e-4206-ba6c-af017934e6fa"},
	}))
	t.Run("LUKS2.Clevis.Tang", boosterTest(Opts{
		disk:        "assets/luks2.clevis.tang.img",
		enableTangd: true,
		kernelArgs:  []string{"rd.luks.uuid=f2473f71-9a68-4b16-ae54-8f942b2daf50", "root=UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a"},
	}))
	t.Run("LUKS2.Clevis.Tang.DHCP", boosterTest(Opts{
		disk:        "assets/luks2.clevis.tang.img",
		enableTangd: true,
		useDhcp:     true,
		kernelArgs:  []string{"rd.luks.uuid=f2473f71-9a68-4b16-ae54-8f942b2daf50", "root=UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a"},
	}))

	t.Run("LUKS1.Clevis.Tpm2", boosterTest(Opts{
		disk:       "assets/luks1.clevis.tpm2.img",
		enableTpm2: true,
		kernelArgs: []string{"rd.luks.uuid=28c2e412-ab72-4416-b224-8abd116d6f2f", "root=UUID=2996cec0-16fd-4f1d-8bf3-6606afa77043"},
	}))
	t.Run("LUKS2.Clevis.Tpm2", boosterTest(Opts{
		disk:       "assets/luks2.clevis.tpm2.img",
		enableTpm2: true,
		kernelArgs: []string{"rd.luks.uuid=3756ba2c-1505-4283-8f0b-b1d1bd7b844f", "root=UUID=c3cc0321-fba8-42c3-ad73-d13f8826d8d7"},
	}))

	// boot Arch userspace (with systemd) against all installed linux packages
	for pkg, ver := range kernelVersions {
		compression := "zstd"
		if pkg == "linux-lts" {
			compression = "gzip"
		}
		checkVmState := func(vm *vmtest.Qemu, t *testing.T) {
			config := &ssh.ClientConfig{
				User:            "root",
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}

			conn, err := ssh.Dial("tcp", ":10022", config)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			sess, err := conn.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()

			out, err := sess.CombinedOutput("systemd-analyze")
			if err != nil {
				t.Fatal(err)
			}

			if !strings.Contains(string(out), "(initrd)") {
				t.Fatalf("expect initrd time stats in systemd-analyze, got '%s'", string(out))
			}

			sess2, err := conn.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer sess2.Close()
			// Arch Linux 5.4 does not shutdown with QEMU's 'shutdown' event for some reason. Force shutdown from ssh session.
			_, _ = sess2.CombinedOutput("shutdown now")
		}

		// simple ext4 image
		t.Run("ArchLinux.ext4."+pkg, boosterTest(Opts{
			kernelVersion: ver,
			compression:   compression,
			params:        []string{"-net", "user,hostfwd=tcp::10022-:22", "-net", "nic"},
			disks:         []vmtest.QemuDisk{{"assets/archlinux.ext4.raw", "raw"}},
			// If you need more debug logs append kernel args: "systemd.log_level=debug", "udev.log-priority=debug", "systemd.log_target=console", "log_buf_len=8M"
			kernelArgs:   []string{"root=/dev/sda", "rw"},
			checkVmState: checkVmState,
		}))

		// more complex setup with LUKS and btrfs subvolumes
		t.Run("ArchLinux.btrfs."+pkg, boosterTest(Opts{
			kernelVersion: ver,
			compression:   compression,
			params:        []string{"-net", "user,hostfwd=tcp::10022-:22", "-net", "nic"},
			disks:         []vmtest.QemuDisk{{"assets/archlinux.btrfs.raw", "raw"}},
			kernelArgs:    []string{"rd.luks.uuid=724151bb-84be-493c-8e32-53e123c8351b", "root=UUID=15700169-8c12-409d-8781-37afa98442a8", "rootflags=subvol=@", "rw", "quiet", "nmi_watchdog=0", "kernel.unprivileged_userns_clone=0", "net.core.bpf_jit_harden=2", "apparmor=1", "lsm=lockdown,yama,apparmor", "systemd.unified_cgroup_hierarchy=1", "add_efi_memmap"},
			prompt:        "Enter passphrase for luks-724151bb-84be-493c-8e32-53e123c8351b:",
			password:      "hello",
			checkVmState:  checkVmState,
		}))
	}
}
