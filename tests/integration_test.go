package tests

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"tests/israce"
	"time"

	"github.com/anatol/tang.go"
	"github.com/anatol/vmtest"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const kernelsDir = "/usr/lib/modules"

var (
	binariesDir    string // working dir with cross-test files like booster init/generator
	kernelVersions map[string]string
)

func detectKernelVersion() (map[string]string, error) {
	files, err := os.ReadDir(kernelsDir)
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
		pkgbase, err := os.ReadFile(filepath.Join(kernelsDir, ver, "pkgbase"))
		if err != nil {
			return nil, err
		}
		pkgbase = bytes.TrimSpace(pkgbase)

		kernels[string(pkgbase)] = ver
	}
	return kernels, nil
}

func generateInitRamfs(workDir string, opts Opts) (string, error) {
	output := path.Join(workDir, "booster.img")
	config := path.Join(workDir, "config.yaml")

	if err := generateBoosterConfig(config, opts); err != nil {
		return "", err
	}

	generatorArgs := []string{"build", "--force", "--init-binary", binariesDir + "/init", "--kernel-version", opts.kernelVersion, "--config", config}
	if opts.modulesDirectory != "" {
		generatorArgs = append(generatorArgs, "--modules-dir", opts.modulesDirectory)
	}
	generatorArgs = append(generatorArgs, output)
	cmd := exec.Command(binariesDir+"/generator", generatorArgs...)
	if testing.Verbose() {
		log.Print("Create booster.img with " + cmd.String())
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
		verifyCmd = exec.Command("cpio", "-i", "--only-verify-crc", "--file", output)
	case "zstd", "":
		verifyCmd = exec.Command("zstd", "--test", output)
	case "gzip":
		verifyCmd = exec.Command("gzip", "--test", output)
	case "xz":
		verifyCmd = exec.Command("xz", "--test", output)
	case "lz4":
		verifyCmd = exec.Command("lz4", "--test", output)
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
	Interfaces string `yaml:",omitempty"` // comma-separated list of interfaces to initialize at early-userspace

	Dhcp bool `yaml:",omitempty"`

	IP         string `yaml:",omitempty"` // e.g. 10.0.2.15/24
	Gateway    string `yaml:",omitempty"` // e.g. 10.0.2.255
	DNSServers string `yaml:"dns_servers,omitempty"`
}

type GeneratorConfig struct {
	Network              *NetworkConfig `yaml:",omitempty"`
	Universal            bool           `yaml:",omitempty"`
	Modules              string         `yaml:",omitempty"`
	ModulesForceLoad     string         `yaml:"modules_force_load,omitempty"` // comma separated list of extra modules to load at the boot time
	Compression          string         `yaml:",omitempty"`
	MountTimeout         string         `yaml:"mount_timeout,omitempty"`
	ExtraFiles           string         `yaml:"extra_files,omitempty"`
	StripBinaries        bool           `yaml:"strip,omitempty"` // strip symbols from the binaries, shared libraries and kernel modules
	EnableVirtualConsole bool           `yaml:"vconsole,omitempty"`
	EnableLVM            bool           `yaml:"enable_lvm"`
	EnableMdraid         bool           `yaml:"enable_mdraid"`
	MdraidConfigPath     string         `yaml:"mdraid_config_path"`
}

func generateBoosterConfig(output string, opts Opts) error {
	var conf GeneratorConfig

	if opts.enableNetwork {
		net := &NetworkConfig{}
		conf.Network = net

		if opts.useDhcp {
			net.Dhcp = true
		} else {
			net.IP = "10.0.2.15/24"
		}

		net.Interfaces = opts.activeNetIfaces
	}
	conf.Universal = true
	conf.Compression = opts.compression
	conf.MountTimeout = strconv.Itoa(opts.mountTimeout) + "s"
	conf.ExtraFiles = opts.extraFiles
	conf.StripBinaries = opts.stripBinaries
	conf.EnableVirtualConsole = opts.enableVirtualConsole
	conf.EnableLVM = opts.enableLVM
	conf.EnableMdraid = opts.enableMdraid
	conf.MdraidConfigPath = opts.mdraidConf
	conf.Modules = opts.modules
	conf.ModulesForceLoad = opts.modulesForceLoad

	data, err := yaml.Marshal(&conf)
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, data, 0644); err != nil {
		return err
	}
	return nil
}

type Opts struct {
	params               []string
	compression          string
	modules              string // extra modules to include into image
	modulesForceLoad     string
	enableNetwork        bool
	useDhcp              bool
	activeNetIfaces      string
	kernelVersion        string // kernel version
	kernelPath           string
	modulesDirectory     string
	kernelArgs           []string
	disk                 string
	disks                []vmtest.QemuDisk
	containsESP          bool // specifies whether the disks contain ESP with bootloader/kernel/initramfs
	scriptEnvvars        []string
	mountTimeout         int // in seconds
	extraFiles           string
	stripBinaries        bool
	enableVirtualConsole bool
	enableLVM            bool
	enableMdraid         bool
	mdraidConf           string
}

// Note: if you see tpm2 tests fail with "integrity check failed" error make sure you pull clevis changes from
// https://github.com/latchset/clevis/issues/244
func startSwtpm() (*os.Process, []string, error) {
	_ = os.Mkdir("assets", 0755)

	if exists := fileExists("assets/tpm2/tpm2-00.permall.pristine"); !exists {
		if err := shell("generate_asset_swtpm.sh"); err != nil {
			return nil, nil, err
		}
	}

	_ = os.Remove("assets/tpm2/.lock")
	_ = os.Remove("assets/swtpm-sock") // sometimes process crashes and leaves this file
	if _, err := copy("assets/tpm2/tpm2-00.permall.pristine", "assets/tpm2/tpm2-00.permall"); err != nil {
		return nil, nil, err
	}

	cmd := exec.Command("swtpm", "socket", "--tpmstate", "dir=assets/tpm2", "--tpm2", "--ctrl", "type=unixio,path=assets/swtpm-sock", "--flags", "not-need-init")
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	// wait till swtpm really starts
	if err := waitForFile("assets/swtpm-sock", 5*time.Second); err != nil {
		return nil, nil, err
	}

	return cmd.Process, []string{"-chardev", "socket,id=chrtpm,path=assets/swtpm-sock", "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0"}, nil
}

func startTangd() (*tang.NativeServer, []string, error) {
	_ = os.Mkdir("assets", 0755)

	if exists := fileExists("assets/tang/adv.json"); !exists {
		if err := shell("generate_asset_tang.sh"); err != nil {
			return nil, nil, err
		}
	}

	tangd, err := tang.NewNativeServer("assets/tang", 0)
	if err != nil {
		return nil, nil, err
	}

	return tangd, []string{"-nic", fmt.Sprintf("user,id=n1,restrict=on,guestfwd=tcp:10.0.2.100:5697-tcp:localhost:%d", tangd.Port)}, nil
}

func buildVmInstance(t *testing.T, opts Opts) (*vmtest.Qemu, error) {
	require.True(t, opts.disk == "" || len(opts.disks) == 0, "Opts.disk and Opts.disks cannot be specified together")

	disks := opts.disks
	if opts.disk != "" {
		disks = append(disks, vmtest.QemuDisk{Path: opts.disk, Format: "raw"})
	}
	for _, d := range disks {
		require.NoError(t, checkAsset(d.Path))
	}

	if opts.kernelVersion == "" {
		if kernel, ok := kernelVersions["linux"]; ok {
			opts.kernelVersion = kernel
		} else {
			require.Fail(t, "System does not have 'linux' package installed needed for the integration tests")
		}
	}

	workDir := t.TempDir()
	initRamfs, err := generateInitRamfs(workDir, opts)
	require.NoError(t, err)

	params := []string{"-m", "8G", "-smp", strconv.Itoa(runtime.NumCPU())}
	if os.Getenv("TEST_DISABLE_KVM") != "1" {
		params = append(params, "-enable-kvm", "-cpu", "host")
	}

	kernelArgs := []string{"booster.log=debug", "printk.devkmsg=on"}
	kernelArgs = append(kernelArgs, opts.kernelArgs...)

	// to enable network dump
	// params = append(params, "-object", "filter-dump,id=f1,netdev=n1,file=network.dat")

	params = append(params, opts.params...)

	// provide host's directory as a guest block device
	// disks = append(disks, vmtest.QemuDisk{Path: fmt.Sprintf("fat:ro:%s,read-only=on", filepath.Join(kernelsDir, opts.kernelVersion)), Format: "raw"})

	vmlinuzPath := opts.kernelPath
	if vmlinuzPath == "" {
		vmlinuzPath = filepath.Join(kernelsDir, opts.kernelVersion, "vmlinuz")
	}

	if opts.containsESP {
		params = append(params, "-bios", "/usr/share/ovmf/x64/OVMF.fd")

		// ESP partition contains initramfs and cannot be statically built
		// we built the image at runtime
		output := workDir + "/espdisk.raw"

		env := []string{
			"OUTPUT=" + output,
			"KERNEL_IMAGE=" + vmlinuzPath,
			"KERNEL_OPTIONS=" + strings.Join(kernelArgs, " "),
			"INITRAMFS_IMAGE=" + initRamfs,
		}
		env = append(env, opts.scriptEnvvars...)
		require.NoError(t, shell("generate_asset_esp.sh", env...))

		disks = append(disks, vmtest.QemuDisk{Path: output, Format: "raw"})
	}

	options := vmtest.QemuOptions{
		Params:          params,
		OperatingSystem: vmtest.OS_LINUX,
		Disks:           disks,
		Verbose:         testing.Verbose(),
		Timeout:         40 * time.Second,
	}

	if !opts.containsESP {
		options.Kernel = vmlinuzPath
		options.InitRamFs = initRamfs
		options.Append = kernelArgs
	}

	return vmtest.NewQemu(&options)
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

	_ = os.Mkdir("assets", 0755)

	if exists := fileExists("assets/init"); !exists {
		if err := exec.Command("gcc", "-static", "-o", "assets/init", "init/init.c").Run(); err != nil {
			return err
		}
	}

	// Build init binary
	if err := os.Chdir("../init"); err != nil {
		return err
	}
	raceFlag := ""
	if israce.Enabled {
		raceFlag = "-race"
	}
	cmd := exec.Command("go", "build", "-o", dir+"/init", "-tags", "test", raceFlag)
	cmd.Env = os.Environ()
	if !israce.Enabled {
		cmd.Env = append(cmd.Env, "CGO_ENABLED=0")
	}
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
	cmd = exec.Command("go", "build", "-o", dir+"/generator", "-tags", "test", raceFlag)
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

func runSSHCommand(t *testing.T, conn *ssh.Client, command string) string {
	sessAnalyze, err := conn.NewSession()
	require.NoError(t, err)
	defer sessAnalyze.Close()

	out, err := sessAnalyze.CombinedOutput(command)
	require.NoError(t, err)

	return string(out)
}

type assetGenerator struct {
	script string
	env    []string
}

var assetGenerators = map[string]assetGenerator{
	"assets/ext4.img":                 assetGenerator{"generate_asset_ext4.sh", []string{"FS_UUID=5c92fc66-7315-408b-b652-176dc554d370", "FS_LABEL=atestlabel12"}},
	"assets/luks1.img":                assetGenerator{"generate_asset_luks.sh", []string{"LUKS_VERSION=1", "LUKS_PASSWORD=1234", "LUKS_UUID=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415", "FS_UUID=ec09a1ea-d43c-4262-b701-bf2577a9ab27"}},
	"assets/luks2.img":                assetGenerator{"generate_asset_luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=639b8fdd-36ba-443e-be3e-e5b335935502", "FS_UUID=7bbf9363-eb42-4476-8c1c-9f1f4d091385"}},
	"assets/luks1.clevis.tpm2.img":    assetGenerator{"generate_asset_luks.sh", []string{"LUKS_VERSION=1", "LUKS_PASSWORD=1234", "LUKS_UUID=28c2e412-ab72-4416-b224-8abd116d6f2f", "FS_UUID=2996cec0-16fd-4f1d-8bf3-6606afa77043", "CLEVIS_PIN=tpm2", "CLEVIS_CONFIG={}"}},
	"assets/luks1.clevis.tang.img":    assetGenerator{"generate_asset_luks.sh", []string{"LUKS_VERSION=1", "LUKS_PASSWORD=1234", "LUKS_UUID=4cdaa447-ef43-42a6-bfef-89ebb0c61b05", "FS_UUID=c23aacf4-9e7e-4206-ba6c-af017934e6fa", "CLEVIS_PIN=tang", `CLEVIS_CONFIG={"url":"http://10.0.2.100:5697", "adv":"assets/tang/adv.json"}`}},
	"assets/luks2.clevis.tpm2.img":    assetGenerator{"generate_asset_luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=3756ba2c-1505-4283-8f0b-b1d1bd7b844f", "FS_UUID=c3cc0321-fba8-42c3-ad73-d13f8826d8d7", "CLEVIS_PIN=tpm2", "CLEVIS_CONFIG={}"}},
	"assets/luks2.clevis.tang.img":    assetGenerator{"generate_asset_luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=f2473f71-9a68-4b16-ae54-8f942b2daf50", "FS_UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a", "CLEVIS_PIN=tang", `CLEVIS_CONFIG={"url":"http://10.0.2.100:5697", "adv":"assets/tang/adv.json"}`}},
	"assets/luks2.clevis.yubikey.img": assetGenerator{"generate_asset_luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=f2473f71-9a61-4b16-ae54-8f942b2daf52", "FS_UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a", "CLEVIS_PIN=yubikey", `CLEVIS_CONFIG={"slot":2}`}},
	"assets/gpt.img":                  assetGenerator{"generate_asset_gpt.sh", []string{"FS_UUID=e5404205-ac6a-4e94-bb3b-14433d0af7d1", "FS_LABEL=newpart"}},
	"assets/gpt_4ksector.img":         assetGenerator{"generate_asset_gpt_4ksector.sh", nil},
	"assets/lvm.img":                  assetGenerator{"generate_asset_lvm.sh", []string{"FS_UUID=74c9e30c-506f-4106-9f61-a608466ef29c", "FS_LABEL=lvmr00t"}},
	"assets/mdraid_raid1.img":         assetGenerator{"generate_asset_mdraid_raid1.sh", []string{"FS_UUID=98b1a905-3c72-42f0-957a-6c23b303b1fd", "FS_LABEL=boosmdraid"}},
	"assets/mdraid_raid5.img":         assetGenerator{"generate_asset_mdraid_raid5.sh", []string{"FS_UUID=e62c7dc0-5728-4571-b475-7745de2eef1e", "FS_LABEL=boosmdraid"}},
	"assets/archlinux.ext4.raw":       assetGenerator{"generate_asset_archlinux_ext4.sh", nil},
	"assets/archlinux.btrfs.raw":      assetGenerator{"generate_asset_archlinux_btrfs.sh", []string{"LUKS_PASSWORD=hello"}},
	"assets/voidlinux.img":            assetGenerator{"generate_asset_voidlinux.sh", nil},
	"assets/alpinelinux.img":          assetGenerator{"generate_asset_alpinelinux.sh", nil},
	"assets/systemd-fido2.img":        assetGenerator{"generate_asset_systemd_fido2.sh", []string{"LUKS_UUID=b12cbfef-da87-429f-ac96-7dda7232c189", "FS_UUID=bb351f0d-07f2-4fe4-bc53-d6ae39fa1c23", "LUKS_PASSWORD=567", "FIDO2_PIN=1111"}}, // use yubikey-manager-qt (or fido2-token -C) to setup FIDO2 pin value to 1111
	"assets/systemd-tpm2.img":         assetGenerator{"generate_asset_systemd_tpm2.sh", []string{"LUKS_UUID=5cbc48ce-0e78-4c6b-ac90-a8a540514b90", "FS_UUID=d8673e36-d4a3-4408-a87d-be0cb79f91a2", "LUKS_PASSWORD=567"}},
	"assets/systemd-recovery.img":     assetGenerator{"generate_asset_systemd_recovery.sh", []string{"LUKS_UUID=62020168-58b9-4095-a3d0-176403353d20", "FS_UUID=b0cfeb48-c1e2-459d-a327-4d611804ac24", "LUKS_PASSWORD=2211"}},
}

func checkAsset(file string) error {
	if !strings.HasPrefix(file, "assets/") {
		return nil
	}

	gen, ok := assetGenerators[file]
	if !ok {
		return fmt.Errorf("no generator for asset %s", file)
	}
	if exists := fileExists(file); exists {
		return nil
	}

	if testing.Verbose() {
		fmt.Printf("Generating asset %s\n", file)
	}
	env := append(gen.env, "OUTPUT="+file)
	err := shell(gen.script, env...)
	if err != nil {
		_ = os.Remove(file)
	}
	return err
}

func shell(script string, env ...string) error {
	sh := exec.Command("bash", "-o", "errexit", script)
	sh.Env = append(os.Environ(), env...)

	if testing.Verbose() {
		sh.Stdout = os.Stdout
		sh.Stderr = os.Stderr
	}
	return sh.Run()
}

func fileExists(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}

type usbdev struct {
	bus, device string
}

func (usb usbdev) toQemuParams() []string {
	return []string{"-usb", "-device", "usb-host,hostbus=" + usb.bus + ",hostaddr=" + usb.device}
}

// detectYubikeys checks if yubikeys tokens are present and uses it slot for tests
func detectYubikeys() ([]usbdev, error) {
	out, err := exec.Command("lsusb").CombinedOutput()
	if err != nil {
		return nil, err
	}

	yubikeys := make([]usbdev, 0)

	for _, l := range strings.Split(string(out), "\n") {
		if !strings.Contains(l, "Yubikey") {
			continue
		}

		re, err := regexp.Compile(`Bus 0*(\d+) Device 0*(\d+):`)
		if err != nil {
			return nil, err
		}

		m := re.FindAllStringSubmatch(l, -1)
		if m == nil {
			return nil, fmt.Errorf("lsusb does not match bus/device")
		}

		yubikeys = append(yubikeys, usbdev{m[0][1], m[0][2]})
	}

	return yubikeys, nil
}

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
	vm, err := buildVmInstance(t, Opts{
		modules:          "e1000", // add network module needed for ssh
		modulesForceLoad: "vfio_pci,vfio,vfio_iommu_type1,vfio_virqfd",
		params:           []string{"-net", "user,hostfwd=tcp::10022-:22", "-net", "nic"},
		disks:            []vmtest.QemuDisk{{Path: "assets/archlinux.ext4.raw", Format: "raw"}},
		kernelArgs:       []string{"root=/dev/sda", "rw", "vfio-pci.ids=1002:67df,1002:aaf0"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", ":10022", config)
	require.NoError(t, err)
	defer conn.Close()

	dmesg := runSSHCommand(t, conn, "dmesg")
	require.Contains(t, dmesg, "loading module vfio_pci params=\"ids=1002:67df,1002:aaf0\"", "expecting vfio_pci module loading")
	require.Contains(t, dmesg, "vfio_pci: add [1002:67df[ffffffff:ffffffff]] class 0x000000/00000000", "expecting vfio_pci 1002:67df device")
	require.Contains(t, dmesg, "vfio_pci: add [1002:aaf0[ffffffff:ffffffff]] class 0x000000/00000000", "expecting vfio_pci 1002:aaf0 device")

	re := regexp.MustCompile(`booster: udev event {Header:add@/bus/pci/drivers/vfio-pci Action:add Devpath:/bus/pci/drivers/vfio-pci Subsystem:drivers Seqnum:\d+ Vars:map\[ACTION:add DEVPATH:/bus/pci/drivers/vfio-pci SEQNUM:\d+ SUBSYSTEM:drivers]}`)
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

func TestXZImageCompression(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		compression: "xz",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGzipImageCompression(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		compression: "gzip",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLz4ImageCompression(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		compression: "lz4",
		disk:        "assets/ext4.img",
		kernelArgs:  []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
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

func TestLUKS1WithName(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks1.img",
		kernelArgs: []string{"rd.luks.name=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415=cryptroot", "root=/dev/mapper/cryptroot", "rd.luks.options=discard"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS1WithUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks1.img",
		kernelArgs: []string{"rd.luks.uuid=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415", "root=UUID=ec09a1ea-d43c-4262-b701-bf2577a9ab27"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-f0c89fd5-7e1e-4ecc-b310-8cd650bd5415:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2WithName(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.img",
		kernelArgs: []string{"rd.luks.name=639b8fdd-36ba-443e-be3e-e5b335935502=cryptroot", "root=/dev/mapper/cryptroot"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for cryptroot:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2WithUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.img",
		kernelArgs: []string{"rd.luks.uuid=639b8fdd-36ba-443e-be3e-e5b335935502", "root=UUID=7bbf9363-eb42-4476-8c1c-9f1f4d091385"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-639b8fdd-36ba-443e-be3e-e5b335935502:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2WithQuotesOverUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.img",
		kernelArgs: []string{"rd.luks.uuid=\"639b8fdd-36ba-443e-be3e-e5b335935502\"", "root=UUID=\"7bbf9363-eb42-4476-8c1c-9f1f4d091385\""},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-639b8fdd-36ba-443e-be3e-e5b335935502:"))
	require.NoError(t, vm.ConsoleWrite("1234\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2ClevisYubikey(t *testing.T) {
	yubikeys, err := detectYubikeys()
	require.NoError(t, err)
	if len(yubikeys) == 0 {
		t.Skip()
	}

	params := make([]string, 0)
	for _, y := range yubikeys {
		params = append(params, y.toQemuParams()...)
	}

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.clevis.yubikey.img",
		kernelArgs: []string{"rd.luks.uuid=f2473f71-9a61-4b16-ae54-8f942b2daf52", "root=UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a"},
		extraFiles: "ykchalresp",
		params:     params,
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS1ClevisTang(t *testing.T) {
	tangd, params, err := startTangd()
	require.NoError(t, err)
	defer tangd.Stop()

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/luks1.clevis.tang.img",
		enableNetwork: true,
		params:        params,
		kernelArgs:    []string{"rd.luks.uuid=4cdaa447-ef43-42a6-bfef-89ebb0c61b05", "root=UUID=c23aacf4-9e7e-4206-ba6c-af017934e6fa"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2ClevisTang(t *testing.T) {
	tangd, params, err := startTangd()
	require.NoError(t, err)
	defer tangd.Stop()

	vm, err := buildVmInstance(t, Opts{
		disk:          "assets/luks2.clevis.tang.img",
		enableNetwork: true,
		params:        params,
		kernelArgs:    []string{"rd.luks.uuid=f2473f71-9a68-4b16-ae54-8f942b2daf50", "root=UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2ClevisTangDHCP(t *testing.T) {
	tangd, params, err := startTangd()
	require.NoError(t, err)
	defer tangd.Stop()

	vm, err := buildVmInstance(t, Opts{
		disk:            "assets/luks2.clevis.tang.img",
		params:          params,
		enableNetwork:   true,
		useDhcp:         true,
		activeNetIfaces: "52-54-00-12-34-53,52:54:00:12:34:56,52:54:00:12:34:57", // 52:54:00:12:34:56 is QEMU's NIC address
		kernelArgs:      []string{"rd.luks.uuid=f2473f71-9a68-4b16-ae54-8f942b2daf50", "root=UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestInactiveNetwork(t *testing.T) {
	tangd, params, err := startTangd()
	require.NoError(t, err)
	defer tangd.Stop()

	vm, err := buildVmInstance(t, Opts{
		disk:            "assets/luks2.clevis.tang.img",
		params:          params,
		enableNetwork:   true,
		useDhcp:         true,
		activeNetIfaces: "52:54:00:12:34:57", // 52:54:00:12:34:56 is QEMU's NIC address
		kernelArgs:      []string{"rd.luks.uuid=f2473f71-9a68-4b16-ae54-8f942b2daf50", "root=UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a"},
		mountTimeout:    10,
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("Timeout waiting for root filesystem"))
}

func TestLUKS1ClevisTpm2(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks1.clevis.tpm2.img",
		params:     params,
		kernelArgs: []string{"rd.luks.uuid=28c2e412-ab72-4416-b224-8abd116d6f2f", "root=UUID=2996cec0-16fd-4f1d-8bf3-6606afa77043"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLUKS2ClevisTpm2(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/luks2.clevis.tpm2.img",
		params:     params,
		kernelArgs: []string{"rd.luks.uuid=3756ba2c-1505-4283-8f0b-b1d1bd7b844f", "root=UUID=c3cc0321-fba8-42c3-ad73-d13f8826d8d7"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLVMPath(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableLVM:  true,
		disk:       "assets/lvm.img",
		kernelArgs: []string{"root=/dev/booster_test_vg/booster_test_lv"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestLVMUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableLVM:  true,
		disk:       "assets/lvm.img",
		kernelArgs: []string{"root=UUID=74c9e30c-506f-4106-9f61-a608466ef29c"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestMdRaid1Path(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableMdraid: true,
		mdraidConf:   "assets/mdraid_raid1.img.array",
		disk:         "assets/mdraid_raid1.img",
		kernelArgs:   []string{"root=/dev/md/BoosterTestArray1"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestMdRaid1UUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableMdraid: true,
		mdraidConf:   "assets/mdraid_raid1.img.array",
		disk:         "assets/mdraid_raid1.img",
		kernelArgs:   []string{"root=UUID=98b1a905-3c72-42f0-957a-6c23b303b1fd"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestMdRaid5Path(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableMdraid: true,
		mdraidConf:   "assets/mdraid_raid5.img.array",
		disk:         "assets/mdraid_raid5.img",
		kernelArgs:   []string{"root=/dev/md/BoosterTestArray5"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestMdRaid5UUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		enableMdraid: true,
		mdraidConf:   "assets/mdraid_raid5.img.array",
		disk:         "assets/mdraid_raid5.img",
		kernelArgs:   []string{"root=UUID=e62c7dc0-5728-4571-b475-7745de2eef1e"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptPath(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=/dev/sda3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=UUID=e5404205-ac6a-4e94-bb3b-14433d0af7d1"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptLABEL(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=LABEL=newpart"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptPARTUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=PARTUUID=1b8e9701-59a6-49f4-8c31-b97c99cd52cf"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptPARTLABEL(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=PARTLABEL=раздел3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptPARTNROFF(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=PARTUUID=78073a8b-bdf6-48cc-918e-edb926b25f64/PARTNROFF=2"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptByUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=/dev/disk/by-uuid/e5404205-ac6a-4e94-bb3b-14433d0af7d1"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptByLABEL(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=/dev/disk/by-label/newpart"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptByPARTUUID(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=/dev/disk/by-partuuid/1b8e9701-59a6-49f4-8c31-b97c99cd52cf"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptByPARTLABEL(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/gpt.img",
		kernelArgs: []string{"root=/dev/disk/by-partlabel/раздел3"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptRootAutodiscoveryExt4(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		containsESP: true,
		kernelArgs:  []string{"console=ttyS0,115200", "ignore_loglevel"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("booster: mounting /dev/sda2->/booster.root, fs=ext4, flags=0x0, options="))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptRootAutodiscoveryLUKS(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		containsESP:   true,
		scriptEnvvars: []string{"ENABLE_LUKS=1"},
		kernelArgs:    []string{"console=ttyS0,115200", "ignore_loglevel"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Enter passphrase for root:"))
	require.NoError(t, vm.ConsoleWrite("66789\n"))
	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestGptRootAutodiscoveryNoAuto(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		containsESP:   true,
		scriptEnvvars: []string{"GPT_ATTR=63"},
		kernelArgs:    []string{"console=ttyS0,115200", "ignore_loglevel"},
		mountTimeout:  1,
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("booster: autodiscovery: partition /dev/sda2 has 'do not mount' GPT attribute, skip it"))
	require.NoError(t, vm.ConsoleExpect("Timeout waiting for root filesystem"))
}

func TestGptRootAutodiscoveryReadOnly(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		containsESP:   true,
		scriptEnvvars: []string{"GPT_ATTR=60"},
		kernelArgs:    []string{"console=ttyS0,115200", "ignore_loglevel"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("booster: mounting /dev/sda2->/booster.root, fs=ext4, flags=0x1, options="))
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

func TestGpt4kSector(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disks:      []vmtest.QemuDisk{{Path: "assets/gpt_4ksector.img", Format: "raw", DeviceParams: []string{"physical_block_size=4096", "logical_block_size=4096"}}},
		kernelArgs: []string{"root=PARTUUID=d4699213-6e73-41d5-ad81-3daf5dfcecfb"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestSystemdFido2(t *testing.T) {
	yubikeys, err := detectYubikeys()
	require.NoError(t, err)
	if len(yubikeys) == 0 {
		t.Skip()
	}

	params := make([]string, 0)
	for _, y := range yubikeys {
		params = append(params, y.toQemuParams()...)
	}
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-fido2.img",
		kernelArgs: []string{"rd.luks.uuid=b12cbfef-da87-429f-ac96-7dda7232c189", "root=UUID=bb351f0d-07f2-4fe4-bc53-d6ae39fa1c23"},
		params:     params,
		extraFiles: "fido2-assert",
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	pin := "1111"
	// there can be multiple Yubikeys, iterate over all "Enter PIN" requests
	re, err := regexp.Compile(`(Enter PIN for /dev/hidraw|Hello, booster!)`)
	require.NoError(t, err)
	for {
		matches, err := vm.ConsoleExpectRE(re)
		require.NoError(t, err)

		if matches[0] == "Hello, booster!" {
			break
		} else {
			require.NoError(t, vm.ConsoleWrite(pin+"\n"))
		}
	}
}

func TestSystemdTPM2(t *testing.T) {
	swtpm, params, err := startSwtpm()
	require.NoError(t, err)
	defer swtpm.Kill()

	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-tpm2.img",
		kernelArgs: []string{"rd.luks.uuid=5cbc48ce-0e78-4c6b-ac90-a8a540514b90", "root=UUID=d8673e36-d4a3-4408-a87d-be0cb79f91a2"},
		params:     params,
		extraFiles: "fido2-assert",
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	require.NoError(t, vm.ConsoleExpect("Hello, booster!"))
}

func TestSystemdRecovery(t *testing.T) {
	vm, err := buildVmInstance(t, Opts{
		disk:       "assets/systemd-recovery.img",
		kernelArgs: []string{"rd.luks.uuid=62020168-58b9-4095-a3d0-176403353d20", "root=UUID=b0cfeb48-c1e2-459d-a327-4d611804ac24"},
	})
	require.NoError(t, err)
	defer vm.Shutdown()

	// enter password manually as recovery file might not be ready at the time test initialized
	require.NoError(t, vm.ConsoleExpect("Enter passphrase for luks-62020168-58b9-4095-a3d0-176403353d20:"))

	password, err := os.ReadFile("assets/systemd.recovery.key")
	require.NoError(t, err)
	require.NoError(t, vm.ConsoleWrite(string(password)+"\n"))
}

func TestVoidLinux(t *testing.T) {
	require.NoError(t, checkAsset("assets/voidlinux.img")) // it will generate vmlinuz-version needed later

	voidlinuxKernelVersion, err := os.ReadFile("assets/voidlinux/vmlinuz-version")
	require.NoError(t, err)
	vm, err := buildVmInstance(t, Opts{
		modulesDirectory: "assets/voidlinux/modules",
		kernelPath:       "assets/voidlinux/vmlinuz",
		kernelVersion:    string(voidlinuxKernelVersion),
		disk:             "assets/voidlinux.img",
		kernelArgs:       []string{"root=/dev/sda"},
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("runsvchdir: default: current."))
}

func TestAlpineLinux(t *testing.T) {
	require.NoError(t, checkAsset("assets/alpinelinux.img")) // it will generate vmlinuz-version needed later

	alpinelinuxKernelVersion, err := os.ReadFile("assets/alpinelinux/vmlinuz-version")
	require.NoError(t, err)
	vm, err := buildVmInstance(t, Opts{
		modulesDirectory: "assets/alpinelinux/modules",
		kernelPath:       "assets/alpinelinux/vmlinuz",
		kernelVersion:    string(alpinelinuxKernelVersion),
		disk:             "assets/alpinelinux.img",
		kernelArgs:       []string{"root=/dev/sda"},
	})
	require.NoError(t, err)
	defer vm.Kill()

	require.NoError(t, vm.ConsoleExpect("Welcome to Alpine Linux"))
}

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
				disks:         []vmtest.QemuDisk{{Path: "assets/archlinux.btrfs.raw", Format: "raw"}},
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
	_, _ = sessShutdown.CombinedOutput("shutdown now")
}
