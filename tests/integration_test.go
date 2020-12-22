package tests

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
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
	kernelVersion string
	binariesDir   string
)

func detectKernelVersion() (string, error) {
	files, err := ioutil.ReadDir(kernelsDir)
	if err != nil {
		return "", err
	}
	versions := make([]string, 0, len(files))
	for _, v := range files {
		versions = append(versions, v.Name())
	}
	sort.Sort(sort.Reverse(sort.StringSlice(versions)))
	for _, v := range versions {
		path := filepath.Join(kernelsDir, v, "vmlinuz")
		_, err := os.Stat(path)
		if err == nil {
			return v, nil
		}
	}
	return "", fmt.Errorf("No kernel found under %v", kernelsDir)
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

	cmd := exec.Command(binariesDir+"/generator", "-force", "-initBinary", binariesDir+"/init", "-kernelVersion", kernelVersion, "-output", output, "-config", config)
	if testing.Verbose() {
		log.Print("Create booster.img")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Cannot generate booster.img: %v", err)
	}

	// check generated image integrity
	if err := exec.Command("/usr/bin/zstd", "--test", output).Run(); err != nil {
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
	Network   *NetworkConfig `yaml:",omitempty"`
	Universal bool           `yaml:",omitempty"`
	Modules   string         `yaml:",omitempty"`
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
	prompt      string
	enableTangd bool
	useDhcp     bool
	enableTpm2  bool
	kernelArgs  []string
	disk        string
	disks       []vmtest.QemuDisk
}

func boosterTest(opts Opts) func(*testing.T) {
	return func(t *testing.T) {
		// TODO: make this test run in parallel
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
			tangd, err := NewTangServer("assets/tang/cache")
			if err != nil {
				t.Fatal(err)
			}
			defer tangd.Stop()
			// using command directly like one below does not work as extra info is printed to stderr and QEMU incorrectly
			// assumes it is a part of HTTP reply
			// guestfwd=tcp:10.0.2.100:5697-cmd:/usr/lib/tangd ./assets/tang/cache 2>/dev/null

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

		options := vmtest.QemuOptions{
			OperatingSystem: vmtest.OS_LINUX,
			Kernel:          filepath.Join(kernelsDir, kernelVersion, "vmlinuz"),
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
		defer vm.Shutdown()

		if opts.prompt != "" {
			if err := vm.ConsoleExpect(opts.prompt); err != nil {
				t.Fatal(err)
			}
			const luksPassword = "1234"
			if err := vm.ConsoleWrite(luksPassword + "\n"); err != nil {
				t.Fatal(err)
			}
		}

		if err := vm.ConsoleExpect("Hello, booster!"); err != nil {
			t.Fatal(err)
		}
	}
}

func archLinuxTest(t *testing.T) {
	initRamfs, err := generateInitRamfs(Opts{})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(initRamfs)

	params := []string{"-net", "user,hostfwd=tcp::10022-:22", "-net", "nic", "-m", "8G", "-smp", strconv.Itoa(runtime.NumCPU())}
	if os.Getenv("TEST_DISABLE_KVM") != "1" {
		params = append(params, "-enable-kvm", "-cpu", "host")
	}
	opts := vmtest.QemuOptions{
		OperatingSystem: vmtest.OS_LINUX,
		Kernel:          filepath.Join(kernelsDir, kernelVersion, "vmlinuz"),
		InitRamFs:       initRamfs,
		Params:          params,
		Disks:           []vmtest.QemuDisk{{"assets/archlinux.raw", "raw"}},
		Append:          []string{"root=/dev/sda", "rw"},
		Verbose:         testing.Verbose(),
		Timeout:         50 * time.Second,
	}
	vm, err := vmtest.NewQemu(&opts)
	if err != nil {
		t.Fatal(err)
	}

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

	vm.Shutdown()
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
	kernelVersion, err = detectKernelVersion()
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

	// note that assets are generated using ./assets_generator tool
	t.Run("Ext4", boosterTest(Opts{
		disk:       "assets/ext4.img",
		kernelArgs: []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370", "rootflags=user_xattr,nobarrier"},
	}))

	t.Run("NonFormattedDrive", boosterTest(Opts{
		disks: []vmtest.QemuDisk{
			{ /* represents non-formatted drive */ "integration_test.go", "raw"},
			{"assets/ext4.img", "raw"},
		},
		kernelArgs: []string{"root=UUID=5c92fc66-7315-408b-b652-176dc554d370"},
	}))

	t.Run("LUKS1.WithName", boosterTest(Opts{
		disk:       "assets/luks1.img",
		prompt:     "Enter passphrase for cryptroot:",
		kernelArgs: []string{"rd.luks.name=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415=cryptroot", "root=/dev/mapper/cryptroot"},
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

	// Verify generated initrd against Arch Linux userspace with systemd
	t.Run("ArchLinux", archLinuxTest)
}
