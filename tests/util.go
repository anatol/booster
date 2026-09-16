package tests

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anatol/booster/tests/israce"
	"github.com/anatol/tang.go"
	"github.com/anatol/vmtest"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// Per-VM sizing.  A guest is sized for the suite rather than for the host: a
// VM that claims every core bounds concurrency at two whatever the machine is,
// and the boot these tests measure does not go faster for the extra vCPUs.
var (
	vmSMP = flag.Int("vm.smp", 0, "vCPUs for each test VM (0: 4, or the host's core count when it has fewer)")
	vmMem = flag.String("vm.mem", "8G", "memory for each test VM")
	vmMax = flag.Int("vm.max", 0, "most VMs to run at once (0: derive from available memory)")
)

// Concurrency here is bounded by memory, not by CPU.  -parallel defaults to
// GOMAXPROCS, so on a large machine an unflagged `go test` would otherwise
// start one VM per core, each asking for -vm.mem — far past what the host can
// back.  Every VM takes a slot before it starts and returns it when the test
// ends, so -parallel tunes concurrency within a limit the machine can serve.
var (
	vmSlots     chan struct{}
	vmSlotsOnce sync.Once
)

// vmCPUs is how many vCPUs a test VM gets.  Four covers the only CPU-bound
// step in these boots, the argon2 KDF of a LUKS unlock: measured sequentially
// on a 32-core host, four is level with one-vCPU-per-core on every test and
// ahead on most, because bringing up 32 vCPUs costs the guest more than the
// parallelism returns, while two costs the unlock a second and a half.  A host
// with fewer cores than that gets one VM the size of the host.
func vmCPUs() int {
	if *vmSMP > 0 {
		return *vmSMP
	}
	if n := runtime.NumCPU(); n < 4 {
		return n
	}
	return 4
}

// autoVMLimit bounds how many VMs run at once when -vm.max is not given.
//
// Memory seldom binds: a guest's -m is an allocation the host backs only as the
// guest touches it, and these touch a fraction of what they are given.  CPU
// does bind — each VM gets -vm.smp vCPUs, and a host oversubscribed several
// times over misses console deadlines rather than running out of memory — so
// take the lower of the two bounds, allowing 2x oversubscription.  Without the
// CPU term, small guests multiply until they swamp the cores.
func autoVMLimit() int {
	per := parseMemSize(*vmMem)
	avail := memAvailableBytes()
	if per <= 0 || avail <= 0 {
		return 2 // no readings to go on; stay conservative
	}

	byMemory := int((avail * 7 / 10) / per)

	byCPU := 2 * runtime.NumCPU() / vmCPUs()

	n := byMemory
	if byCPU < n {
		n = byCPU
	}
	// The floor is applied by the caller, which also sees an explicit -vm.max.
	return n
}

// parseMemSize understands the qemu -m forms the tests use: a plain number of
// megabytes, or a K/M/G suffix.
func parseMemSize(s string) int64 {
	if s == "" {
		return 0
	}
	mult := int64(1 << 20) // qemu treats a bare number as megabytes
	switch s[len(s)-1] {
	case 'K', 'k':
		mult, s = 1<<10, s[:len(s)-1]
	case 'M', 'm':
		mult, s = 1<<20, s[:len(s)-1]
	case 'G', 'g':
		mult, s = 1<<30, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n * mult
}

func memAvailableBytes() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

// acquireVMSlot blocks until this test may start a VM, and releases the slot
// when the test finishes.
func acquireVMSlot(t *testing.T) {
	vmSlotsOnce.Do(func() {
		n := *vmMax
		if n <= 0 {
			n = autoVMLimit()
		}
		// A test may hold more than one slot at a time — TestArchLinuxHibernate
		// takes a second for the VM that resumes, and slots are only returned
		// when the test ends — so a limit below three can wedge it against
		// whatever else is running.
		if n < 3 {
			n = 3
		}
		if testing.Verbose() {
			fmt.Printf("limiting concurrent VMs to %d (-vm.max)\n", n)
		}
		vmSlots = make(chan struct{}, n)
	})

	vmSlots <- struct{}{}
	t.Cleanup(func() { <-vmSlots })
}

const kernelsDir = "/usr/lib/modules"

var (
	binariesDir    string // working dir shared between all tests
	kernelVersions map[string]string
)

func copyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	return io.Copy(destination, source)
}

// Note: if you see tpm2 tests fail with "integrity check failed" error make sure you pull clevis changes from
// https://github.com/latchset/clevis/issues/244
// startSwtpm gives each caller its own TPM state and control socket, so tests
// that need a TPM can run concurrently.
func startSwtpm(t *testing.T) (*os.Process, []string, error) {
	_ = os.Mkdir("assets", 0o755)

	if err := checkAsset("assets/tpm2/tpm2-00.permall.pristine"); err != nil {
		return nil, nil, err
	}

	dir := t.TempDir()
	if _, err := copyFile("assets/tpm2/tpm2-00.permall.pristine", filepath.Join(dir, "tpm2-00.permall")); err != nil {
		return nil, nil, err
	}
	sock := filepath.Join(dir, "swtpm-sock")

	cmd := exec.Command("swtpm", "socket", "--tpmstate", "dir="+dir, "--tpm2", "--ctrl", "type=unixio,path="+sock, "--flags", "not-need-init")
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, unwrapExitError(err)
	}

	if err := waitForFile(sock, 5*time.Second); err != nil {
		return nil, nil, err
	}
	if err := waitForSwtpmReady(sock, 5*time.Second); err != nil {
		return nil, nil, err
	}

	return cmd.Process, []string{"-chardev", "socket,id=chrtpm,path=" + sock, "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0"}, nil
}

// waitForSwtpmReady asks the control channel for its capabilities.  The socket
// appearing only means swtpm bound it, and a qemu that connects to one which is
// not answering yet still starts, leaving the guest with no TPM at all.
func waitForSwtpmReady(sock string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", sock, time.Second)
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		// CMD_GET_CAPABILITY, answered with an eight byte capability mask.
		if err := binary.Write(conn, binary.BigEndian, uint32(1)); err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, err = io.ReadFull(conn, make([]byte, 8)); err == nil {
				_ = conn.Close()
				return nil
			}
		}
		lastErr = err
		_ = conn.Close()
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("swtpm at %v did not answer its control channel: %v", sock, lastErr)
}

func startTangd() (*tang.NativeServer, []string, error) {
	_ = os.Mkdir("assets", 0o755)

	if err := checkAsset("assets/tang/key.pub"); err != nil {
		return nil, nil, err
	}

	tangd, err := tang.NewNativeServer("assets/tang", 0)
	if err != nil {
		return nil, nil, err
	}

	return tangd, []string{"-nic", fmt.Sprintf("user,id=n1,restrict=on,guestfwd=tcp:10.0.2.100:5697-tcp:localhost:%d", tangd.Port)}, nil
}

// createFido2LuksImage creates a temporary LUKS2 image with a FIDO2 token
// enrolled against the currently-connected FIDO2 device.  The image is written
// to t.TempDir() and cleaned up automatically when the test finishes.
//
// The returned luksUUID and fsUUID should be threaded through to the crypttab
// entry and kernel args of the QEMU VM so they match the generated image.
func createFido2LuksImage(t *testing.T, pin string) (luksUUID, fsUUID, imgPath string) {
	t.Helper()
	luksUUID = "b12cbfef-da87-429f-ac96-7dda7232c189"
	fsUUID = "bb351f0d-07f2-4fe4-bc53-d6ae39fa1c23"
	imgPath = filepath.Join(t.TempDir(), "fido2.img")
	require.NoError(t, shell("generators/systemd_fido2.sh",
		"OUTPUT="+imgPath,
		"LUKS_UUID="+luksUUID,
		"FS_UUID="+fsUUID,
		"LUKS_PASSWORD=567",
		"FIDO2_PIN="+pin,
	))
	return
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

func runSSHCommand(t *testing.T, conn *ssh.Client, command string) string {
	sessAnalyze, err := conn.NewSession()
	require.NoError(t, err)
	defer sessAnalyze.Close()

	out, err := sessAnalyze.CombinedOutput(command)
	require.NoError(t, err)

	return string(out)
}

// writableOverlay gives a test its own copy-on-write view of an asset, for the
// tests whose guest writes have to outlive the VM and so cannot use -snapshot.
// Writing straight to the asset would mutate what every other test of that
// distro reads.  A qcow2 overlay opens the asset read-only and costs a few
// hundred kilobytes, where copying the image costs its whole size on any
// filesystem without reflink.
func writableOverlay(t *testing.T, asset string) string {
	t.Helper()

	// Generate the source first if it is missing: the caller passes the overlay
	// to the VM, and a temp path would not be recognised as an asset to build.
	require.NoError(t, checkAsset(asset))

	// qemu resolves a relative backing path against the overlay's directory,
	// which is not where the asset is.
	backing, err := filepath.Abs(asset)
	require.NoError(t, err)

	// qemu-img ships separately from the emulator on some distributions, and
	// only this test needs it, so skip rather than fail the run over it.
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed, needed to overlay " + asset)
	}

	dst := filepath.Join(t.TempDir(), filepath.Base(asset)+".qcow2")
	out, err := exec.Command("qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", backing, dst).CombinedOutput()
	require.NoError(t, err, "qemu-img create %s: %s", dst, out)
	return dst
}

// fsUUID reads a filesystem UUID out of an image file.  Tests that attach more
// than one disk cannot name a root by kernel device: /dev/sda goes to whichever
// disk the SCSI probe reaches first, and with two disks that order is not
// stable across boots.
func fsUUID(t *testing.T, image string) string {
	t.Helper()

	out, err := exec.Command("blkid", "-o", "value", "-s", "UUID", image).Output()
	require.NoError(t, err, "blkid %s", image)
	uuid := strings.TrimSpace(string(out))
	require.NotEmpty(t, uuid, "no filesystem UUID in %s", image)
	return uuid
}

func shell(script string, env ...string) error {
	sh := exec.Command("bash", "-o", "errexit", script)
	sh.Env = append(os.Environ(), env...)
	sh.Env = append(sh.Env, "PATH="+generatorPath())

	// A bootstrap run exists to say why an image could not be built.
	if testing.Verbose() || *bootstrapAssets {
		sh.Stdout = os.Stdout
		sh.Stderr = os.Stderr
	}
	return unwrapExitError(sh.Run())
}

func fileExists(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}

// hostSignsModules reports whether this host's modules for kernelVersion are signed
func hostSignsModules(kernelVersion string) bool {
	var module string

	dir := filepath.Join(kernelsDir, kernelVersion, "kernel")
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // an unreadable subtree just means we keep looking
		}
		module = path
		return fs.SkipAll
	})
	if err != nil || module == "" {
		return false
	}

	// modinfo handles whatever compression the distribution packs modules with
	signer, err := exec.Command("modinfo", "-F", "signer", module).Output()

	return err == nil && len(bytes.TrimSpace(signer)) > 0
}

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
	output := filepath.Join(workDir, "booster.img")
	config := filepath.Join(workDir, "config.yaml")

	if err := generateBoosterConfig(config, opts); err != nil {
		return "", err
	}

	generatorArgs := []string{"build", "--force", "--init-binary", binariesDir + "/init", "--kernel-version", opts.kernelVersion, "--config", config}
	if opts.modulesDirectory != "" {
		generatorArgs = append(generatorArgs, "--modules-dir", opts.modulesDirectory)
	}
	crypttabArg := opts.crypttabFile
	if crypttabArg == "" {
		crypttabArg = "/dev/null" // tests run without root; avoid reading /etc/crypttab
	}
	generatorArgs = append(generatorArgs, "--crypttab", crypttabArg)
	generatorArgs = append(generatorArgs, output)
	cmd := exec.Command(binariesDir+"/generator", generatorArgs...)
	if testing.Verbose() {
		log.Print("Create booster.img with " + cmd.String())
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("Cannot generate booster.img: %v", unwrapExitError(err))
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
		return "", fmt.Errorf("unable to verify integrity of the output image %s: %v", output, unwrapExitError(err))
	}

	return output, nil
}

type NetworkConfig struct {
	Interfaces string `yaml:",omitempty"` // comma-separated list of interfaces to initialize at early-userspace

	Dhcp bool `yaml:",omitempty"`

	IP         string `yaml:",omitempty"` // e.g. 10.0.2.15/24
	Gateway    string `yaml:",omitempty"` // e.g. 10.0.2.255
	DNSServers string `yaml:"dns_servers,omitempty"`

	// SSH remote-unlock fields. The generator reads these as paths to files
	// on the host whose contents are embedded into the initramfs config.
	SshHostKey        string `yaml:"ssh_host_key,omitempty"`
	SshAuthorizedKeys string `yaml:"ssh_authorized_keys,omitempty"`
	SshListen         string `yaml:"ssh_listen,omitempty"`
}

type GeneratorConfig struct {
	Network              *NetworkConfig `yaml:",omitempty"`
	Universal            bool           `yaml:",omitempty"`
	Modules              string         `yaml:",omitempty"`
	ModulesForceLoad     string         `yaml:"modules_force_load,omitempty"` // comma separated list of extra modules to load at the boot time
	Compression          string         `yaml:",omitempty"`
	MountTimeout         string         `yaml:"mount_timeout,omitempty"`
	AppendAllModAliases  bool           `yaml:"append_all_modaliases,omitempty"`
	ExtraFiles           string         `yaml:"extra_files,omitempty"`
	StripBinaries        bool           `yaml:"strip,omitempty"` // strip symbols from the binaries, shared libraries and kernel modules
	EnableVirtualConsole bool           `yaml:"vconsole,omitempty"`
	EnableLVM            bool           `yaml:"enable_lvm"`
	EnableMdraid         bool           `yaml:"enable_mdraid"`
	MdraidConfigPath     string         `yaml:"mdraid_config_path"`
	EnableZfs            bool           `yaml:"enable_zfs"`
	ZfsImportParams      string         `yaml:"zfs_import_params"`
	ZfsCachePath         string         `yaml:"zfs_cache_path"`
	EnableFido2          bool           `yaml:"enable_fido2"`
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

		// SSH remote-unlock wiring. Test code writes the keypair + authorized_keys
		// to temp files and passes their paths through Opts; the generator
		// embeds the file contents into the initramfs.
		net.SshHostKey = opts.sshHostKeyPath
		net.SshAuthorizedKeys = opts.sshAuthorizedKeysPath
		net.SshListen = opts.sshListen
	}
	conf.Universal = true
	conf.Compression = opts.compression
	conf.MountTimeout = strconv.Itoa(opts.mountTimeout) + "s"
	conf.AppendAllModAliases = opts.appendAllModAliases
	conf.ExtraFiles = opts.extraFiles
	conf.StripBinaries = opts.stripBinaries
	conf.EnableVirtualConsole = opts.enableVirtualConsole
	conf.EnableLVM = opts.enableLVM
	conf.EnableMdraid = opts.enableMdraid
	conf.MdraidConfigPath = opts.mdraidConf
	conf.EnableZfs = opts.enableZfs
	conf.ZfsImportParams = opts.zfsImportParams
	conf.ZfsCachePath = opts.zfsCachePath
	conf.EnableFido2 = opts.enableFido2
	conf.Modules = opts.modules
	conf.ModulesForceLoad = opts.modulesForceLoad

	data, err := yaml.Marshal(&conf)
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, data, 0o644); err != nil {
		return err
	}
	return nil
}

type Opts struct {
	params           []string
	compression      string
	modules          string // extra modules to include into image
	modulesForceLoad string
	enableNetwork    bool
	useDhcp          bool
	activeNetIfaces  string
	kernelVersion    string // kernel version
	kernelPath       string
	modulesDirectory string
	kernelArgs       []string
	disk             string
	disks            []vmtest.QemuDisk
	containsESP      bool // specifies whether the disks contain ESP with bootloader/kernel/initramfs
	// persistent keeps guest writes in the backing image instead of discarding
	// them into a temporary overlay.  Only for a test whose writes must outlive
	// its VM: TestArchLinuxHibernate resumes a second VM from what the first one
	// wrote.  Left false, the image is opened read-only, so several tests can
	// boot the same asset at once and none of them can corrupt it.
	persistent           bool
	asIso                bool // generate ISO file instead of *.raw
	scriptEnvvars        []string
	mountTimeout         int           // in seconds
	vmTimeout            time.Duration // QEMU VM timeout; 0 = use default (40s)
	appendAllModAliases  bool
	extraFiles           string
	stripBinaries        bool
	enableVirtualConsole bool
	enableLVM            bool
	enableMdraid         bool
	mdraidConf           string
	enableZfs            bool
	zfsImportParams      string
	zfsCachePath         string // TODO: do we need any of these parameters?
	crypttabFile         string // path to host crypttab to bundle; overrides /etc/crypttab
	enableFido2          bool

	// SSH remote-unlock options. Paths are passed through to the generator,
	// which embeds the file contents into the initramfs config.
	sshHostKeyPath        string
	sshAuthorizedKeysPath string
	sshListen             string
}

// defaultKernelVersion picks the kernel for a test that does not name one:
// the "linux" package, else the running kernel, else the first by name.  Map
// order would vary per run, taking out-of-tree modules (zfs) with it.
func defaultKernelVersion(t *testing.T) string {
	t.Helper()

	if kernel, ok := kernelVersions["linux"]; ok {
		return kernel
	}
	require.NotEmpty(t, kernelVersions, "no kernel with a pkgbase found under "+kernelsDir)

	if running, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		want := strings.TrimSpace(string(running))
		for _, ver := range kernelVersions {
			if ver == want {
				return ver
			}
		}
	}

	pkgbases := make([]string, 0, len(kernelVersions))
	for pkgbase := range kernelVersions {
		pkgbases = append(pkgbases, pkgbase)
	}
	sort.Strings(pkgbases)
	return kernelVersions[pkgbases[0]]
}

// testLogWriter forwards VM output to t.Log, one line per call.  Go buffers
// t.Log per test and prints it under that test's heading, so a failing VM's
// console stays contiguous and attributed instead of interleaved.
type testLogWriter struct {
	t   *testing.T
	buf []byte
}

func (w *testLogWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(w.buf[:i]), "\r")
		w.buf = w.buf[i+1:]
		w.t.Log(line)
	}
	return len(p), nil
}

func buildVmInstance(t *testing.T, opts Opts) (*vmtest.Qemu, error) {
	acquireVMSlot(t)

	require.True(t, opts.disk == "" || len(opts.disks) == 0, "Opts.disk and Opts.disks cannot be specified together")
	require.False(t, opts.asIso && opts.containsESP)

	disks := opts.disks
	var isoFile string
	if strings.HasSuffix(opts.disk, ".iso") {
		isoFile = opts.disk
	} else if opts.disk != "" {
		disks = append(disks, vmtest.QemuDisk{Path: opts.disk, Format: "raw"})
	}
	for _, d := range disks {
		require.NoError(t, checkAsset(d.Path))
	}

	if opts.kernelVersion == "" {
		opts.kernelVersion = defaultKernelVersion(t)
	}

	workDir := t.TempDir()
	initRamfs, err := generateInitRamfs(workDir, opts)
	require.NoError(t, err)

	params := []string{"-m", *vmMem, "-smp", strconv.Itoa(vmCPUs())}
	if os.Getenv("TEST_DISABLE_KVM") != "1" {
		params = append(params, "-enable-kvm", "-cpu", "host")
	}

	kernelArgs := []string{"booster.log=debug", "printk.devkmsg=on"}
	kernelArgs = append(kernelArgs, opts.kernelArgs...)

	// to enable network dump
	// params = append(params, "-object", "filter-dump,id=f1,netdev=n1,file=network.dat")

	if !opts.persistent {
		params = append(params, "-snapshot")
	}
	params = append(params, opts.params...)

	// provide host's directory as a guest block device
	// disks = append(disks, vmtest.QemuDisk{Path: fmt.Sprintf("fat:ro:%s,read-only=on", filepath.Join(kernelsDir, opts.kernelVersion)), Format: "raw"})

	vmlinuzPath := opts.kernelPath
	if vmlinuzPath == "" {
		vmlinuzPath = filepath.Join(kernelsDir, opts.kernelVersion, "vmlinuz")
	}

	if opts.containsESP {
		params = append(params, "-bios", "/usr/share/edk2/x64/OVMF.4m.fd")

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
		require.NoError(t, shell("generators/esp.sh", env...))

		disks = append(disks, vmtest.QemuDisk{Path: output, Format: "raw"})
	}
	if opts.asIso {
		params = append(params, "-bios", "/usr/share/edk2/x64/OVMF.4m.fd")

		// ESP partition contains initramfs and cannot be statically built
		// we built the image at runtime
		isoFile = workDir + "/disk.iso"

		env := []string{
			"OUTPUT=" + isoFile,
			"KERNEL_IMAGE=" + vmlinuzPath,
			"KERNEL_OPTIONS=" + strings.Join(kernelArgs, " "),
			"INITRAMFS_IMAGE=" + initRamfs,
		}
		env = append(env, opts.scriptEnvvars...)
		require.NoError(t, shell("generators/iso.sh", env...))
	}

	vmTimeout := opts.vmTimeout
	if vmTimeout == 0 {
		vmTimeout = 40 * time.Second
	}
	options := vmtest.QemuOptions{
		Params:          params,
		OperatingSystem: vmtest.OS_LINUX,
		Disks:           disks,
		Verbose:         testing.Verbose(),
		Output:          &testLogWriter{t: t},
		Timeout:         vmTimeout,
	}
	if isoFile != "" {
		options.CdRom = isoFile
	}

	if !opts.containsESP {
		options.Kernel = vmlinuzPath
		options.InitRamFs = initRamfs
		options.Append = kernelArgs
	}

	return vmtest.NewQemu(&options)
}

func compileBinaries(dir string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	_ = os.Mkdir("assets", 0o755)

	if exists := fileExists("assets/init"); !exists {
		if err := exec.Command("gcc", "-static", "-o", "assets/init", "init/init.c").Run(); err != nil {
			return unwrapExitError(err)
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
	if testing.Verbose() {
		log.Print("Call 'go build' for init")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Cannot build init binary: %v", unwrapExitError(err))
	}

	// Build fido2plugin.so (best-effort: skipped silently if libfido2 is not installed)
	pluginCmd := exec.Command("go", "build", "-buildmode=plugin", "-o", dir+"/fido2plugin.so", "./fido2plugin")
	if testing.Verbose() {
		log.Print("Call 'go build' for fido2plugin")
		pluginCmd.Stdout = os.Stdout
		pluginCmd.Stderr = os.Stderr
	}
	if err := pluginCmd.Run(); err != nil && testing.Verbose() {
		log.Printf("fido2plugin.so build skipped (libfido2 may not be installed): %v", unwrapExitError(err))
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
		return fmt.Errorf("Cannot build generator binary: %v", unwrapExitError(err))
	}

	return os.Chdir(cwd)
}

func unwrapExitError(err error) error {
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("%v: %v", err, string(exitErr.Stderr))
	}
	return err
}
