package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

var compileAssetsMutex sync.Mutex

func prepareAssets(t *testing.T) {
	compileAssetsMutex.Lock()
	defer compileAssetsMutex.Unlock()

	if _, err := os.Stat("assets/test_module.ko"); os.IsNotExist(err) {
		cmd := exec.Command("make", "-C", "assets")
		if testing.Verbose() {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		require.NoError(t, cmd.Run())
		// compress with zst
		require.NoError(t, exec.Command("zstd", "-z", "assets/test_module.ko", "-o", "assets/test_module.ko.zst").Run())

		// compress with xz
		require.NoError(t, exec.Command("xz", "-z", "--keep", "assets/test_module.ko").Run())

		// compress with lz4
		cmd = exec.Command("lz4", "-z", "assets/test_module.ko")
		cmd.Stdout = os.Stdout // lz4 does not work without stdout, it is weird
		require.NoError(t, cmd.Run())

		// compress with gz
		require.NoError(t, exec.Command("gzip", "--keep", "assets/test_module.ko").Run())
	}
}

type options struct {
	workDir                      string
	compression                  string
	universal                    bool
	extraModules                 []string // modules to add to the image
	prepareModulesAt             []string // copy a test module to these locations
	signModulesAt                []string // same, with a module signature appended
	unpackImage                  bool
	hostModules                  []string // modules as found under /proc/modules
	hostAliases                  []string // list of all aliases for the host devices
	kernelAliases                []alias  // aliases as found under kernel/modules.alias (pattern + corresponding module)
	softDeps                     []string
	builtin                      []string
	extraFiles                   []string
	modprobeOptions              map[string]string
	expectError                  string
	stripBinaries                bool
	stripExtraSections           []string
	enableLVM                    bool
	vConsoleConfig, localeConfig string
	enableMdraid                 bool
	mdraidConfigPath             string
	enableFido2                  bool
	enableClevis                 bool
}

func generateAliasesFile(aliases []alias) []byte {
	var buff bytes.Buffer

	for _, a := range aliases {
		buff.WriteString("alias ")
		buff.WriteString(a.pattern)
		buff.WriteString(" ")
		buff.WriteString(a.module)
		buff.WriteString("\n")
	}

	return buff.Bytes()
}

func generateSoftdepFile(deps []string) []byte {
	var buff bytes.Buffer

	for _, d := range deps {
		buff.WriteString("softdep ")
		buff.WriteString(d)
		buff.WriteString("\n")
	}

	return buff.Bytes()
}

func generateBuiltinFile(mods []string) []byte {
	return []byte(strings.Join(mods, "\n"))
}

func generateProcModulesFile(modules []string) []byte {
	var buff bytes.Buffer

	for _, m := range modules {
		buff.WriteString(m)
		// plus some random stuff that is currently skipped by booster
		buff.WriteString(" 16384 0 - Live 0x0000000000000000\n")
	}

	return buff.Bytes()
}

func createTestInitRamfs(t *testing.T, o *options) {
	t.Parallel()

	opts.Verbose = testing.Verbose()
	prepareAssets(t)

	wd := t.TempDir()
	o.workDir = wd

	modulesDir := filepath.Join(wd, "modules")
	require.NoError(t, os.Mkdir(modulesDir, 0o755))

	for _, l := range o.prepareModulesAt {
		loc := modulesDir + "/" + l
		dir := filepath.Dir(loc)
		require.NoError(t, exec.Command("mkdir", "-p", dir).Run())
		source := "assets/test_module.ko"
		switch filepath.Ext(loc) {
		case ".xz":
			source += ".xz"
		case ".zst":
			source += ".zst"
		case ".lz4":
			source += ".lz4"
		case ".gz":
			source += ".gz"
		}
		require.NoError(t, exec.Command("cp", source, loc).Run())
	}

	for _, l := range o.signModulesAt {
		loc := modulesDir + "/" + l
		require.NoError(t, os.MkdirAll(filepath.Dir(loc), 0o755))

		content, err := os.ReadFile("assets/test_module.ko")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(loc, appendModuleSignature(content), 0o644))
	}

	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin", generateBuiltinFile(o.builtin), 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin.modinfo", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.alias", generateAliasesFile(o.kernelAliases), 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.dep", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.softdep", generateSoftdepFile(o.softDeps), 0o644))
	require.NoError(t, os.WriteFile(wd+"/proc_modules", generateProcModulesFile(o.hostModules), 0o644))

	listAsSet := func(in []string) set {
		out := make(set)
		for _, a := range in {
			out[a] = true
		}
		return out
	}

	listAsFunc := func(in []string) func() (set, error) {
		return func() (set, error) { return listAsSet(in), nil }
	}

	compression := o.compression
	if compression == "" {
		compression = "none"
	}

	initBinary := "/usr/bin/false"
	if o.enableFido2 || o.enableClevis {
		initBinary = wd + "/init"
		require.NoError(t, os.WriteFile(initBinary, []byte("dummy"), 0o755))
		if o.enableFido2 {
			require.NoError(t, os.WriteFile(wd+"/fido2plugin.so", []byte("dummy"), 0o755))
		}
		if o.enableClevis {
			require.NoError(t, os.WriteFile(wd+"/clevisplugin.so", []byte("dummy"), 0o755))
		}
	}

	conf := generatorConfig{
		initBinary:          initBinary,
		compression:         compression,
		universal:           o.universal,
		kernelVersion:       "matestkernel",
		modulesDir:          modulesDir,
		output:              wd + "/booster.img",
		readDeviceAliases:   listAsFunc(o.hostAliases),
		readHostModules:     func(ver string) (set, error) { return listAsSet(o.hostModules), nil },
		readModprobeOptions: func() (map[string]string, error) { return o.modprobeOptions, nil },
		extraFiles:          o.extraFiles,
		modules:             o.extraModules,
		stripBinaries:       o.stripBinaries,
		stripExtraSections:  o.stripExtraSections,
		enableLVM:           o.enableLVM,
		enableMdraid:        o.enableMdraid,
		mdraidConfigPath:    o.mdraidConfigPath,
		enableFido2:         o.enableFido2,
		enableClevis:        o.enableClevis,
		crypttabFile:        "/dev/null", // tests run without root; avoid reading /etc/crypttab
	}
	if o.vConsoleConfig != "" {
		conf.enableVirtualConsole = true
		conf.vconsolePath = wd + "/vconsole.conf"
		require.NoError(t, os.WriteFile(conf.vconsolePath, []byte(o.vConsoleConfig), 0o644))
	}

	if o.localeConfig != "" {
		conf.localePath = wd + "/locale.conf"
		require.NoError(t, os.WriteFile(conf.localePath, []byte(o.localeConfig), 0o644))
	}

	err := generateInitRamfs(&conf)
	if o.expectError == "" {
		require.NoError(t, err)
	} else {
		require.Equal(t, o.expectError, err.Error())
		return
	}

	require.NoError(t, verifyCompressedFile(compression, wd+"/booster.img"))

	if o.unpackImage {
		require.NoError(t, os.Mkdir(wd+"/image.unpacked", 0o755))

		unpCmd := exec.Command("unp", wd+"/booster.img")
		unpCmd.Dir = wd + "/image.unpacked"
		require.NoError(t, unpCmd.Run())
	}
}

func verifyCompressedFile(compression string, file string) error {
	var verifyCmd *exec.Cmd
	switch compression {
	case "none":
		verifyCmd = exec.Command("cpio", "-i", "--only-verify-crc", "--file", file)
	case "zstd", "":
		verifyCmd = exec.Command("zstd", "--test", file)
	case "gzip":
		verifyCmd = exec.Command("gzip", "--test", file)
	case "xz":
		verifyCmd = exec.Command("xz", "--test", file)
	case "lz4":
		verifyCmd = exec.Command("lz4", "--test", file)
	default:
		return fmt.Errorf("Unknown compression: %s", compression)
	}
	if testing.Verbose() {
		verifyCmd.Stdout = os.Stdout
		verifyCmd.Stderr = os.Stderr
	}
	if err := verifyCmd.Run(); err != nil {
		return fmt.Errorf("unable to verify integrity of the output image %s: %v", file, err)
	}

	return nil
}

func checkDirListing(t *testing.T, dir string, expected ...string) {
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Equal(t, len(expected), len(entries))

entriesLoop:
	for _, e := range entries {
		for _, f := range expected {
			if e.Name() == f {
				// found the file
				continue entriesLoop
			}
		}
		require.Failf(t, "directory %s contains unexpected file %s", dir, e.Name())
	}
}

func checkFileExistence(t *testing.T, file string) {
	_, err := os.Stat(file)
	require.NoError(t, err)
}

func checkFilesEqual(t *testing.T, files ...string) {
	require.Greater(t, len(files), 2)

	b1, err := os.ReadFile(files[0])
	require.NoError(t, err)

	for _, f := range files[1:] {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		require.Equal(t, b1, b)
	}
}

func readGeneratedInitConfig(t *testing.T, workDir string) InitConfig {
	c, err := os.ReadFile(workDir + "/image.unpacked/etc/booster.init.yaml")
	require.NoError(t, err)

	var cfg InitConfig
	require.NoError(t, yaml.Unmarshal(c, &cfg))
	return cfg
}

func TestSimple(t *testing.T) {
	createTestInitRamfs(t, &options{})
}

func TestNoneImageCompression(t *testing.T) {
	createTestInitRamfs(t, &options{compression: "none"})
}

func TestZstdImageCompression(t *testing.T) {
	createTestInitRamfs(t, &options{compression: "zstd"})
}

func TestGzipImageCompression(t *testing.T) {
	createTestInitRamfs(t, &options{compression: "gzip"})
}

func TestXzImageCompression(t *testing.T) {
	createTestInitRamfs(t, &options{compression: "xz"})
}

func TestLz4ImageCompression(t *testing.T) {
	createTestInitRamfs(t, &options{compression: "lz4"})
}

func TestUniversalMode(t *testing.T) {
	opts := options{
		universal:        true,
		prepareModulesAt: []string{"kernel/fs/foo.ko", "kernel/testfoo.ko", "kernel/crypto/cbc.ko", "kernel/subdir/virtio_scsi.ko"},
		kernelAliases: []alias{
			{"pci:v*d*sv*sd*bc0Csc03i30*", "cbc"},
			{"pci:v00008086d000015B8sv*sd*bc*sc*i*", "e1000e"},
			{"cpu:type:x86,ven*fam*mod*:feature:*0099*", "virtio_scsi"},
			{"cpu:type:x86,ven*fam*mod*:feature:*0081*", "cbc"},
			{"usb:v*p*d*dc*dsc*dp*ic03isc*ip*in*", "ddd"},
		},
		unpackImage: true,
	}
	createTestInitRamfs(t, &opts)

	cfg := readGeneratedInitConfig(t, opts.workDir)
	require.Equal(t, "matestkernel", cfg.Kernel)

	// all except kernel/testfoo.ko need to be in the image
	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/", "foo.ko", "cbc.ko", "virtio_scsi.ko", "booster.alias")

	aliasesFile, err := os.ReadFile(opts.workDir + "/image.unpacked/usr/lib/modules/booster.alias")
	require.NoError(t, err)

	expectedAliases := `cpu:type:x86,ven*fam*mod*:feature:*0081* cbc
cpu:type:x86,ven*fam*mod*:feature:*0099* virtio_scsi
pci:v*d*sv*sd*bc0Csc03i30* cbc
`
	require.Equal(t, expectedAliases, string(aliasesFile))

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/whiteheat.fw.zst")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/usbdux_firmware.bin.zst")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/rtw88/rtw8723d_fw.bin.zst")
}

func TestSoftDependencies(t *testing.T) {
	opts := options{
		prepareModulesAt: []string{"kernel/fs/foo.ko", "a.ko", "b.ko", "c.ko", "d.ko"},
		hostModules:      []string{"foo"},
		softDeps:         []string{"foo abuiltinfoo pre: a b post: c d"},
		builtin:          []string{"kernel/arch/x86/kernel/abuiltinfoo.ko"},
		universal:        true,
		unpackImage:      true,
	}
	createTestInitRamfs(t, &opts)

	// all except kernel/testfoo.ko need to be in the image
	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/", "foo.ko", "a.ko", "b.ko", "c.ko", "d.ko", "booster.alias")
}

func TestComplexPatterns(t *testing.T) {
	opts := options{
		prepareModulesAt: []string{"kernel/fs/k1.ko", "k2.ko", "zzz/ee/k3.ko", "zzz/k4.ko", "zzz/k5.ko", "k6.ko", "k7-1.ko"},
		hostModules:      []string{"foo", "k1"},
		builtin:          []string{"kernel/arch/x86/kernel/abuiltinfoo.ko"},
		extraModules:     []string{"-*", "abuiltinfoo", "zzz/", "-zzz/ee/", "k7_1"},
		unpackImage:      true,
	}

	createTestInitRamfs(t, &opts)

	// all except kernel/testfoo.ko need to be in the image
	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/", "booster.alias", "k4.ko", "k5.ko", "k7_1.ko")
}

func TestHostMode(t *testing.T) {
	opts := options{
		universal:        false,
		prepareModulesAt: []string{"kernel/fs/foo.ko", "kernel/testfoo.ko", "kernel/crypto/cbc.ko", "kernel/subdir/virtio_scsi.ko", "zzz.ko"},
		hostModules:      []string{"cbc", "virtio_scsi", "zzz"}, // only "cbc", "virtio_scsi" should be in the final image
		hostAliases: []string{
			"pci:v33d1svgsd3bc0Csc03i30aaa",                   // cbc
			"pci:v00008086d000015B8sv5sdbc44scsi1",            // e1000e
			"cpu:type:x86,venfamddddmod11111:feature:0008112", // cbc
			"cpu:type:amd,44e,gggg",
			"somerandomalias",
		},
		kernelAliases: []alias{
			{"pci:v*d*sv*sd*bc0Csc03i30*", "cbc"},
			{"pci:v00008086d000015B8sv*sd*bc*sc*i*", "e1000e"},
			{"cpu:type:x86,ven*fam*mod*:feature:*0099*", "virtio_scsi"},
			{"cpu:type:x86,ven*fam*mod*:feature:*0081*", "cbc"},
			{"usb:v*p*d*dc*dsc*dp*ic03isc*ip*in*", "ddd"},
		},
		unpackImage: true,
	}
	createTestInitRamfs(t, &opts)

	// all except kernel/testfoo.ko need to be in the image
	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/", "cbc.ko", "virtio_scsi.ko", "booster.alias")

	aliasesFile, err := os.ReadFile(opts.workDir + "/image.unpacked/usr/lib/modules/booster.alias")
	require.NoError(t, err)

	expectedAliases := "cpu:type:x86,ven*fam*mod*:feature:*0081* cbc\npci:v*d*sv*sd*bc0Csc03i30* cbc\n"
	require.Equal(t, expectedAliases, string(aliasesFile))

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/whiteheat.fw.zst")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/usbdux_firmware.bin.zst")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/rtw88/rtw8723d_fw.bin.zst")
}

func TestFido2HostModeIncludesUsbHid(t *testing.T) {
	// Regression test for https://github.com/anatol/booster/issues/277.
	// In host-specific mode, usbhid and hid_generic must be included when
	// enable_fido2 is set, even if no USB HID device was connected at build time
	// (i.e. neither module appears in the host's loaded-module list).
	opts := options{
		universal:        false,
		prepareModulesAt: []string{"kernel/drivers/hid/usbhid.ko", "kernel/drivers/hid/hid_generic.ko"},
		hostModules:      []string{}, // no USB HID modules loaded at build time
		enableFido2:      true,
		unpackImage:      true,
	}
	createTestInitRamfs(t, &opts)

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/modules/usbhid.ko")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/modules/hid_generic.ko")
}

func TestExtraFiles(t *testing.T) {
	files := []string{"e", "q", "z"}
	d := t.TempDir()
	for _, f := range files {
		require.NoError(t, os.WriteFile(filepath.Join(d, f), []byte{}, 0o644))
	}

	opts := options{
		extraFiles:  []string{"true", "/usr/bin/false", d},
		unpackImage: true,
	}
	createTestInitRamfs(t, &opts)

	for _, f := range []string{"/usr/bin/true", "/usr/bin/false"} {
		checkFileExistence(t, filepath.Join(opts.workDir, "image.unpacked", f))
	}

	checkDirListing(t, filepath.Join(opts.workDir, "image.unpacked", d), files...)
}

func TestInvalidExtraFiles(t *testing.T) {
	createTestInitRamfs(t, &options{
		extraFiles:  []string{"true", "/usr/bin/false", "/foo/nonexistent"},
		expectError: "lstat /foo/nonexistent: no such file or directory",
	})
}

func TestCompressedModules(t *testing.T) {
	opts := options{
		universal:        true,
		prepareModulesAt: []string{"kernel/fs/plain.ko", "kernel/fs/zst.ko.zst", "kernel/fs/xz.ko.xz", "kernel/fs/lz4.ko.lz4", "kernel/fs/gz.ko.gz"},
		unpackImage:      true,
	}
	createTestInitRamfs(t, &opts)

	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/", "plain.ko", "zst.ko", "xz.ko", "lz4.ko", "gz.ko", "booster.alias")
	checkFilesEqual(t,
		"assets/test_module.ko",
		opts.workDir+"/image.unpacked/usr/lib/modules/plain.ko",
		opts.workDir+"/image.unpacked/usr/lib/modules/zst.ko",
		opts.workDir+"/image.unpacked/usr/lib/modules/xz.ko",
		opts.workDir+"/image.unpacked/usr/lib/modules/lz4.ko",
		opts.workDir+"/image.unpacked/usr/lib/modules/gz.ko",
	)

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/whiteheat.fw.zst")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/usbdux_firmware.bin.zst")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/rtw88/rtw8723d_fw.bin.zst")
}

func TestModuleNameAliases(t *testing.T) {
	opts := options{
		prepareModulesAt: []string{"kernel/fs/plain.ko", "kernel/fs/zst.ko.zst", "kernel/fs/xz.ko.xz", "kernel/fs/lz4.ko.lz4", "kernel/fs/gz.ko.gz"},
		extraModules:     []string{"zst", "kernel/fs/xz.ko.xz", "kernel/fs/gz.ko"},
		unpackImage:      true,
	}
	createTestInitRamfs(t, &opts)

	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/", "zst.ko", "xz.ko", "gz.ko", "booster.alias")
	checkFilesEqual(t,
		"assets/test_module.ko",
		opts.workDir+"/image.unpacked/usr/lib/modules/zst.ko",
		opts.workDir+"/image.unpacked/usr/lib/modules/xz.ko",
		opts.workDir+"/image.unpacked/usr/lib/modules/gz.ko",
	)
}

func TestStripBinaries(t *testing.T) {
	opts := options{
		universal:        true,
		stripBinaries:    true,
		prepareModulesAt: []string{"kernel/fs/foo.ko", "kernel/testfoo.ko", "kernel/crypto/cbc.ko", "kernel/subdir/virtio_scsi.ko"},
		unpackImage:      true,
	}
	createTestInitRamfs(t, &opts)

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/whiteheat.fw.zst")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/usbdux_firmware.bin.zst")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/rtw88/rtw8723d_fw.bin.zst")
}

// Shaped like a real signature (signature, 12 byte descriptor, marker) per the
// kernel's scripts/sign-file.c, though only the marker matters to the generator.
func appendModuleSignature(content []byte) []byte {
	sig := bytes.Repeat([]byte{0xab}, 64)
	descriptor := make([]byte, 12)
	binary.BigEndian.PutUint32(descriptor[8:], uint32(len(sig)))

	out := append([]byte{}, content...)
	out = append(out, sig...)
	out = append(out, descriptor...)

	return append(out, "~Module signature appended~\n"...)
}

// captureStdout collects what the generator prints, which is where warning()
// goes.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)
	saved := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = saved }()

	fn()
	require.NoError(t, w.Close())

	out, err := io.ReadAll(r)
	require.NoError(t, err)

	return string(out)
}

// TestUnsignedModuleWarnsWhenKernelEnforces covers the case booster cannot fix
// for the user: a module that was never signed, packed for a kernel that refuses
// unsigned modules. Silence there means an image that fails at finit_module with
// nothing in the build output pointing at why.
func TestUnsignedModuleWarnsWhenKernelEnforces(t *testing.T) {
	prepareAssets(t)
	content, err := os.ReadFile("assets/test_module.ko")
	require.NoError(t, err)

	img, err := NewImage(filepath.Join(t.TempDir(), "booster.img"), "none", false)
	require.NoError(t, err)
	defer img.Cleanup()
	img.signedModulesRequired = true

	out := captureStdout(t, func() {
		require.NoError(t, img.AppendContent(imageModulesDir+"nosig.ko", 0o644, content))
		require.NoError(t, img.AppendContent(imageModulesDir+"withsig.ko", 0o644, appendModuleSignature(content)))
	})

	require.Contains(t, out, "nosig.ko is not signed")
	require.NotContains(t, out, "withsig.ko is not signed")
}

// TestStripKeepsKernelConsumedSections pins the dracut-aligned split: a module
// gives up debug info only, because the kernel reads its ORC unwind tables, BTF
// and build-id note out of the file, and an image whose modules cannot be
// unwound through is an image whose panics cannot be read.
func TestStripKeepsKernelConsumedSections(t *testing.T) {
	opts := options{
		universal:        true,
		stripBinaries:    true,
		prepareModulesAt: []string{"kernel/fs/mod.ko"},
		unpackImage:      true,
	}
	createTestInitRamfs(t, &opts)

	packed := opts.workDir + "/image.unpacked/usr/lib/modules/mod.ko"
	sections := readelfSections(t, packed)
	for _, want := range []string{".orc_unwind", ".orc_unwind_ip", ".BTF", ".note.gnu.build-id"} {
		require.Contains(t, sections, want, "the kernel reads %s out of the module file", want)
	}
	require.NotContains(t, sections, ".debug_info", "debug info is what stripping a module is for")

	// and the module really was processed rather than copied whole
	original, err := os.Stat("assets/test_module.ko")
	require.NoError(t, err)
	stripped, err := os.Stat(packed)
	require.NoError(t, err)
	require.Less(t, stripped.Size(), original.Size())
}

func readelfSections(t *testing.T, path string) []string {
	t.Helper()

	out, err := exec.Command("readelf", "-SW", path).Output()
	require.NoError(t, err)

	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "["))
		if len(f) > 2 && strings.HasPrefix(f[1], ".") {
			names = append(names, f[1])
		}
	}

	return names
}

// TestStripExtraSections covers the escape hatch for people who want the
// aggressive behaviour back: sections named in strip_extra_sections are removed
// from modules on top of debug info, and userspace files are left alone.
func TestStripExtraSections(t *testing.T) {
	require.Equal(t, []string{"--strip-debug"}, stripArgs(false, true, nil))
	require.Equal(t,
		[]string{"--strip-debug", "-R", "*orc_unwind*", "-R", ".BTF"},
		stripArgs(false, true, []string{"*orc_unwind*", ".BTF"}))

	// userspace files are unaffected: the list is about modules
	require.NotContains(t, stripArgs(true, false, []string{".BTF"}), ".BTF")

}

func TestStripExtraSectionsReachTheImage(t *testing.T) {
	opts := options{
		universal:          true,
		stripBinaries:      true,
		stripExtraSections: []string{"*orc_unwind*", ".BTF"},
		prepareModulesAt:   []string{"kernel/fs/mod.ko"},
		unpackImage:        true,
	}
	createTestInitRamfs(t, &opts)

	sections := readelfSections(t, opts.workDir+"/image.unpacked/usr/lib/modules/mod.ko")
	require.NotContains(t, sections, ".orc_unwind")
	require.NotContains(t, sections, ".BTF")
	require.Contains(t, sections, ".note.gnu.build-id", "only the listed sections go")
}

func TestKernelEnforcesModuleSignatures(t *testing.T) {
	dir := t.TempDir()
	require.False(t, kernelEnforcesModuleSignatures(dir, "matestkernel"), "no config means no claim either way")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "config"),
		[]byte("CONFIG_MODULE_SIG=y\n# CONFIG_MODULE_SIG_FORCE is not set\n"), 0o644))
	require.False(t, kernelEnforcesModuleSignatures(dir, "matestkernel"), "signing without forcing is not enforcement")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "config"),
		[]byte("CONFIG_MODULE_SIG=y\nCONFIG_MODULE_SIG_FORCE=y\n"), 0o644))
	require.True(t, kernelEnforcesModuleSignatures(dir, "matestkernel"))

	// the kernel build directory is where a distribution that ships no separate
	// config file keeps it
	build := filepath.Join(dir, "build")
	require.NoError(t, os.MkdirAll(build, 0o755))
	require.NoError(t, os.Remove(filepath.Join(dir, "config")))
	require.NoError(t, os.WriteFile(filepath.Join(build, ".config"), []byte("CONFIG_MODULE_SIG_FORCE=y\n"), 0o644))
	require.True(t, kernelEnforcesModuleSignatures(dir, "matestkernel"))
}

func TestStripKeepsModuleSignatures(t *testing.T) {
	// strip discards everything past the ELF, signature included, so a stripped
	// module is refused once the kernel enforces signatures
	opts := options{
		universal:        true,
		stripBinaries:    true,
		prepareModulesAt: []string{"kernel/fs/unsigned.ko"},
		signModulesAt:    []string{"kernel/fs/signed.ko"},
		unpackImage:      true,
	}
	createTestInitRamfs(t, &opts)

	source, err := os.ReadFile(opts.workDir + "/modules/kernel/fs/signed.ko")
	require.NoError(t, err)
	packed, err := os.ReadFile(opts.workDir + "/image.unpacked/usr/lib/modules/signed.ko")
	require.NoError(t, err)
	require.Equal(t, source, packed, "signed module must reach the image untouched")

	// the unsigned module is still stripped, so this is not a blanket opt-out
	unsigned, err := os.ReadFile(opts.workDir + "/image.unpacked/usr/lib/modules/unsigned.ko")
	require.NoError(t, err)
	original, err := os.ReadFile("assets/test_module.ko")
	require.NoError(t, err)
	require.Less(t, len(unsigned), len(original), "unsigned module should still be stripped")
}

func TestVirtualConsoleFontMap(t *testing.T) {
	// Regression test for https://github.com/anatol/booster/issues/207:
	// FONT_MAP files (e.g. 8859-2) live in consoletrans/, not consolefonts/.
	// The generator must find and bundle the map file and set FontMapFile
	// (not FontFile) in the init config so setfont receives it via -m.
	opts := options{
		vConsoleConfig: "KEYMAP=us\nFONT=lat1-10\nFONT_MAP=8859-2\nFONT_UNIMAP=cp437\n",
		localeConfig:   "LANG=en_US.UTF-8\n",
		unpackImage:    true,
	}
	createTestInitRamfs(t, &opts)

	checkFileExistence(t, opts.workDir+"/image.unpacked/console/font")
	checkFileExistence(t, opts.workDir+"/image.unpacked/console/font.map")
	checkFileExistence(t, opts.workDir+"/image.unpacked/console/font.unimap")

	cfg := readGeneratedInitConfig(t, opts.workDir)
	require.Equal(t, "/console/font", cfg.VirtualConsole.FontFile)
	require.Equal(t, "/console/font.map", cfg.VirtualConsole.FontMapFile)
	require.Equal(t, "/console/font.unimap", cfg.VirtualConsole.FontUnicodeFile)
}

func TestEnableVirtualConsole(t *testing.T) {
	opts := options{
		universal:      true,
		vConsoleConfig: "KEYMAP=us\nKEYMAP_TOGGLE=de\nFONT=lat1-10\n",
		localeConfig:   "LANG=en_US.UTF-8\n",
		unpackImage:    true,
	}
	createTestInitRamfs(t, &opts)

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/bin/setfont")
	checkFileExistence(t, opts.workDir+"/image.unpacked/console/keymap")
	checkFileExistence(t, opts.workDir+"/image.unpacked/console/font")
}

func TestEnableVirtualConsoleWithoutLocaleConf(t *testing.T) {
	opts := options{
		universal:      true,
		vConsoleConfig: "KEYMAP=us\nKEYMAP_TOGGLE=de\nFONT=lat1-10\n",
		unpackImage:    true,
	}
	createTestInitRamfs(t, &opts)

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/bin/setfont")
	checkFileExistence(t, opts.workDir+"/image.unpacked/console/keymap")
	checkFileExistence(t, opts.workDir+"/image.unpacked/console/font")

	cfg := readGeneratedInitConfig(t, opts.workDir)
	require.Equal(t, true, cfg.VirtualConsole.Utf)
}

func TestModprobeOptions(t *testing.T) {
	opts := options{
		prepareModulesAt: []string{"kernel/fs/test1.ko", "test2.ko", "test3.ko", "test4.ko"},
		modprobeOptions: map[string]string{
			"test1": "foo=1 bar=2",
			"test2": "bazz=foo",
			"test3": "hello=world world=hello",
			"test4": "ee=aaa debug",
		},
		unpackImage:  true,
		hostModules:  []string{"test1", "test2", "test3"},
		extraModules: []string{"test2"},
	}
	createTestInitRamfs(t, &opts)

	cfg := readGeneratedInitConfig(t, opts.workDir)
	expect := map[string]string{
		"test1": "foo=1 bar=2",
		"test2": "bazz=foo",
	}
	require.Equal(t, expect, cfg.ModprobeOptions)
}

func TestLookupFile(t *testing.T) {
	path, err := lookupPath("echo")
	require.NoError(t, err)
	require.Equal(t, "/usr/bin/echo", path)
}

// TestDeterministicImage verifies that two builds with identical inputs produce
// byte-for-byte identical images. This guards against map iteration order and
// goroutine scheduling introducing non-determinism in the CPIO entry order or
// the booster.alias file.
func TestDeterministicImage(t *testing.T) {
	t.Parallel()
	prepareAssets(t)

	wd := t.TempDir()
	modulesDir := filepath.Join(wd, "modules")
	require.NoError(t, os.Mkdir(modulesDir, 0o755))

	// Several modules with overlapping aliases (same pattern → multiple modules)
	// to exercise both the alias sort and the CPIO module ordering.
	mods := []string{
		"kernel/crypto/aes.ko",
		"kernel/crypto/cbc.ko",
		"kernel/crypto/chacha20.ko",
		"kernel/fs/ext4.ko",
		"kernel/fs/btrfs.ko",
	}
	for _, mod := range mods {
		loc := filepath.Join(modulesDir, mod)
		require.NoError(t, os.MkdirAll(filepath.Dir(loc), 0o755))
		require.NoError(t, exec.Command("cp", "assets/test_module.ko", loc).Run())
	}

	aliases := []alias{
		{"crypto_aes", "aes"},
		{"crypto_aes", "cbc"}, // same pattern, two modules
		{"crypto_chacha20", "chacha20"},
		{"crypto_chacha20", "cbc"}, // same pattern, two modules
		{"fs_ext4", "ext4"},
		{"fs_btrfs", "btrfs"},
	}
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin.modinfo", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.alias", generateAliasesFile(aliases), 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.dep", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.softdep", []byte{}, 0o644))

	newConf := func(output string) *generatorConfig {
		return &generatorConfig{
			initBinary:          "/usr/bin/false",
			compression:         "none",
			universal:           true,
			kernelVersion:       "matestkernel",
			modulesDir:          modulesDir,
			output:              output,
			readDeviceAliases:   func() (set, error) { return make(set), nil },
			readHostModules:     func(string) (set, error) { return make(set), nil },
			readModprobeOptions: func() (map[string]string, error) { return nil, nil },
			crypttabFile:        "/dev/null",
		}
	}

	img1 := filepath.Join(wd, "image1.img")
	img2 := filepath.Join(wd, "image2.img")
	require.NoError(t, generateInitRamfs(newConf(img1)))
	require.NoError(t, generateInitRamfs(newConf(img2)))

	b1, err := os.ReadFile(img1)
	require.NoError(t, err)
	b2, err := os.ReadFile(img2)
	require.NoError(t, err)
	require.Equal(t, b1, b2, "image must be byte-for-byte identical across builds")
}

func TestPluginBundlingInCpio(t *testing.T) {
	wd := t.TempDir()
	initBinary := wd + "/init"
	require.NoError(t, os.WriteFile(initBinary, []byte("dummy-init"), 0o755))
	require.NoError(t, os.WriteFile(wd+"/fido2plugin.so", []byte("dummy-fido2"), 0o755))
	require.NoError(t, os.WriteFile(wd+"/clevisplugin.so", []byte("dummy-clevis"), 0o755))

	modulesDir := t.TempDir()
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin.modinfo", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.alias", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.dep", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.softdep", []byte{}, 0o644))

	conf := &generatorConfig{
		initBinary:          initBinary,
		compression:         "none",
		universal:           false,
		kernelVersion:       "matestkernel",
		modulesDir:          modulesDir,
		output:              wd + "/test.img",
		readDeviceAliases:   func() (set, error) { return make(set), nil },
		readHostModules:     func(string) (set, error) { return make(set), nil },
		readModprobeOptions: func() (map[string]string, error) { return nil, nil },
		crypttabFile:        "/dev/null",
		enableFido2:         true,
		enableClevis:        true,
	}

	require.NoError(t, generateInitRamfs(conf))

	f, err := os.Open(conf.output)
	require.NoError(t, err)
	defer f.Close()

	reader := cpio.NewReader(f)
	foundFiles := make(map[string]bool)
	for {
		hdr, err := reader.Next()
		if err != nil {
			break
		}
		foundFiles[hdr.Name] = true
	}

	require.True(t, foundFiles["usr/lib/booster/fido2plugin.so"], "fido2plugin.so should be in cpio")
	require.True(t, foundFiles["usr/lib/booster/clevisplugin.so"], "clevisplugin.so should be in cpio")
}

func TestClevisAutoDetectedFromHost(t *testing.T) {
	wd := t.TempDir()
	initBinary := wd + "/init"
	require.NoError(t, os.WriteFile(initBinary, []byte("dummy-init"), 0o755))
	require.NoError(t, os.WriteFile(wd+"/clevisplugin.so", []byte("dummy-clevis"), 0o755))

	modulesDir := t.TempDir()
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin.modinfo", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.alias", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.dep", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.softdep", []byte{}, 0o644))

	conf := &generatorConfig{
		initBinary:           initBinary,
		compression:          "none",
		universal:            false,
		kernelVersion:        "matestkernel",
		modulesDir:           modulesDir,
		output:               wd + "/test.img",
		readDeviceAliases:    func() (set, error) { return make(set), nil },
		readHostModules:      func(string) (set, error) { return make(set), nil },
		readModprobeOptions:  func() (map[string]string, error) { return nil, nil },
		readHostClevisTokens: func() (bool, error) { return true, nil },
		crypttabFile:         "/dev/null",
	}

	require.NoError(t, generateInitRamfs(conf))

	f, err := os.Open(conf.output)
	require.NoError(t, err)
	defer f.Close()

	reader := cpio.NewReader(f)
	foundClevis := false
	for {
		hdr, err := reader.Next()
		if err != nil {
			break
		}
		if hdr.Name == "usr/lib/booster/clevisplugin.so" {
			foundClevis = true
		}
	}

	require.True(t, foundClevis, "clevisplugin.so should be auto-bundled when host clevis tokens detected")
}

func TestClevisExplicitlyDisabledOverridesHost(t *testing.T) {
	wd := t.TempDir()
	initBinary := wd + "/init"
	require.NoError(t, os.WriteFile(initBinary, []byte("dummy-init"), 0o755))
	require.NoError(t, os.WriteFile(wd+"/clevisplugin.so", []byte("dummy-clevis"), 0o755))

	modulesDir := t.TempDir()
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin.modinfo", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.alias", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.dep", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.softdep", []byte{}, 0o644))

	conf := &generatorConfig{
		initBinary:           initBinary,
		compression:          "none",
		universal:            false,
		kernelVersion:        "matestkernel",
		modulesDir:           modulesDir,
		output:               wd + "/test.img",
		readDeviceAliases:    func() (set, error) { return make(set), nil },
		readHostModules:      func(string) (set, error) { return make(set), nil },
		readModprobeOptions:  func() (map[string]string, error) { return nil, nil },
		readHostClevisTokens: func() (bool, error) { return true, nil },
		crypttabFile:         "/dev/null",
		enableClevis:         false,
		explicitEnableClevis: true,
	}

	require.NoError(t, generateInitRamfs(conf))

	f, err := os.Open(conf.output)
	require.NoError(t, err)
	defer f.Close()

	reader := cpio.NewReader(f)
	foundClevis := false
	for {
		hdr, err := reader.Next()
		if err != nil {
			break
		}
		if hdr.Name == "usr/lib/booster/clevisplugin.so" {
			foundClevis = true
		}
	}

	require.False(t, foundClevis, "clevisplugin.so must NOT be bundled when explicitly disabled")
}

func TestClevisMissingPluginImplicitWarnsAndSucceeds(t *testing.T) {
	wd := t.TempDir()
	initBinary := wd + "/init"
	require.NoError(t, os.WriteFile(initBinary, []byte("fake init binary"), 0o755))
	// Notice: clevisplugin.so is NOT created in wd

	modulesDir := t.TempDir()
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin.modinfo", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.alias", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.dep", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.softdep", []byte{}, 0o644))

	conf := &generatorConfig{
		initBinary:           initBinary,
		compression:          "none",
		universal:            true,
		kernelVersion:        "matestkernel",
		modulesDir:           modulesDir,
		output:               wd + "/test.img",
		readDeviceAliases:    func() (set, error) { return make(set), nil },
		readHostModules:      func(string) (set, error) { return make(set), nil },
		readModprobeOptions:  func() (map[string]string, error) { return nil, nil },
		crypttabFile:         "/dev/null",
		enableClevis:         true,
		explicitEnableClevis: false,
	}

	require.NoError(t, generateInitRamfs(conf), "implicit clevis must not fail the build if plugin is missing")
	require.False(t, conf.enableClevis, "enableClevis must be set to false when plugin is missing")
}

func TestClevisMissingPluginExplicitFails(t *testing.T) {
	wd := t.TempDir()
	initBinary := wd + "/init"
	require.NoError(t, os.WriteFile(initBinary, []byte("fake init binary"), 0o755))
	// Notice: clevisplugin.so is NOT created in wd

	modulesDir := t.TempDir()
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin.modinfo", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.alias", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.dep", []byte{}, 0o644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.softdep", []byte{}, 0o644))

	conf := &generatorConfig{
		initBinary:           initBinary,
		compression:          "none",
		universal:            false,
		kernelVersion:        "matestkernel",
		modulesDir:           modulesDir,
		output:               wd + "/test.img",
		readDeviceAliases:    func() (set, error) { return make(set), nil },
		readHostModules:      func(string) (set, error) { return make(set), nil },
		readModprobeOptions:  func() (map[string]string, error) { return nil, nil },
		crypttabFile:         "/dev/null",
		enableClevis:         true,
		explicitEnableClevis: true,
	}

	require.Error(t, generateInitRamfs(conf), "explicit enable_clevis: true must fail if plugin is missing")
}


