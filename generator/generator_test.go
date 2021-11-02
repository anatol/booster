package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func prepareAssets(t *testing.T) {
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
	enableVirtualConsole         bool
	enableLVM                    bool
	vConsoleConfig, localeConfig string
	enableMdraid                 bool
	mdraidConfigPath             string
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

func createTestInitRamfs(t *testing.T, opts *options) {
	t.Parallel()

	wd := t.TempDir()
	opts.workDir = wd

	modulesDir := path.Join(wd, "modules")
	require.NoError(t, os.Mkdir(modulesDir, 0755))

	for _, l := range opts.prepareModulesAt {
		loc := modulesDir + "/" + l
		dir := filepath.Dir(loc)
		require.NoError(t, exec.Command("mkdir", "-p", dir).Run())
		source := "assets/test_module.ko"
		switch path.Ext(loc) {
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

	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin", generateBuiltinFile(opts.builtin), 0644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.builtin.modinfo", []byte{}, 0644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.alias", generateAliasesFile(opts.kernelAliases), 0644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.dep", []byte{}, 0644))
	require.NoError(t, os.WriteFile(modulesDir+"/modules.softdep", generateSoftdepFile(opts.softDeps), 0644))
	require.NoError(t, os.WriteFile(wd+"/proc_modules", generateProcModulesFile(opts.hostModules), 0644))

	listAsFunc := func(in []string) func() (set, error) {
		out := make(set)
		for _, a := range in {
			out[a] = true
		}
		return func() (set, error) { return out, nil }
	}

	compression := opts.compression
	if compression == "" {
		compression = "none"
	}

	conf := generatorConfig{
		initBinary:           "/usr/bin/false",
		compression:          compression,
		universal:            opts.universal,
		kernelVersion:        "matestkernel",
		modulesDir:           modulesDir,
		output:               wd + "/booster.img",
		readDeviceAliases:    listAsFunc(opts.hostAliases),
		readHostModules:      listAsFunc(opts.hostModules),
		readModprobeOptions:  func() (map[string]string, error) { return opts.modprobeOptions, nil },
		extraFiles:           opts.extraFiles,
		modules:              opts.extraModules,
		stripBinaries:        opts.stripBinaries,
		enableVirtualConsole: opts.enableVirtualConsole,
		enableLVM:            opts.enableLVM,
		enableMdraid:         opts.enableMdraid,
		mdraidConfigPath:     opts.mdraidConfigPath,
	}
	if opts.enableVirtualConsole {
		conf.vconsolePath = wd + "/vconsole.conf"
		require.NoError(t, os.WriteFile(conf.vconsolePath, []byte(opts.vConsoleConfig), 0644))

		conf.localePath = wd + "/locale.conf"
		require.NoError(t, os.WriteFile(conf.localePath, []byte(opts.localeConfig), 0644))
	}

	err := generateInitRamfs(&conf)
	if opts.expectError == "" {
		require.NoError(t, err)
	} else {
		require.Equal(t, opts.expectError, err.Error())
		return
	}

	require.NoError(t, verifyCompressedFile(compression, wd+"/booster.img"))

	if opts.unpackImage {
		require.NoError(t, os.Mkdir(wd+"/image.unpacked", 0755))

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

	b1, err := ioutil.ReadFile(files[0])
	require.NoError(t, err)

	for _, f := range files[1:] {
		b, err := ioutil.ReadFile(f)
		require.NoError(t, err)
		require.Equal(t, b1, b)
	}
}

func testSimple(t *testing.T) {
	createTestInitRamfs(t, &options{})
}

func testNoneImageCompression(t *testing.T) {
	createTestInitRamfs(t, &options{compression: "none"})
}

func testZstdImageCompression(t *testing.T) {
	createTestInitRamfs(t, &options{compression: "zstd"})
}

func testGzipImageCompression(t *testing.T) {
	createTestInitRamfs(t, &options{compression: "gzip"})
}

func testXzImageCompression(t *testing.T) {
	createTestInitRamfs(t, &options{compression: "xz"})
}

func testLz4ImageCompression(t *testing.T) {
	createTestInitRamfs(t, &options{compression: "lz4"})
}

func testUniversalMode(t *testing.T) {
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

	conf, err := os.ReadFile(opts.workDir + "/image.unpacked/etc/booster.init.yaml")
	require.NoError(t, err)

	expectedConf := "kernel: matestkernel\n"
	require.Equal(t, expectedConf, string(conf))

	// all except kernel/testfoo.ko need to be in the image
	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/", "foo.ko", "cbc.ko", "virtio_scsi.ko", "booster.alias")

	aliasesFile, err := os.ReadFile(opts.workDir + "/image.unpacked/usr/lib/modules/booster.alias")
	require.NoError(t, err)

	expectedAliases := `pci:v*d*sv*sd*bc0Csc03i30* cbc
cpu:type:x86,ven*fam*mod*:feature:*0099* virtio_scsi
cpu:type:x86,ven*fam*mod*:feature:*0081* cbc
`
	require.Equal(t, expectedAliases, string(aliasesFile))

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/whiteheat.fw")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/usbdux_firmware.bin")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/rtw88/rtw8723d_fw.bin")
}

func testSoftDependencies(t *testing.T) {
	opts := options{
		prepareModulesAt: []string{"kernel/fs/foo.ko", "a.ko", "b.ko", "c.ko", "d.ko"},
		hostModules:      []string{"foo"},
		softDeps:         []string{"foo abuiltinfoo pre: a b post: c d"},
		builtin:          []string{"kernel/arch/x86/kernel/abuiltinfoo.ko"},
		unpackImage:      true,
	}
	createTestInitRamfs(t, &opts)

	// all except kernel/testfoo.ko need to be in the image
	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/", "foo.ko", "a.ko", "b.ko", "c.ko", "d.ko", "booster.alias")
}

func testComplexPatterns(t *testing.T) {
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

func testHostMode(t *testing.T) {
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

	expectedAliases := `cpu:type:x86,ven*fam*mod*:feature:*0081* cbc
pci:v*d*sv*sd*bc0Csc03i30* cbc`

	// aliases generated by booster are not guaranteed to be sorted
	// do it here so we can bit-to-bit compare with the expected result
	arr := strings.Split(strings.TrimRight(string(aliasesFile), "\n"), "\n")
	sort.Strings(arr)
	sortedAliases := strings.Join(arr, "\n")

	require.Equal(t, expectedAliases, sortedAliases)

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/whiteheat.fw")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/usbdux_firmware.bin")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/rtw88/rtw8723d_fw.bin")
}

func testExtraFiles(t *testing.T) {
	files := []string{"e", "q", "z"}
	d := t.TempDir()
	for _, f := range files {
		require.NoError(t, os.WriteFile(d+"/"+f, []byte{}, 0644))
	}

	opts := options{
		extraFiles:  []string{"true", "/usr/bin/false", d},
		unpackImage: true,
	}
	createTestInitRamfs(t, &opts)

	for _, f := range []string{"/usr/bin/true", "/usr/bin/false"} {
		_, err := os.Stat(opts.workDir + "/image.unpacked" + f)
		require.NoError(t, err)

	}

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/bin/true")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/bin/false")
	checkDirListing(t, opts.workDir+"/image.unpacked/"+d, files...)
}

func testInvalidExtraFiles(t *testing.T) {
	createTestInitRamfs(t, &options{
		extraFiles:  []string{"true", "/usr/bin/false", "/foo/nonexistent"},
		expectError: "lstat /foo/nonexistent: no such file or directory",
	})
}

func testCompressedModules(t *testing.T) {
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

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/whiteheat.fw")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/usbdux_firmware.bin")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/rtw88/rtw8723d_fw.bin")
}

func testModuleNameAliases(t *testing.T) {
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

func testStripBinaries(t *testing.T) {
	opts := options{
		universal:        true,
		stripBinaries:    true,
		prepareModulesAt: []string{"kernel/fs/foo.ko", "kernel/testfoo.ko", "kernel/crypto/cbc.ko", "kernel/subdir/virtio_scsi.ko"},
		unpackImage:      true,
	}
	createTestInitRamfs(t, &opts)

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/whiteheat.fw")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/usbdux_firmware.bin")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/lib/firmware/rtw88/rtw8723d_fw.bin")
}

func testEnableVirtualConsole(t *testing.T) {
	opts := options{
		universal:            true,
		enableVirtualConsole: true,
		vConsoleConfig:       "KEYMAP=us\nKEYMAP_TOGGLE=de\nFONT=lat1-10\nFONT_UNIMAP=GohaClassic-14\n",
		localeConfig:         "LANG=en_US.UTF-8\n",
		unpackImage:          true,
	}
	createTestInitRamfs(t, &opts)

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/bin/setfont")
	checkFileExistence(t, opts.workDir+"/image.unpacked/console/keymap")
	checkFileExistence(t, opts.workDir+"/image.unpacked/console/font")
	checkFileExistence(t, opts.workDir+"/image.unpacked/console/font.unimap")
}

func testModprobeOptions(t *testing.T) {
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

	checkFileExistence(t, opts.workDir+"/image.unpacked/etc/booster.init.yaml")

	c, err := os.ReadFile(opts.workDir + "/image.unpacked/etc/booster.init.yaml")
	require.NoError(t, err)

	cfg := struct {
		ModprobeOptions map[string]string `yaml:",omitempty"`
	}{}

	require.NoError(t, yaml.Unmarshal(c, &cfg))

	expect := map[string]string{
		"test1": "foo=1 bar=2",
		"test2": "bazz=foo",
	}
	require.Equal(t, expect, cfg.ModprobeOptions)
}

func TestGenerator(t *testing.T) {
	opts.Verbose = testing.Verbose()

	prepareAssets(t)

	t.Run("Simple", testSimple)
	t.Run("NoneImageCompression", testNoneImageCompression)
	t.Run("ZstdImageCompression", testZstdImageCompression)
	t.Run("GzipImageCompression", testGzipImageCompression)
	t.Run("XzImageCompression", testXzImageCompression)
	t.Run("Lz4ImageCompression", testLz4ImageCompression)
	t.Run("UniversalMode", testUniversalMode)
	t.Run("HostMode", testHostMode)
	t.Run("ComplexPatterns", testComplexPatterns)
	t.Run("SoftDepenencies", testSoftDependencies)
	t.Run("ExtraFiles", testExtraFiles)
	t.Run("InvalidExtraFiles", testInvalidExtraFiles)
	t.Run("CompressedModules", testCompressedModules)
	t.Run("ModuleNameAliases", testModuleNameAliases)
	t.Run("StripBinaries", testStripBinaries)
	t.Run("EnableVirtualConsole", testEnableVirtualConsole)
	t.Run("ModprobeOptions", testModprobeOptions)
}
