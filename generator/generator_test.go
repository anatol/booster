package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"testing"
)

func prepareAssets(t *testing.T) {
	if _, err := os.Stat("assets/test_module.ko"); os.IsNotExist(err) {
		cmd := exec.Command("make", "-C", "assets")
		if testing.Verbose() {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}

		// compress with zst
		if err := exec.Command("zstd", "-z", "assets/test_module.ko", "-o", "assets/test_module.ko.zst").Run(); err != nil {
			t.Fatal(err)
		}

		// compress with xz
		if err := exec.Command("xz", "-z", "--keep", "assets/test_module.ko").Run(); err != nil {
			t.Fatal(err)
		}
	}
}

type options struct {
	workDir          string
	compression      string
	universal        bool
	prepareModulesAt []string // copy a test module to these locations
	unpackImage      bool
	hostModules      []string // modules as found under /proc/modules
	hostAliases      []string // list of all aliases for the host devices
	kernelAliases    []alias  // aliases as found under kernel/modules.alias (pattern + corresponding module)
	extraFiles       []string
	expectError      string
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
	if err := os.Mkdir(modulesDir, 0755); err != nil {
		t.Fatal(err)
	}

	for _, l := range opts.prepareModulesAt {
		loc := modulesDir + "/" + l
		dir := filepath.Dir(loc)
		if err := exec.Command("mkdir", "-p", dir).Run(); err != nil {
			t.Fatal(err)
		}
		source := "assets/test_module.ko"
		switch path.Ext(loc) {
		case ".xz":
			source += ".xz"
		case ".zst":
			source += ".zst"
		}
		if err := exec.Command("cp", source, loc).Run(); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(modulesDir+"/modules.builtin", []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modulesDir+"/modules.alias", generateAliasesFile(opts.kernelAliases), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modulesDir+"/modules.dep", []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modulesDir+"/modules.softdep", []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wd+"/proc_modules", generateProcModulesFile(opts.hostModules), 0644); err != nil {
		t.Fatal(err)
	}

	devAliases := func() ([]string, error) {
		return opts.hostAliases, nil
	}

	compression := opts.compression
	if compression == "" {
		compression = "none"
	}

	conf := generatorConfig{
		initBinary:        "/usr/bin/false",
		compression:       compression,
		universal:         opts.universal,
		kernelVersion:     "matestkernel",
		modulesDir:        modulesDir,
		output:            wd + "/booster.img",
		readDeviceAliases: devAliases,
		hostModulesFile:   wd + "/proc_modules",
		extraFiles:        opts.extraFiles,
	}
	err := generateInitRamfs(&conf)
	if opts.expectError == "" {
		if err != nil {
			t.Fatal(err)
		}
	} else {
		if err == nil || opts.expectError != err.Error() {
			t.Fatalf("expected failure '%s', got error '%v'", opts.expectError, err)
		}
		return
	}

	if err := verifyCompressedFile(compression, wd+"/booster.img"); err != nil {
		t.Fatal(err)
	}

	if opts.unpackImage {
		if err := os.Mkdir(wd+"/image.unpacked", 0755); err != nil {
			t.Fatal(err)
		}

		unpCmd := exec.Command("unp", wd+"/booster.img")
		unpCmd.Dir = wd + "/image.unpacked"
		if err := unpCmd.Run(); err != nil {
			t.Fatal(err)
		}
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
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(expected) {
		t.Fatalf("%s: expected %d files in modules dir, got %d", dir, len(expected), len(entries))
	}

entriesLoop:
	for _, e := range entries {
		for _, f := range expected {
			if e.Name() == f {
				// found the file
				continue entriesLoop
			}
		}
		t.Fatalf("directory %s contains unexpected file %s", dir, e.Name())
	}
}

func checkFileExistence(t *testing.T, file string) {
	if _, err := os.Stat(file); err != nil {
		t.Fatal(err)
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
	if err != nil {
		t.Fatal(err)
	}
	expectedConf := "kernel: matestkernel\n"
	if string(conf) != expectedConf {
		t.Fatalf("invalid init config, expected %s, got %s", expectedConf, conf)
	}

	// all except kernel/testfoo.ko need to be in the image
	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/", "foo.ko", "cbc.ko", "virtio_scsi.ko", "booster.alias")

	aliasesFile, err := os.ReadFile(opts.workDir + "/image.unpacked/usr/lib/modules/booster.alias")
	if err != nil {
		t.Fatal(err)
	}
	expectedAliases := `pci:v*d*sv*sd*bc0Csc03i30* cbc
cpu:type:x86,ven*fam*mod*:feature:*0099* virtio_scsi
cpu:type:x86,ven*fam*mod*:feature:*0081* cbc
`
	if string(aliasesFile) != expectedAliases {
		t.Fatalf("Generated booster.alias '%s' does not match the expected one '%s'", string(aliasesFile), expectedAliases)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	expectedAliases := `pci:v*d*sv*sd*bc0Csc03i30* cbc
cpu:type:x86,ven*fam*mod*:feature:*0081* cbc
`
	if string(aliasesFile) != expectedAliases {
		t.Fatalf("Generated booster.alias '%s' does not match the expected one '%s'", string(aliasesFile), expectedAliases)
	}
}

func testExtraFiles(t *testing.T) {
	files := []string{"e", "q", "z"}
	d := t.TempDir()
	for _, f := range files {
		if err := os.WriteFile(d+"/"+f, []byte{}, 0644); err != nil {
			t.Fatal(err)
		}
	}

	opts := options{
		extraFiles:  []string{"true", "/usr/bin/false", d},
		unpackImage: true,
	}
	createTestInitRamfs(t, &opts)

	for _, f := range []string{"/usr/bin/true", "/usr/bin/false"} {
		if _, err := os.Stat(opts.workDir + "/image.unpacked" + f); err != nil {
			t.Fatal(err)
		}
	}

	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/bin/true")
	checkFileExistence(t, opts.workDir+"/image.unpacked/usr/bin/false")
	checkDirListing(t, opts.workDir+"/image.unpacked/"+d, files...)

}

func testInvalidExtraFiles(t *testing.T) {
	createTestInitRamfs(t, &options{
		extraFiles:  []string{"true", "/usr/bin/false", "/foo/nonexistent"},
		expectError: "AppendFile: lstat /foo/nonexistent: no such file or directory",
	})
}

func testCompressedModules(t *testing.T) {
	opts := options{
		universal:        true,
		prepareModulesAt: []string{"kernel/fs/plain.ko", "kernel/fs/zst.ko.zst", "kernel/fs/xz.ko.xz"},
		unpackImage:      true,
	}
	createTestInitRamfs(t, &opts)

	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/", "plain.ko", "zst.ko", "xz.ko", "booster.alias")
}

func TestGenerator(t *testing.T) {
	prepareAssets(t)

	t.Run("Simple", testSimple)
	t.Run("NoneImageCompression", testNoneImageCompression)
	t.Run("ZstdImageCompression", testZstdImageCompression)
	t.Run("GzipImageCompression", testGzipImageCompression)
	t.Run("UniversalMode", testUniversalMode)
	t.Run("HostMode", testHostMode)
	t.Run("ExtraFiles", testExtraFiles)
	t.Run("InvalidExtraFiles", testInvalidExtraFiles)
	t.Run("CompressedModules", testCompressedModules)
}
