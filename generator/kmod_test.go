package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/xi2/xz"
)

// Scans all modules at the current kernel and verifies that its calculated mod name equal to one embeeded into the module
func TestModuleNames(t *testing.T) {
	t.Parallel()

	ver, err := readKernelVersion()
	if err != nil {
		t.Fatal(err)
	}

	conf := &generatorConfig{
		universal:         true,
		kernelVersion:     ver,
		modulesDir:        "/usr/lib/modules/" + ver,
		hostModulesFile:   "/proc/modules",
		readDeviceAliases: readDeviceAliases,
	}
	kmod, err := NewKmod(conf)
	if err != nil {
		t.Fatal(err)
	}

	for name, fn := range kmod.nameToPathMapping.forward {
		if fn[0] == '/' {
			t.Fatalf("module filename %s should not start with slash", fn)
		}
		if fn != path.Clean(fn) {
			t.Fatalf("filepath %s is not clean", fn)
		}

		extractedName, err := modNameFromFile(path.Join(kmod.hostModulesDir, fn))
		if err != nil {
			t.Fatal(err)
		}
		if name != extractedName {
			t.Fatalf("filename %s: calculated modname is %s, extracted from the binary - %s", fn, name, extractedName)
		}
	}
}

func modNameFromFile(filename string) (string, error) {
	if strings.HasSuffix(filename, ".ko") {
		f, err := os.Open(filename)
		if err != nil {
			return "", err
		}
		defer f.Close()

		return moduleName(f)
	} else if strings.HasSuffix(filename, ".ko.xz") {
		f, err := os.Open(filename)
		if err != nil {
			return "", err
		}
		defer f.Close()

		r, err := xz.NewReader(f, 0)
		if err != nil {
			return "", err
		}

		return moduleName(NewBufferedReaderAt(r))
	}

	return "", fmt.Errorf("unknown kernel module extension: %s", filename)

}

func moduleName(r io.ReaderAt) (string, error) {
	// read the content of '.gnu.linkonce.this_module' section and get
	// data at offset 24 (64bit arch), this is going to be module_name
	const moduleNameOffset64 = 24

	ef, err := elf.NewFile(r)
	if err != nil {
		return "", err
	}
	defer ef.Close()

	sec := ef.Section(".gnu.linkonce.this_module")
	if sec == nil {
		return "", fmt.Errorf("there is no .gnu.linkonce.this_module section")
	}

	b, err := sec.Data()
	if err != nil {
		return "", err
	}
	b = b[moduleNameOffset64:]
	return string(b[:bytes.IndexByte(b, '\x00')]), nil
}

func TestReadDeviceAliases(t *testing.T) {
	t.Parallel()

	a, err := readDeviceAliases()
	if err != nil {
		t.Fatal(err)
	}

	// on a regular host we would expect at least dozen devices/aliases
	if len(a) < 12 {
		t.Fatalf("too few device aliases detected: %d", len(a))
	}
}
