package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
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
		readHostModules:   readHostModules,
		readDeviceAliases: readDeviceAliases,
	}
	kmod, err := NewKmod(conf)
	if err != nil {
		t.Fatal(err)
	}

	ch := make(chan error)
	wg := sync.WaitGroup{}
	for name, fn := range kmod.nameToPathMapping.forward {
		if fn[0] == '/' {
			t.Fatalf("module filename %s should not start with slash", fn)
		}
		if fn != path.Clean(fn) {
			t.Fatalf("filepath %s is not clean", fn)
		}

		wg.Add(1)
		go checkModuleName(name, path.Join(kmod.hostModulesDir, fn), &wg, ch)
	}

	wg.Wait()
}

func checkModuleName(modname, filename string, wg *sync.WaitGroup, ch chan error) {
	defer wg.Done()

	var r io.ReaderAt

	if strings.HasSuffix(filename, ".ko") {
		var err error
		f, err := os.Open(filename)
		if err != nil {
			ch <- err
			return
		}
		r = f
		defer f.Close()
	} else if strings.HasSuffix(filename, ".ko.xz") {
		f, err := os.Open(filename)
		if err != nil {
			ch <- err
			return
		}
		defer f.Close()

		x, err := xz.NewReader(f, 0)
		if err != nil {
			ch <- err
			return
		}
		r = NewBufferedReaderAt(x)
	} else {
		ch <- fmt.Errorf("unknown kernel module extension: %s", filename)
		return
	}

	extractedName, err := readModnameFromELF(r)
	if err != nil {
		ch <- err
		return
	}

	if modname != extractedName {
		ch <- fmt.Errorf("filename %s: calculated modname is %s, extracted from the binary - %s", filename, extractedName, extractedName)
	}
}

func readModnameFromELF(r io.ReaderAt) (string, error) {
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

func TestReadBuiltinModinfo(t *testing.T) {
	t.Parallel()

	ver, err := readKernelVersion()
	if err != nil {
		t.Fatal(err)
	}

	fws, err := readBuiltinModinfo("/usr/lib/modules/"+ver, "file")
	if err != nil {
		t.Fatal(err)
	}

	_ = fws
}
