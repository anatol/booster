package main

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
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
		universal:           true,
		kernelVersion:       ver,
		modulesDir:          "/usr/lib/modules/" + ver,
		readHostModules:     readHostModules,
		readDeviceAliases:   readDeviceAliases,
		readModprobeOptions: readModprobeOptions,
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
		if _, ok := kmod.builtinModules[name]; ok {
			continue // skip builtin modules
		}

		wg.Add(1)
		go checkModuleName(name, path.Join(kmod.hostModulesDir, fn), &wg, ch)
	}

	// waitGroup as a channel
	w := make(chan struct{})
	go func() {
		defer close(w)
		wg.Wait()
	}()

	select {
	case err := <-ch:
		t.Fatal(err)
	case <-w:
		// wg is Done()
		break
	}
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

func TestParseModprobe(t *testing.T) {
	check := func(content string, expected map[string][]string) {
		got := make(map[string][]string)
		if err := parseModprobe(content, got); err != nil {
			t.Fatal(err)
		}

		if !reflect.DeepEqual(expected, got) {
			t.Fatalf("invalid options generated: expected %v, got %v", expected, got)
		}
	}

	check("# use \"reset=1\" as default, since it should be safe for recent devices and\n# solves all kind of problems.\noptions btusb reset=1",
		map[string][]string{
			"btusb": {"reset=1"},
		})
	check("# use \"reset=1\" as default, since it should be safe for recent devices and\n  \t  \n# solves all kind of problems.\noptions btusb reset=1",
		map[string][]string{
			"btusb": {"reset=1"},
		})
	check("install libnvdimm /usr/bin/ndctl load-keys ; /sbin/modprobe --ignore-install libnvdimm $CMDLINE_OPTS\n", map[string][]string{})
	check("# When bonding module is loaded, it creates bond0 by default due to max_bonds\n# option default value 1. This interferes with the network configuration\n# management / networkd, as it is not possible to detect whether this bond0 was\n# intentionally configured by the user, or should be managed by\n# networkd/NM/etc. Therefore disable bond0 creation.\n\noptions bonding max_bonds=0\n\n# Do the same for dummy0.\n\noptions dummy numdummies=0\n",
		map[string][]string{
			"bonding": {"max_bonds=0"},
			"dummy":   {"numdummies=0"},
		})
}

func TestReadModprobeOptions(t *testing.T) {
	opts, err := readModprobeOptions()
	if err != nil {
		t.Fatal(err)
	}
	if opts == nil {
		t.Fatal("expect non-nil options map")
	}
}
