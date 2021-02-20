package main

import (
	"bufio"
	"bytes"
	"container/list"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/xi2/xz"
	"golang.org/x/sys/unix"
)

type set map[string]bool
type alias struct {
	pattern, module string
}

type Kmod struct {
	universal         bool // if false - include modules for current host only
	kernelVersion     string
	dir               string // e.g. /usr/lib/modules/5.9.9-arch1-1
	nameToPathMapping *Bimap // kernel module name to path (relative to modulesDir)
	builtinModules    set
	requiredModules   set                 // set of modules that we need to be added to the image
	dependencies      map[string][]string // dependency list for non-builtin modules
	aliases           []alias
	extraDep          map[string][]string // extra dependencies added by the generator
	loadModules       []string            // force modules to load in init
	hostAliases       []alias
	hostModules       set
}

func NewKmod(universal bool) (*Kmod, error) {
	kernel := *kernelVersion
	if kernel == "" {
		var err error
		kernel, err = readKernelVersion()
		if err != nil {
			return nil, err
		}
	}

	modulesDir := path.Join("/usr/lib/modules", kernel)

	nameToPathMapping, err := scanModulesDir(modulesDir)
	if err != nil {
		return nil, err
	}

	builtinModules, err := readModuleBuiltin(modulesDir)
	if err != nil {
		return nil, err
	}

	aliases, err := readModAliases(modulesDir)
	if err != nil {
		return nil, err
	}

	hostModAliases := make([]alias, 0)
	hostModules := make(set)
	if !universal {
		hostModAliases, err = readHostAliases(aliases)
		if err != nil {
			return nil, err
		}

		// find all current modules at /proc/modules
		hostModules, err = readHostModules()
		if err != nil {
			return nil, err
		}
	}

	kmod := &Kmod{
		universal:         universal,
		kernelVersion:     kernel,
		dir:               modulesDir,
		nameToPathMapping: nameToPathMapping,
		builtinModules:    builtinModules,
		requiredModules:   make(set),
		aliases:           aliases,
		extraDep:          make(map[string][]string),
		loadModules:       make([]string, 0),
		hostAliases:       hostModAliases,
		hostModules:       hostModules,
	}
	return kmod, nil

}

func (k *Kmod) activateModules(filter, failIfMissing bool, mods ...string) error {
	filter = filter && !k.universal // filtering works only if we in host (non-universal) mode

	for _, m := range mods {
		if pattern := m; strings.HasSuffix(pattern, "/") {
			// trailing '/' means we match path recursively
			for mod, modPath := range k.nameToPathMapping.forward {
				if filter && !k.hostModules[mod] {
					continue
				}
				if strings.HasPrefix(modPath, pattern) {
					debug("activate module %s\n", mod)
					k.requiredModules[mod] = true
				}
			}
		} else {
			if k.builtinModules[m] {
				// this module is builtin, no need to add it to image
				continue
			}
			if filter && !k.hostModules[m] {
				continue
			}

			if _, ok := k.nameToPathMapping.forward[m]; ok {
				debug("activate module %s\n", m)
				k.requiredModules[m] = true
			} else if name, ok := k.nameToPathMapping.reverse[m]; ok {
				// m is a filename that contains the module
				debug("activate module %s\n", name)
				k.requiredModules[name] = true
			} else {
				debug("requested module %s is missing\n", name)
				if failIfMissing {
					return fmt.Errorf("module %s does not exist", m)
				}
			}
		}
	}
	return nil
}

func (k *Kmod) resolveDependencies() error {
	// read modules.dep
	modulesDep, err := k.readModulesDep(k.dir, k.nameToPathMapping)
	if err != nil {
		return err
	}

	modulesSoftDep, err := k.readModulesSoftDep(k.dir)
	if err != nil {
		return err
	}

	depsToVisit := list.New()
	for mod := range k.requiredModules {
		depsToVisit.PushBack(mod)
	}

	k.dependencies = make(map[string][]string)

	depsVisited := make(map[string]bool)
	for e := depsToVisit.Front(); e != nil; e = e.Next() {
		name := e.Value.(string)
		if depsVisited[name] {
			continue
		}
		depsVisited[name] = true
		k.requiredModules[name] = true

		deps := make([]string, 0)

		if d, exist := modulesDep[name]; exist {
			deps = append(deps, d...)
		}
		if d, exist := modulesSoftDep[name]; exist {
			deps = append(deps, d...)
		}
		if d, exist := k.extraDep[name]; exist {
			deps = append(deps, d...)
		}

		if len(deps) > 0 {
			k.dependencies[name] = deps
			for _, d := range deps {
				depsToVisit.PushBack(d)
			}
		}
	}

	return nil
}

func readModAliases(dir string) ([]alias, error) {
	f, err := os.Open(path.Join(dir, "modules.alias"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var aliases []alias
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if !strings.HasPrefix(line, "alias ") {
			continue // also skips comments
		}
		line = strings.TrimPrefix(line, "alias ")
		idx := strings.LastIndexByte(line, ' ')
		if idx == -1 {
			return nil, fmt.Errorf("modules.alias line has no space: %q", line)
		}
		pattern := line[:idx]
		module := line[idx+1:]
		aliases = append(aliases, alias{pattern, module})
	}

	return aliases, s.Err()
}

func (k *Kmod) addModulesToImage(img *Image) error {
	var wg sync.WaitGroup
	var m sync.Mutex
	modNum := len(k.requiredModules)
	errCh := make(chan error, modNum)

	unpackModule := func(modName string) {
		defer wg.Done()

		p, ok := k.nameToPathMapping.forward[modName]
		if !ok {
			errCh <- fmt.Errorf("unable to find module file for %s", modName)
		}

		modulePath := path.Join(k.dir, p)

		f, err := os.Open(modulePath)
		if err != nil {
			errCh <- fmt.Errorf("%s: %v", modulePath, err)
			return
		}
		defer f.Close()

		var r io.Reader
		switch path.Ext(p) {
		case ".ko":
			r = f
		case ".xz":
			r, err = xz.NewReader(f, 0)
		case ".zst":
			r, err = zstd.NewReader(f)
		}
		if err != nil {
			errCh <- fmt.Errorf("unpacking module %s: %v", modName, err)
			return
		}

		content, err := ioutil.ReadAll(r)
		if err != nil {
			errCh <- fmt.Errorf("unpacking module %s: %v", modName, err)
			return
		}

		m.Lock()
		// img operations are not thread-safe so we need to serialize them
		err = img.AppendContent(content, 0644, path.Join(k.dir, modName+".ko"))
		m.Unlock()

		if err != nil {
			errCh <- err
			return
		}
	}

	wg.Add(modNum)
	for modName := range k.requiredModules {
		go unpackModule(modName)
	}
	wg.Wait()

	select {
	case err := <-errCh:
		return err // return the fist error in the channel
	default:
		return nil
	}
}

func scanModulesDir(dir string) (*Bimap, error) {
	nameToPathMapping := NewBimap()
	// go through modulesDir and extract all module names to build a map name <-> path
	err := filepath.Walk(dir, func(filename string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "build" && filename == path.Join(dir, "build") {
				// skip header files under ./build dir
				return filepath.SkipDir
			} else {
				return nil
			}
		}

		parts := strings.Split(info.Name(), ".")
		// kernel module either has ext of *.ko or *.ko.$COMPRESSION
		if len(parts) == 2 || len(parts) == 3 {
			if parts[1] != "ko" {
				return nil
			}
		} else {
			return nil
		}

		// There seems a convention to keep module name consistent with its filename
		// TODO: find out where is in Linux kernel sources this rule set
		modName := normalizeModuleName(parts[0])
		relativePath := filename[len(dir)+1:]

		return nameToPathMapping.Add(modName, relativePath)
	})
	if err != nil {
		return nil, err
	}

	return nameToPathMapping, err
}

func readModuleBuiltin(dir string) (map[string]bool, error) {
	f, err := os.Open(path.Join(dir, "modules.builtin"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	result := make(map[string]bool)
	for s := bufio.NewScanner(f); s.Scan(); {
		filename := s.Text()
		module := path.Base(filename)

		if !strings.HasSuffix(module, ".ko") {
			return nil, fmt.Errorf("modules.builtin contains module filename that does not have *.ko extension: %s", filename)
		}

		result[normalizeModuleName(module[:len(module)-3])] = true
	}

	return result, nil
}

// TODO: read modules.bin file using following logic https://github.com/vadmium/module-init-tools/blob/master/index.c#L253

func readKernelVersion() (string, error) {
	// read kernel binary version as
	//     if (argc > 1){
	//        FILE* f = fopen(argv[1], "r");
	//        short offset = 0;
	//        char str[128];
	//        if(f){
	//            fseek(f, 0x20E, SEEK_SET);
	//            fread(&offset, 2, 1, f);
	//            fseek(f, offset + 0x200, SEEK_SET);
	//            fread(str, 128, 1, f);
	//            str[127] = '\0';
	//            printf("%s\n", str);
	//            fclose(f);
	//            return 0;
	//        }else {
	//            return 2;
	//        }
	//    } else {
	//        printf("use: kver [kernel image file]\n");
	//        return 1;
	//    }

	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}
	release := uts.Release
	length := bytes.IndexByte(release[:], 0)
	return string(uts.Release[:length]), nil
}

func (k *Kmod) readModulesDep(dir string, nameToPathMapping *Bimap) (map[string][]string, error) {
	f, err := os.Open(path.Join(dir, "modules.dep"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	modules := make(map[string][]string)
	for scanner.Scan() {
		// line has a format "foo: bar baz"
		line := scanner.Text()

		idx := strings.Index(line, ":")
		if idx == -1 {
			return nil, fmt.Errorf("Cannot parse a line from modules.dep file: %v", line)
		}
		koPath := line[:idx]
		name, ok := nameToPathMapping.reverse[koPath]
		if !ok {
			return nil, fmt.Errorf("modules.dep: unable to resolve module name for %v", koPath)
		}
		if idx != len(line)-1 {
			deps := strings.Split(line[idx+2:], " ")
			for i, d := range deps {
				modName, ok := nameToPathMapping.reverse[d]
				if !ok {
					return nil, fmt.Errorf("modules.dep: unable to resolve module name for %v", d)
				}
				deps[i] = modName
			}
			modules[name] = deps
		}

	}
	return modules, scanner.Err()
}

func (k *Kmod) readModulesSoftDep(dir string) (map[string][]string, error) {
	f, err := os.Open(path.Join(dir, "modules.softdep"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	modules := make(map[string][]string)
	for scanner.Scan() {
		line := scanner.Text()

		if line[0] == '#' {
			continue
		}

		parts := strings.Split(line, " ")
		if parts[0] != "softdep" {
			return nil, fmt.Errorf("Invalid softdep line: %s", line)
		}
		modname := parts[1]
		modname, err = k.resolveModname(modname)
		if err != nil {
			return nil, err
		}

		parts = parts[2:]

		deps := make([]string, 0)
		for _, d := range parts {
			if d != "pre:" && d != "post:" {
				var err error
				d, err = k.resolveModname(d)
				if err != nil {
					// some softdeps have really weird modnames e.g. kpc_i2c or kpc_nwl_dma, just ignore it
					continue
				}
				if _, ok := k.builtinModules[d]; ok {
					// skip builtin dependencies
					continue
				}
				deps = append(deps, d)
			}
		}
		if len(deps) > 0 {
			modules[modname] = deps
		}
	}
	return modules, scanner.Err()
}

func (k *Kmod) matchAlias(alias string) ([]alias, error) {
	return matchAlias(alias, k.aliases)
}

// this function may return multiple matches for the input match, e.g.
//   modprobe -qaR 'serio:ty06pr00id00ex00'
//     atkbd
//     serio_raw
func matchAlias(needle string, aliases []alias) ([]alias, error) {
	// TODO: implement it according to https://github.com/vadmium/module-init-tools/blob/master/modprobe.c#L2000
	var result []alias

	for _, a := range aliases {
		match, err := path.Match(a.pattern, needle)
		if err != nil {
			return nil, err
		}
		if match {
			result = append(result, a)
		}
	}
	return result, nil
}

func (k *Kmod) resolveModname(name string) (string, error) {
	if k.builtinModules[name] {
		return name, nil
	}
	if _, exists := k.nameToPathMapping.forward[name]; exists {
		return name, nil
	}

	normalizedMod := normalizeModuleName(name)
	if k.builtinModules[normalizedMod] {
		return normalizedMod, nil
	}
	if _, exists := k.nameToPathMapping.forward[normalizedMod]; exists {
		return normalizedMod, nil
	}

	aliases, err := k.matchAlias(name)
	if err != nil {
		return "", err
	}

	// return the first map element if it exists
	for _, a := range aliases {
		return a.module, nil
	}
	return "", fmt.Errorf("cannot resolve module name: %s", name)
}

func normalizeModuleName(mod string) string {
	return strings.ReplaceAll(mod, "-", "_")
}

func (k *Kmod) forceLoadModules() []string {
	result := k.loadModules

	if !k.universal {
		for m := range k.hostModules {
			if k.requiredModules[m] {
				result = append(result, m)
			}
		}
	}

	return result
}

func (k *Kmod) filterAliasesForRequiredModules() ([]alias, error) {
	var all, result []alias

	if k.universal {
		all = k.aliases
	} else {
		all = k.hostAliases
	}

	for _, a := range all {
		if k.requiredModules[a.module] {
			result = append(result, a)
		}
	}

	return result, nil
}

func readHostAliases(allAliases []alias) ([]alias, error) {
	var hostAliases []alias

	err := filepath.Walk("/sys/devices", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if info.Name() != "modalias" {
			return nil
		}

		b, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		alias := strings.TrimSpace(string(b))
		if alias == "" {
			return nil
		}

		// for debugging one can use "modprobe -qaR 'pci:v00001AF4d00001004sv00001AF4sd00000008bc01sc00i00'" to find out what driver is responsible for a given alias
		matched, err := matchAlias(alias, allAliases)
		if err != nil {
			return err
		}
		if len(matched) > 0 {
			hostAliases = append(hostAliases, matched...)
		} else {
			debug("no matches found for alias '%s' (%s)\n", alias, path)
		}

		return nil
	})

	return hostAliases, err
}

func readHostModules() (map[string]bool, error) {
	modules := make(map[string]bool)

	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		modname := strings.Split(line, " ")[0]
		modules[modname] = true
	}

	return modules, s.Err()
}

func (k *Kmod) addExtraDep(mod string, deps ...string) {
	for _, d := range deps {
		// skip builtin deps
		if _, ok := k.builtinModules[d]; ok {
			continue
		}
		k.extraDep[mod] = append(k.extraDep[mod], d)
	}
}

func (k *Kmod) forceLoad(mods ...string) {
	k.loadModules = append(k.loadModules, mods...)
}
