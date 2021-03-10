package main

import (
	"bufio"
	"bytes"
	"container/list"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/xi2/xz"
)

type set map[string]bool
type alias struct {
	pattern, module string
}

type Kmod struct {
	universal         bool // if false - include modules for current host only
	kernelVersion     string
	hostModulesDir    string // host path to modules e.g. /usr/lib/modules/5.9.9-arch1-1, note that image path is always /usr/lib/modules
	nameToPathMapping *Bimap // kernel module name to path (relative to modulesDir)
	builtinModules    set
	requiredModules   set                 // set of modules that we need to be added to the image
	dependencies      map[string][]string // dependency list for non-builtin modules
	aliases           []alias
	extraDep          map[string][]string // extra dependencies added by the generator
	loadModules       []string            // force modules to load in init
	hostModules       set
}

func NewKmod(conf *generatorConfig) (*Kmod, error) {
	nameToPathMapping, err := scanModulesDir(conf.modulesDir)
	if err != nil {
		return nil, err
	}

	builtinModules, err := readModuleBuiltin(conf.modulesDir)
	if err != nil {
		return nil, err
	}

	aliases, err := readKernelAliases(conf.modulesDir)
	if err != nil {
		return nil, err
	}

	// find all modules currently used at the host
	hostModules, err := readHostModules(conf.hostModulesFile)
	if err != nil {
		return nil, err
	}

	kmod := &Kmod{
		universal:         conf.universal,
		kernelVersion:     conf.kernelVersion,
		hostModulesDir:    conf.modulesDir,
		nameToPathMapping: nameToPathMapping,
		builtinModules:    builtinModules,
		requiredModules:   make(set),
		aliases:           aliases,
		extraDep:          make(map[string][]string),
		loadModules:       make([]string, 0),
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
					debug("activate module %s", mod)
					k.requiredModules[mod] = true
				}
			}
		} else {
			if filter && !k.hostModules[m] {
				continue
			}

			if k.builtinModules[m] {
				k.requiredModules[m] = true
			} else if _, ok := k.nameToPathMapping.forward[m]; ok {
				debug("activate module %s", m)
				k.requiredModules[m] = true
			} else if name, ok := k.nameToPathMapping.reverse[m]; ok {
				// m is a filename that contains the module
				debug("activate module %s", name)
				k.requiredModules[name] = true
			} else {
				debug("requested module %s is missing", m)
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
	modulesDep, err := k.readModulesDep(k.hostModulesDir, k.nameToPathMapping)
	if err != nil {
		return err
	}

	modulesSoftDep, err := k.readModulesSoftDep(k.hostModulesDir)
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

func readKernelAliases(dir string) ([]alias, error) {
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

// readBuiltinModinfo reads builtin modules properties and returns a map of
// module -> [values]
// Note that values is an array as a module can contain multiple properties with the same name.
func readBuiltinModinfo(dir string, propName string) (map[string][]string, error) {
	data, err := os.ReadFile(path.Join(dir, "modules.builtin.modinfo"))
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string)

	re := regexp.MustCompile(`(\w*?).` + propName + `=([^\0]*)`)
	matches := re.FindAllSubmatch(data, -1)

	for _, m := range matches {
		name := string(m[1])
		fw := string(m[2])
		result[name] = append(result[name], fw)
	}

	return result, nil
}

func (k *Kmod) addModulesToImage(img *Image) error {
	var wg sync.WaitGroup
	modNum := len(k.requiredModules)
	errCh := make(chan error, modNum)

	unpackModule := func(modName string) {
		defer wg.Done()

		p, ok := k.nameToPathMapping.forward[modName]
		if !ok {
			errCh <- fmt.Errorf("unable to find module file for %s", modName)
		}

		modulePath := path.Join(k.hostModulesDir, p)

		f, err := os.Open(modulePath)
		if err != nil {
			errCh <- fmt.Errorf("%s: %v", modulePath, err)
			return
		}
		defer f.Close()

		var r io.Reader
		ext := path.Ext(p)
		switch ext {
		case ".ko":
			r = f
		case ".xz":
			r, err = xz.NewReader(f, 0)
		case ".zst":
			r, err = zstd.NewReader(f)
		default:
			err = fmt.Errorf("unknown module compression format: %s", ext)
		}
		if err != nil {
			errCh <- fmt.Errorf("unpacking module %s: %v", modName, err)
			return
		}

		content, err := io.ReadAll(r)
		if err != nil {
			errCh <- fmt.Errorf("unpacking module %s: %v", modName, err)
			return
		}

		if err := img.AppendContent(content, 0644, imageModulesDir+modName+".ko"); err != nil {
			errCh <- err
			return
		}

		ef, err := elf.NewFile(bytes.NewReader(content))
		if err != nil {
			errCh <- err
			return
		}

		fws, err := readModuleFirmwareRequirements(ef)
		if err != nil {
			errCh <- err
			return
		}

		if err := img.appendFirmwareFiles(modName, fws); err != nil {
			errCh <- err
			return
		}
	}

	builtinFw, err := readBuiltinModinfo(k.hostModulesDir, "firmware")
	if err != nil {
		return err
	}

	for modName := range k.requiredModules {
		if k.builtinModules[modName] {
			if err := img.appendFirmwareFiles(modName, builtinFw[modName]); err != nil {
				return err
			}
		} else {
			wg.Add(1)
			go unpackModule(modName)
		}
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
		modname = k.resolveModname(modname)
		if modname == "" {
			return nil, fmt.Errorf("unable to resolve modname %s", modname)
		}

		parts = parts[2:]

		var deps []string
		for _, d := range parts {
			if d != "pre:" && d != "post:" {
				if n := k.resolveModname(d); n != "" {
					deps = append(deps, n)
				} else {
					debug("softdep: unable to resolve module name %s", d)
				}
			}
		}
		if len(deps) > 0 {
			modules[modname] = deps
		}
	}
	return modules, scanner.Err()
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

// matches needed using simple string comparison instead of using path matching
// returns the match module name
func firstExactAliasMatch(needle string, aliases []alias) string {
	for _, a := range aliases {
		if a.pattern == needle {
			return a.module
		}
	}
	return ""
}

// resolveModname tries to resolve and normalize to its canonical name
// return empty stream if cannot normalize it
func (k *Kmod) resolveModname(name string) string {
	if k.builtinModules[name] {
		return name
	}
	if _, exists := k.nameToPathMapping.forward[name]; exists {
		return name
	}

	normalizedMod := normalizeModuleName(name)
	if k.builtinModules[normalizedMod] {
		return normalizedMod
	}
	if _, exists := k.nameToPathMapping.forward[normalizedMod]; exists {
		return normalizedMod
	}

	return firstExactAliasMatch(name, k.aliases)
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

// filter only those aliases that match activated modules and, if host mode enabled,
// active devices aliases
func (k *Kmod) filterAliasesForRequiredModules(conf *generatorConfig) ([]alias, error) {
	var filteredAliases []alias

	for _, a := range k.aliases {
		if k.requiredModules[a.module] {
			filteredAliases = append(filteredAliases, a)
		}
	}

	if !k.universal {
		devAliases, err := conf.readDeviceAliases()
		if err != nil {
			return nil, err
		}

		// filter out only aliases known to kernel
		var newFilteredAliases []alias // aliases for the given devices
		for a := range devAliases {
			matched, err := matchAlias(a, filteredAliases)
			if err != nil {
				return nil, err
			}
			if len(matched) > 0 {
				newFilteredAliases = append(newFilteredAliases, matched...)
			} else {
				debug("no matches found for a device alias '%s'", a)
			}
		}
		filteredAliases = newFilteredAliases
	}

	return filteredAliases, nil
}

func readDeviceAliases() (set, error) {
	aliases := make(set)

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

		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		al := strings.TrimSpace(string(b))
		if al == "" {
			return nil
		}

		aliases[al] = true

		return nil
	})

	return aliases, err
}

func readHostModules(modulesFile string) (map[string]bool, error) {
	modules := make(map[string]bool)

	f, err := os.Open(modulesFile)
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
	k.extraDep[mod] = append(k.extraDep[mod], deps...)
}

func (k *Kmod) forceLoad(mods ...string) {
	k.loadModules = append(k.loadModules, mods...)
}

// readModuleFirmwareRequirements parses given module file .modinfo section
// and collects all firmware files dependencies for it.
func readModuleFirmwareRequirements(ef *elf.File) ([]string, error) {
	var result []string
	if sec := ef.Section(".modinfo"); sec != nil {
		data, err := sec.Data()
		if err != nil {
			return nil, err
		}
		for _, s := range strings.Split(string(data), "\x00") {
			const prefix = "firmware="
			if strings.HasPrefix(s, prefix) {
				fw := s[len(prefix):]
				result = append(result, fw)
			}
		}
	}
	return result, nil
}
