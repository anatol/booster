package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/list"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/xi2/xz" // github.com/xi2/xz is faster so we use it here https://github.com/ulikunitz/xz/issues/23
)

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
	dependencies      map[string][]string // dependency list for modules
	postDependencies  map[string][]string // post dependency list for modules
	modprobeOptions   map[string]string   // module options parsed from modprobe.d
	aliases           []alias
	extraDep          map[string][]string // extra dependencies added by the generator
	hostModules       set
}

func NewKmod(conf *generatorConfig) (*Kmod, error) {
	kmod := &Kmod{
		universal:         conf.universal,
		kernelVersion:     conf.kernelVersion,
		hostModulesDir:    conf.modulesDir,
		nameToPathMapping: NewBimap(),
		builtinModules:    make(set),
		requiredModules:   make(set),
		aliases:           nil,
		extraDep:          make(map[string][]string),
		hostModules:       make(set),
	}

	if err := kmod.scanModulesDir(); err != nil {
		return nil, err
	}

	if err := kmod.readModuleBuiltin(); err != nil {
		return nil, err
	}

	if err := kmod.readKernelAliases(); err != nil {
		return nil, err
	}

	var err error
	// find all modules currently used at the host
	kmod.hostModules, err = conf.readHostModules(conf.kernelVersion)
	if err != nil {
		return nil, err
	}

	kmod.modprobeOptions, err = conf.readModprobeOptions()
	if err != nil {
		return nil, err
	}

	return kmod, nil
}

func (k *Kmod) activateModules(filter, failIfMissing bool, mods ...string) error {
	filter = filter && !k.universal // filtering works only if we in host (non-universal) mode

	for _, m := range mods {
		activate := true
		if m[0] == '-' {
			m = m[1:]
			activate = false // i.e. remove modules from the list
		}
		if m == "" {
			return fmt.Errorf("invalid modules pattern %s", m)
		}

		if pattern := m; pattern == "*" || strings.HasSuffix(pattern, "/") {
			// trailing '/' means we match path recursively
			for mod, modPath := range k.nameToPathMapping.forward {
				if filter && !k.hostModules[mod] {
					continue
				}
				if pattern == "*" || strings.HasPrefix(modPath, pattern) {
					if activate {
						if !k.requiredModules[mod] {
							debug("activate module %s", mod)
							k.requiredModules[mod] = true
						}
					} else {
						if k.requiredModules[mod] {
							debug("deactivate module %s", mod)
							delete(k.requiredModules, mod)
						}
					}
				}
			}
		} else {
			if filter && !k.hostModules[m] {
				continue
			}

			var mod string
			if _, ok := k.nameToPathMapping.forward[m]; ok {
				// matched
				mod = m
			} else if name, ok := k.nameToPathMapping.reverse[m]; ok {
				// m is a filename that contains the module
				mod = name
			} else {
				debug("requested module %s is missing", m)
				if failIfMissing {
					return fmt.Errorf("module %s does not exist", m)
				}
				continue
			}

			if activate {
				if !k.requiredModules[mod] {
					debug("activate module %s", mod)
					k.requiredModules[mod] = true
				}
			} else {
				if k.requiredModules[mod] {
					debug("deactivate module %s", mod)
					delete(k.requiredModules, mod)
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

	softPreDeps, softPostDeps, err := k.readModulesSoftDep(k.hostModulesDir)
	if err != nil {
		return err
	}

	depsToVisit := list.New()
	for mod := range k.requiredModules {
		depsToVisit.PushBack(mod)
	}

	k.dependencies = make(map[string][]string)
	k.postDependencies = make(map[string][]string)

	depsVisited := make(set)
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
		if d, exist := softPreDeps[name]; exist {
			if k.universal {
				deps = append(deps, d...)
			} else {
				// filter out soft dependencies
				for _, d1 := range d {
					if k.hostModules[d1] {
						deps = append(deps, d1)
					}
				}
			}
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

		if deps, exist := softPostDeps[name]; exist {
			for _, d := range deps {
				if !k.universal && !k.hostModules[d] {
					continue
				}
				k.postDependencies[name] = append(k.postDependencies[name], d)
				depsToVisit.PushBack(d)
			}
		}
	}

	return nil
}

func (k *Kmod) readKernelAliases() error {
	f, err := os.Open(filepath.Join(k.hostModulesDir, "modules.alias"))
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if !strings.HasPrefix(line, "alias ") {
			continue // also skips comments
		}
		line = strings.TrimPrefix(line, "alias ")
		idx := strings.LastIndexByte(line, ' ')
		if idx == -1 {
			return fmt.Errorf("modules.alias line has no space: %q", line)
		}
		pattern := line[:idx]
		module := line[idx+1:]
		k.aliases = append(k.aliases, alias{pattern, module})
	}

	return s.Err()
}

// readBuiltinModinfo reads builtin modules properties and returns a map of
// module -> [values]
// Note that values is an array as a module can contain multiple properties with the same name.
func readBuiltinModinfo(dir string, propName string) (map[string][]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "modules.builtin.modinfo"))
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

		modulePath := filepath.Join(k.hostModulesDir, p)

		f, err := os.Open(modulePath)
		if err != nil {
			errCh <- fmt.Errorf("%s: %v", modulePath, err)
			return
		}
		defer f.Close()

		var r io.Reader
		ext := filepath.Ext(p)
		switch ext {
		case ".ko":
			r = f
		case ".xz":
			r, err = xz.NewReader(f, 0)
		case ".zst":
			r, err = zstd.NewReader(f)
		case ".lz4":
			r, err = newLz4Reader(f)
		case ".gz":
			r, err = gzip.NewReader(f)
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

		if err := img.AppendContent(imageModulesDir+modName+".ko", 0o644, content); err != nil {
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

	for m := range k.hostModules {
		if !k.requiredModules[m] {
			debug("module '%s' currently used at the host but was not added to the image", m)
		}
	}

	wg.Wait()

	select {
	case err := <-errCh:
		return err // return the first error in the channel
	default:
		return nil
	}
}

func (k *Kmod) scanModulesDir() error {
	// go through modulesDir and extract all module names to build a map name <-> path
	return filepath.Walk(k.hostModulesDir, func(filename string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "build" && filename == filepath.Join(k.hostModulesDir, "build") {
				// skip header files under ./build dir
				return filepath.SkipDir
			}
			return nil
		}

		parts := strings.Split(info.Name(), ".")
		// kernel module either has ext of *.ko or *.ko.$COMPRESSION
		if len(parts) < 2 || len(parts) > 3 || parts[1] != "ko" {
			// it is not a kernel module
			return nil
		}

		// There seems a convention to keep module name consistent with its filename
		// TODO: find out where is in Linux kernel sources this rule set
		modName := normalizeModuleName(parts[0])
		relativePath := filename[len(k.hostModulesDir)+1:]

		// In addition tracking modname->pathname add (possible) filename aliases.
		// A filename alias is the filename without archive extension, i.e. for kernel/foo.ko.xz an alias would be
		// kernel/foo.ko and a user can specify it in its config and thus avoiding future module compression change in
		// the future.
		var aliases []string
		if len(parts) == 3 {
			compressionSuffix := "." + parts[2]
			aliases = []string{strings.TrimSuffix(relativePath, compressionSuffix)}
		}

		return k.nameToPathMapping.Add(modName, relativePath, aliases...)
	})
}

func (k *Kmod) readModuleBuiltin() error {
	f, err := os.Open(filepath.Join(k.hostModulesDir, "modules.builtin"))
	if err != nil {
		return err
	}
	defer f.Close()

	for s := bufio.NewScanner(f); s.Scan(); {
		filename := s.Text()
		module := filepath.Base(filename)

		if !strings.HasSuffix(module, ".ko") {
			return fmt.Errorf("modules.builtin contains module filename that does not have *.ko extension: %s", filename)
		}

		modName := normalizeModuleName(module[:len(module)-3])

		k.builtinModules[modName] = true
		if err := k.nameToPathMapping.Add(modName, filename); err != nil {
			return err
		}
	}

	return nil
}

// TODO: read modules.bin file using following logic https://github.com/vadmium/module-init-tools/blob/master/index.c#L253
func (k *Kmod) readModulesDep(dir string, nameToPathMapping *Bimap) (map[string][]string, error) {
	f, err := os.Open(filepath.Join(dir, "modules.dep"))
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

func (k *Kmod) readModulesSoftDep(dir string) (map[string][]string, map[string][]string, error) {
	f, err := os.Open(filepath.Join(dir, "modules.softdep"))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	pre := make(map[string][]string)
	post := make(map[string][]string)
	for scanner.Scan() {
		line := scanner.Text()

		if line[0] == '#' {
			continue
		}

		parts := strings.Split(line, " ")
		if parts[0] != "softdep" {
			return nil, nil, fmt.Errorf("Invalid softdep line: %s", line)
		}
		modname := parts[1]
		modname = k.resolveModname(modname)
		if modname == "" {
			return nil, nil, fmt.Errorf("unable to resolve modname %s", modname)
		}

		parts = parts[2:]

		preDeps := true // some softdeps do not have "pre:" part, assume that elements are modules
		postDeps := false
		for _, d := range parts {
			if d == "pre:" {
				preDeps = true
				postDeps = false
				continue
			}
			if d == "post:" {
				preDeps = false
				postDeps = true
				continue
			}

			var deps []string
			aliases, err := matchAlias(d, k.aliases)
			if err != nil {
				return nil, nil, err
			}
			if aliases != nil {
				for _, a := range aliases {
					deps = append(deps, a.module)
				}
			} else {
				d = k.resolveModname(d)
				if d == "" {
					// kernel includes softdeps to non-existent modules for some reason
					continue
				}
				deps = []string{d}
			}

			if preDeps {
				pre[modname] = append(pre[modname], deps...)
			} else if postDeps {
				post[modname] = append(post[modname], deps...)
			} else {
				return nil, nil, fmt.Errorf("unable parse dependencies for a softdep: %s", line)
			}
		}
	}

	return pre, post, scanner.Err()
}

// this function may return multiple matches for the input match, e.g.
//   modprobe -qaR 'serio:ty06pr00id00ex00'
//     atkbd
//     serio_raw
func matchAlias(needle string, aliases []alias) ([]alias, error) {
	// TODO: implement it according to https://github.com/vadmium/module-init-tools/blob/master/modprobe.c#L2000
	var result []alias

	for _, a := range aliases {
		match, err := filepath.Match(a.pattern, needle)
		if err != nil {
			return nil, err
		}
		if match {
			result = append(result, a)
		}
	}
	return result, nil
}

// resolveModname tries to resolve and normalize to its canonical name
// return empty stream if cannot normalize it
func (k *Kmod) resolveModname(name string) string {
	if _, exists := k.nameToPathMapping.forward[name]; exists {
		return name
	}

	normalizedMod := normalizeModuleName(name)
	if _, exists := k.nameToPathMapping.forward[normalizedMod]; exists {
		return normalizedMod
	}

	debug("unable to resolve module name %s", name)
	return ""
}

func normalizeModuleName(mod string) string {
	return strings.ReplaceAll(mod, "-", "_")
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

	if k.universal {
		return filteredAliases, nil
	}

	// for a non-universal mode filter out only aliases known to kernel
	uniqAliases := make(map[alias]bool)

	devAliases, err := conf.readDeviceAliases() // list of current host aliases as reported by /sys/devices
	if err != nil {
		return nil, err
	}
	for a := range devAliases {
		matched, err := matchAlias(a, filteredAliases)
		if err != nil {
			return nil, err
		}
		if len(matched) == 0 {
			debug("no matches found for a device alias '%s'", a)
			continue
		}

		for _, m := range matched {
			uniqAliases[m] = true
		}
	}

	// quirk: some modules do not report modaliases they use at /sysfs so we just add all aliases for specified modules.
	addAllAliasesForModules := []string{
		// mmc bus sends an udev event modalias 'mmc:block' (see Linux drivers/mmc/core/bus.c)
		// but it seems that this modalias is not reported anywhere under /sys/devices, see https://github.com/anatol/booster/issues/90
		"mmc_block",
		// uas does not report alias for its USB_PR_BULK interface https://github.com/anatol/booster/issues/121
		"uas",
	}
	for _, m := range addAllAliasesForModules {
		if !k.requiredModules[m] {
			continue
		}

		for _, a := range filteredAliases {
			if a.module != m {
				continue
			}
			uniqAliases[a] = true
		}
	}

	newFilteredAliases := make([]alias, 0, len(uniqAliases)) // aliases for the given devices
	for a := range uniqAliases {
		newFilteredAliases = append(newFilteredAliases, a)
	}

	return newFilteredAliases, nil
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

var errNoConfigFile = fmt.Errorf("unable to find a config for the kernel")

// readCompiledInComponents reads/parses /proc/config file and finds all compiled-in config options (i.e. those having 'Y')
// the function tries to open /proc/config and /proc/config.gz, if having problems with it then the function returns errNoConfigFile
func readCompiledInComponents(kernelVersion string) (set, error) {
	var r io.Reader

	if f, err := os.Open("/boot/config-" + kernelVersion); err == nil {
		// Fedora does not have /proc/config. Instead it stores config at /boot.
		debug("reading %s", f.Name())
		defer f.Close()
		r = f
	} else if f, err := os.Open("/proc/config"); err == nil {
		debug("reading %s", f.Name())
		defer f.Close()
		r = f
	} else if gz, err := os.Open("/proc/config.gz"); err == nil {
		debug("reading %s", gz.Name())
		defer gz.Close()

		r, err = gzip.NewReader(gz)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
	} else {
		return nil, errNoConfigFile
	}

	result := make(set)

	re := regexp.MustCompile(`^(CONFIG_.*)=y$`)

	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		matches := re.FindAllStringSubmatch(line, -1)
		if matches == nil {
			continue
		}

		config := matches[0][1]
		result[config] = true
	}

	return result, nil
}

func readHostModules(kernelVersion string) (set, error) {
	// Unlike /proc/modules (or `lsmod`) /sys/module provides information about builtin modules as well.
	// And we need to check the built-in modules and try to add it to the image. This is needed because
	// with the next kernel this built-in module might be compiled as loadable *.ko module.
	dir, err := os.Open("/sys/module")
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	ents, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	result := make(set, len(ents))
	modules := make([]string, len(ents))
	for i, e := range ents {
		result[e.Name()] = true
		modules[i] = e.Name()
	}

	// some built-in modules are not reported at /proc/modules, e.g. ext4
	// so in addition to reading /proc/modules we read /proc/config and see if some modules are compiled-in so we force adding them to
	// 'active' modules
	compiledIn, err := readCompiledInComponents(kernelVersion)
	if err == errNoConfigFile {
		debug("%v", err)
	} else if err != nil {
		return nil, err
	}

	type configToModule struct {
		configOption, module string
	}

	// here is the list of built-in kernel modules that are not reported as active via /proc/modules
	// TODO: as /proc/modules does not work then find another way to list all built-in modules
	unreportedModules := []configToModule{{"CONFIG_EXT4_FS", "ext4"}}

	for _, m := range unreportedModules {
		if result[m.module] {
			continue
		}
		if err != errNoConfigFile && !compiledIn[m.configOption] {
			// if there is no /proc/config at the host then add all unreported modules as a safe tion
			continue
		}

		result[m.module] = true
		modules = append(modules, "config:"+m.module)
	}

	debug("active host modules: %v", modules)

	return result, nil
}

func (k *Kmod) addExtraDep(mod string, deps ...string) {
	k.extraDep[mod] = append(k.extraDep[mod], k.selectNonBuiltinModules(deps)...)
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

// parseModprobeFunction parses the content of modprobe.d file and appends found module options to the input map
// the map represents modname->[]options
func parseModprobe(content string, options map[string][]string) error {
	s := bufio.NewScanner(strings.NewReader(content))
	var (
		multiLine bool         // if true means that we are processing multiline directive
		b         bytes.Buffer // multiline buffer
	)
	for s.Scan() {
		line := s.Text()
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			if multiLine {
				return fmt.Errorf("multiline directive contains an empty or comment line")
			}
			continue
		}

		if line[len(line)-1] == '\\' {
			multiLine = true
			b.WriteString(line[:len(line)-1])
			b.WriteByte(' ')
			continue
		}

		if multiLine {
			// we are in multiline more and the current line is the end of it
			b.WriteString(line)
			line = b.String()
			multiLine = false
			b.Reset()
		}

		const prefix = "options "
		if !strings.HasPrefix(line, prefix) {
			continue
		}

		line = line[len(prefix):]

		sep := strings.IndexByte(line, ' ')
		if sep == -1 {
			return fmt.Errorf("invalid line: '%s'. It needs to be 'options modname params'", line)
		}

		modname := normalizeModuleName(line[:sep]) // currently it does not handle aliases, do we need it?
		params := line[sep+1:]

		options[modname] = append(options[modname], params)
	}
	return nil
}

func readModprobeOptions() (map[string]string, error) {
	dirs := []string{
		"/lib/modprobe.d/",
		"/etc/modprobe.d/",
		"/run/modprobe.d/",
	}

	options := make(map[string][]string)
	for _, d := range dirs {
		dir, err := os.ReadDir(d)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}

		for _, e := range dir {
			filename := filepath.Join(d, e.Name())
			content, err := os.ReadFile(filename)
			if err != nil {
				return nil, err
			}
			if err := parseModprobe(string(content), options); err != nil {
				return nil, fmt.Errorf("%s: %s", filename, err)
			}
		}
	}

	result := make(map[string]string)
	for m, o := range options {
		result[m] = strings.Join(o, " ")
	}

	return result, nil
}

func (k *Kmod) filterModprobeForRequiredModules() {
	for m := range k.modprobeOptions {
		if _, ok := k.requiredModules[m]; !ok {
			delete(k.modprobeOptions, m)
		}
	}
}

func (k *Kmod) selectNonBuiltinModules(mods []string) []string {
	var result []string
	for _, m := range mods {
		if !k.builtinModules[m] {
			result = append(result, m)
		}
	}
	return result
}
