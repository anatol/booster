package main

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const imageModulesDir = "/usr/lib/modules"

var (
	loadedModules    = make(map[string]bool)
	loadingModules   = make(map[string][]*sync.WaitGroup)
	loadingModulesWg sync.WaitGroup // total number of modules being loaded
	modulesMutex     sync.Mutex

	missingModules      = make(map[string]bool) // set of modules that kernel wanted to load via aliases but they were missing in the image
	missingModulesMutex sync.Mutex
)

type alias struct{ pattern, module string } // module alias info
var (
	aliases          []alias      // all aliases from initramfs
	processedAliases = sync.Map{} // aliases that have been seen/processed by booster
)

func loadModalias(alias string) error {
	if _, existed := processedAliases.LoadOrStore(alias, true); existed {
		return nil
	}

	mods := matchAlias(alias)
	if len(mods) == 0 {
		debug("no match found for alias %s", alias)
		return nil
	}
	_ = loadModules(mods...)
	return nil
}

func readAliases() error {
	f, err := os.Open(imageModulesDir + "/booster.alias")
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		a, ok, err := parseAliasLine(s.Text())
		if err != nil {
			return err
		}
		if ok {
			aliases = append(aliases, a)
		}
	}

	return s.Err()
}

func parseAliasLine(line string) (alias, bool, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return alias{}, false, nil
	}
	if len(fields) != 2 {
		return alias{}, false, errors.New("invalid alias line")
	}
	return alias{pattern: fields[0], module: fields[1]}, true, nil
}

// loadModuleUnlocked asynchronously loads specified modules
func loadModuleUnlocked(wg *sync.WaitGroup, modules ...string) {
	// TODO: assert that modulesMutex is locked

	loadModule := func(mod string, depsWg *sync.WaitGroup) {
		defer loadingModulesWg.Done()

		depsWg.Wait()
		if err := finitModule(mod); err != nil {
			info("finit(%v): %v", mod, err)
			if errors.Is(err, os.ErrNotExist) {
				missingModulesMutex.Lock()
				missingModules[mod] = true
				missingModulesMutex.Unlock()
			}
		}

		modulesMutex.Lock()
		defer modulesMutex.Unlock()

		for _, w := range loadingModules[mod] {
			// signal waiters that the module is loaded
			w.Done()
		}
		delete(loadingModules, mod)
		loadedModules[mod] = true

		// Post dependencies are best-effort follow-up loads. They run after the
		// parent module finishes so they never block the main dependency chain.
		var postDepsWg sync.WaitGroup
		if deps, ok := config.ModulePostDependencies[mod]; ok {
			loadModuleUnlocked(&postDepsWg, deps...)
		}
	}

	for _, module := range modules {

		if _, ok := loadedModules[module]; ok {
			continue // the module is already loaded
		}

		if ok := config.BuiltinModules[module]; ok {
			continue // no need to load builtin module
		}

		_, alreadyLoading := loadingModules[module]
		wg.Add(1)
		loadingModules[module] = append(loadingModules[module], wg)

		if alreadyLoading {
			// we already incremented 'wg' counter
			// now wait till the module is loaded
			continue
		}

		var depsWg sync.WaitGroup
		if deps, ok := config.ModuleDependencies[module]; ok {
			loadModuleUnlocked(&depsWg, deps...)
		}

		loadingModulesWg.Add(1)
		go loadModule(module, &depsWg)
	}

	return
}

func finitModule(module string) error {
	f, err := os.Open(imageModulesDir + "/" + module + ".ko")
	if err != nil {
		return err
	}
	defer f.Close()

	// these are module parameters coming from modprobe
	var opts []string
	// I am not sure if ordering is important but we add modprobe params first and then cmdline
	if v, ok := config.ModprobeOptions[module]; ok {
		opts = append(opts, v)
	}
	opts = append(opts, moduleParams[module]...)

	params := strings.Join(opts, " ")

	if params == "" {
		debug("loading module %s", module)
	} else {
		debug("loading module %s params=\"%s\"", module, params)
	}
	return unix.FinitModule(int(f.Fd()), params, 0)
}

func loadModules(modules ...string) *sync.WaitGroup {
	var wg sync.WaitGroup

	modulesMutex.Lock()
	defer modulesMutex.Unlock()

	loadModuleUnlocked(&wg, modules...)
	return &wg
}

// returns all module names that match given alias
func matchAlias(tofind ...string) []string {
	var result []string
	for _, a := range aliases {
		for _, f := range tofind {
			match, err := filepath.Match(a.pattern, f)
			if err != nil {
				warning("unable to use modalias %s", a.pattern)
				continue
			}
			if match {
				debug("modalias %v matched module %v", f, a.module)
				result = append(result, a.module)
			}
		}
	}
	return result
}
