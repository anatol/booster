package main

import (
	"bufio"
	"fmt"
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

	mods, err := matchAlias(alias)
	if err != nil {
		return fmt.Errorf("unable to match modalias %s: %v", alias, err)
	}
	if len(mods) == 0 {
		debug("no match found for alias %s", alias)
		return nil
	}
	_, err = loadModules(mods...)
	return err
}

func readAliases() error {
	f, err := os.Open(imageModulesDir + "/booster.alias")
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		parts := strings.Split(line, " ")
		aliases = append(aliases, alias{parts[0], parts[1]})
	}

	return s.Err()
}

func loadModuleUnlocked(wg *sync.WaitGroup, modules ...string) error {
	loadModule := func(mod string, depsWg *sync.WaitGroup) error {
		defer loadingModulesWg.Done()

		depsWg.Wait()
		if err := finitModule(mod); err != nil {
			return fmt.Errorf("finit(%v): %v", mod, err)
		}

		modulesMutex.Lock()
		defer modulesMutex.Unlock()

		for _, w := range loadingModules[mod] {
			// signal waiters that the module is loaded
			w.Done()
		}
		delete(loadingModules, mod)
		loadedModules[mod] = true

		// post deps
		var postDepsWg sync.WaitGroup
		if deps, ok := config.ModuleDependencies[mod]; ok {
			return loadModuleUnlocked(&postDepsWg, deps...)
		}
		return nil
	}

	for _, module := range modules {
		module := module

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
			if err := loadModuleUnlocked(&depsWg, deps...); err != nil {
				return err
			}
		}

		loadingModulesWg.Add(1)
		go func() { check(loadModule(module, &depsWg)) }()
	}

	return nil
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

func loadModules(modules ...string) (*sync.WaitGroup, error) {
	var wg sync.WaitGroup

	modulesMutex.Lock()
	defer modulesMutex.Unlock()

	err := loadModuleUnlocked(&wg, modules...)
	return &wg, err
}

// returns all module names that match given alias
func matchAlias(alias string) ([]string, error) {
	var result []string
	for _, a := range aliases {
		match, err := filepath.Match(a.pattern, alias)
		if err != nil {
			return nil, err
		}
		if match {
			debug("modalias %v matched module %v", alias, a.module)
			result = append(result, a.module)
		}
	}
	return result, nil
}
