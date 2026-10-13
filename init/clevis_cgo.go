//go:build cgo

package main

import (
	"fmt"
	"plugin"

	"github.com/anatol/booster/init/clevisiface"
)

const clevisPluginPath = "/usr/lib/booster/clevisplugin.so"

var clevisPlugin clevisiface.ClevisPlugin

func loadClevisPlugin() error {
	p, err := plugin.Open(clevisPluginPath)
	if err != nil {
		return fmt.Errorf("clevis: cannot open plugin %s: %w", clevisPluginPath, err)
	}
	sym, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("clevis: plugin missing Plugin symbol: %w", err)
	}
	pl, ok := sym.(*clevisiface.ClevisPlugin)
	if !ok {
		return fmt.Errorf("clevis: Plugin symbol does not implement ClevisPlugin interface")
	}
	clevisPlugin = *pl
	return nil
}
