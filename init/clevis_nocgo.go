//go:build !cgo

package main

import (
	"github.com/anatol/booster/init/clevisiface"
)

var clevisPlugin clevisiface.ClevisPlugin

func loadClevisPlugin() error {
	warning("clevis: init was built without cgo, clevis tokens cannot be unlocked")
	return nil
}
