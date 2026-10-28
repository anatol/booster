// Package main implements clevisplugin.so, a Go plugin that decrypts Clevis Tang/JWE tokens.
package main

import (
	"github.com/anatol/booster/init/clevisiface"
	"github.com/anatol/clevis.go"
)

// Plugin is the exported symbol loaded by the init binary via plugin.Lookup.
var Plugin clevisiface.ClevisPlugin = &clevisImpl{}

type clevisImpl struct{}

func (c *clevisImpl) Decrypt(payload []byte) ([]byte, error) {
	return clevis.Decrypt(payload)
}
