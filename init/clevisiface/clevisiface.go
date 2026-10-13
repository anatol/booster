// Package clevisiface defines the ClevisPlugin interface shared between the
// booster init binary and the clevisplugin.so plugin.
package clevisiface

// ClevisPlugin is implemented by clevisplugin.so and loaded at runtime via plugin.Open.
type ClevisPlugin interface {
	Decrypt(payload []byte) ([]byte, error)
}
