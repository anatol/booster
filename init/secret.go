package main

import "runtime"

// wipe zeroes b in place. It scrubs secret material (LUKS passphrases, TPM2
// PINs) from memory once it is no longer needed, reducing cold-boot exposure.
// runtime.KeepAlive keeps the final stores from being treated as dead once b is
// otherwise unreachable.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
