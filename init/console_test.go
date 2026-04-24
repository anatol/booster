package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConsoleSetFontFailureIsNonFatal(t *testing.T) {
	// Regression test for https://github.com/anatol/booster/issues/234:
	// when setfont exits non-zero (e.g. EINVAL from KMS refusing an oversized
	// font), configureVirtualConsole propagates the error and init exits,
	// preventing the system from booting. A font load failure is cosmetic —
	// boot must continue with a warning rather than crashing.
	f, err := os.CreateTemp("", "booster-test-font-*")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.WriteString("not a valid psf font")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	vc := &VirtualConsole{FontFile: f.Name()}
	err = consoleSetFont(vc)
	require.NoError(t, err) // setfont failure must not propagate — font is cosmetic, boot must continue
}
