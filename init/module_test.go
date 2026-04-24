package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseAliasLine(t *testing.T) {
	t.Parallel()

	a, ok, err := parseAliasLine("pci:v00008086d00002416 snd_intel8x0m")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, alias{
		pattern: "pci:v00008086d00002416",
		module:  "snd_intel8x0m",
	}, a)
}

func TestParseAliasLineRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	_, ok, err := parseAliasLine("")
	require.NoError(t, err)
	require.False(t, ok)

	_, ok, err = parseAliasLine("alias only extra-field")
	require.Error(t, err)
	require.False(t, ok)
}
