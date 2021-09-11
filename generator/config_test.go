package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadEmptyConfig(t *testing.T) {
	t.Parallel()

	c, err := readGeneratorConfig("")
	require.NoError(t, err)
	require.Equal(t, "zstd", c.compression)
}
