package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBimap(t *testing.T) {
	b := NewBimap()

	require.NoError(t, b.Add("f1", "p1"))
	val, _ := b.forward["f1"]
	require.Equal(t, "p1", val)

	val, _ = b.reverse["p1"]
	require.Equal(t, "f1", val)

	require.Error(t, b.Add("f2", "p1"))
}
