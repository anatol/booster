package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	wipe(b)
	require.Equal(t, []byte{0, 0, 0, 0, 0}, b)
}

func TestWipeEmpty(t *testing.T) {
	require.NotPanics(t, func() { wipe(nil) })
	require.NotPanics(t, func() { wipe([]byte{}) })
}
