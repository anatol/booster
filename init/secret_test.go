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

func TestWipeSecretCache(t *testing.T) {
	p1 := []byte("hunter2")
	p2 := []byte("correct horse battery")

	passphraseCache.Lock()
	passphraseCache.passwords = [][]byte{p1, p2}
	passphraseCache.Unlock()

	wipeSecretCache()

	// p1/p2 are the retained slice headers; assert their backing arrays were
	// zeroed (proves the bytes were cleared, not just the cache header dropped).
	require.True(t, allZero(p1), "p1 backing not zeroed")
	require.True(t, allZero(p2), "p2 backing not zeroed")

	passphraseCache.Lock()
	require.Nil(t, passphraseCache.passwords)
	passphraseCache.Unlock()
}

func TestWipeSecretCacheIdempotent(t *testing.T) {
	passphraseCache.Lock()
	passphraseCache.passwords = nil
	passphraseCache.Unlock()
	require.NotPanics(t, wipeSecretCache)
}
