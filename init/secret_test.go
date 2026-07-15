package main

import (
	"context"
	"testing"

	"github.com/anatol/luks.go"
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

// resetKeyboardHarness puts the package into a state where requestKeyboardPassword
// runs without real plymouth/terminal I/O.
func resetKeyboardHarness(t *testing.T) {
	t.Helper()
	plymouthEnabled = false
	plymouthInitDone = make(chan struct{})
	close(plymouthInitDone) // waitForPlymouthInit returns immediately
	passphraseCache.Lock()
	passphraseCache.passwords = nil
	passphraseCache.Unlock()
}

func TestRequestKeyboardPasswordWipesFailedAttempts(t *testing.T) {
	resetKeyboardHarness(t)

	var handed [][]byte
	askKeyboardPassword = func(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
		p := []byte("wrongpass")
		handed = append(handed, p)
		return p, nil
	}
	t.Cleanup(func() { askKeyboardPassword = askPasswordWithFallback })

	dev := &fenceFakeLuksDevice{
		unseal: func(int, []byte) (*luks.Volume, error) {
			return nil, luks.ErrPassphraseDoesNotMatch
		},
	}
	volumes := make(chan *luks.Volume, 1)

	requestKeyboardPassword(context.Background(), volumes, dev, []int{0}, "root", 2)

	require.Len(t, handed, 2, "expected maxTries=2 attempts")
	for i, p := range handed {
		require.Truef(t, allZero(p), "failed attempt %d not wiped", i)
	}
}

func TestRequestKeyboardPasswordKeepsCachedPassphrase(t *testing.T) {
	resetKeyboardHarness(t)

	secret := []byte("goodpass")
	askKeyboardPassword = func(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
		return secret, nil
	}
	t.Cleanup(func() { askKeyboardPassword = askPasswordWithFallback })

	dev := &fenceFakeLuksDevice{
		unseal: func(int, []byte) (*luks.Volume, error) {
			return &luks.Volume{}, nil // success on first try
		},
	}
	volumes := make(chan *luks.Volume, 1)

	requestKeyboardPassword(context.Background(), volumes, dev, []int{0}, "root", 3)

	// The success branch caches by reference and must NOT wipe.
	passphraseCache.Lock()
	require.Len(t, passphraseCache.passwords, 1)
	require.False(t, allZero(passphraseCache.passwords[0]), "cached passphrase wrongly wiped")
	passphraseCache.Unlock()

	// And the handoff wipe clears it.
	wipeSecretCache()
	require.True(t, allZero(secret), "cached passphrase not wiped at handoff")
}
