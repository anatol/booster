package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPromptVolumeUnlocked covers the three states promptVolumeUnlocked can
// observe: no done channel set, an open done channel, and a closed done channel.
// The third case is what statusMessage uses to skip a redraw when the volume's
// already been unlocked by a sibling token.
func TestPromptVolumeUnlocked(t *testing.T) {
	// Save and restore consolePrompt around each subtest so they can mutate it
	// without leaking state.
	saved := consolePrompt
	t.Cleanup(func() { consolePrompt = saved })

	t.Run("nil done returns false", func(t *testing.T) {
		consolePrompt.done = nil
		require.False(t, promptVolumeUnlocked())
	})

	t.Run("open done returns false", func(t *testing.T) {
		ch := make(chan struct{})
		consolePrompt.done = ch
		require.False(t, promptVolumeUnlocked())
	})

	t.Run("closed done returns true", func(t *testing.T) {
		ch := make(chan struct{})
		close(ch)
		consolePrompt.done = ch
		require.True(t, promptVolumeUnlocked())
	})
}

// TestTokenFriendlyName pins down the labels used in the unlock-confirmation
// status message — these are user-visible strings so a typo would ship.
func TestTokenFriendlyName(t *testing.T) {
	cases := []struct {
		typ  string
		want string
	}{
		{"systemd-fido2", "FIDO2"},
		{"systemd-tpm2", "TPM2"},
		{"clevis", "clevis"},
		{"unknown-token-type", "unknown-token-type"}, // fallback: pass through
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			require.Equal(t, tc.want, tokenFriendlyName(tc.typ))
		})
	}
}
