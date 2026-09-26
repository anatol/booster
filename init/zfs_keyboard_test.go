package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadZfsKeySshUnlockWhileKeyboardBusy(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)

	// An unrelated LUKS prompt owns the shared keyboard gate.
	keyboardSem <- struct{}{}
	held := true
	t.Cleanup(func() {
		if held {
			select {
			case <-keyboardSem:
			default:
			}
		}
	})
	asked := make(chan struct{}, 1)
	askKeyboardPassword = func(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
		asked <- struct{}{}
		return []byte("local-password"), nil
	}
	execZfsLoadKey = func(ctx context.Context, encryptionRoot string, password []byte) (bool, error) {
		return encryptionRoot == "tank/remote" && string(password) == "ssh-password" ||
			encryptionRoot == "tank/local" && string(password) == "local-password", nil
	}

	done := make(chan error, 1)
	go func() { done <- loadZfsKey("tank/remote") }()
	require.Eventually(t, func() bool {
		return len(pendingDeviceNames()) == 1
	}, time.Second, time.Millisecond)
	require.Equal(t, []string{"tank/remote"}, trySubmitPassphraseToPending([]byte("ssh-password")))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("SSH unlock waited for an unrelated keyboard prompt")
	}
	require.Len(t, keyboardSem, 1, "the unrelated prompt must still own the keyboard")
	require.Empty(t, asked, "ZFS must not prompt while the keyboard is occupied")

	<-keyboardSem
	held = false
	go func() { done <- loadZfsKey("tank/local") }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("keyboard acquisition remained blocked after cancellation")
	}
	require.Len(t, asked, 1)
	require.Empty(t, keyboardSem, "local unlock must release the keyboard")
}
