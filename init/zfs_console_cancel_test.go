package main

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestZfsConsoleCancellationDoesNotReportWrongPassword(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)
	output, err := os.CreateTemp(t.TempDir(), "console")
	require.NoError(t, err)
	stdout := os.Stdout
	os.Stdout = output
	t.Cleanup(func() {
		os.Stdout = stdout
		output.Close()
	})
	password := []byte("console-password")
	askKeyboardPassword = func(context.Context, string, string) ([]byte, error) {
		return password, nil
	}
	execZfsLoadKey = func(ctx context.Context, dataset string, input []byte) (bool, error) {
		if string(input) == "ssh-password" {
			return true, nil
		}
		// SSH wins while the console's command is in flight. The canceled
		// command returns the same result as execZfsLoadKey's cancellation path.
		require.Equal(t, []string{"tank/ROOT"}, trySubmitPassphraseToPending([]byte("ssh-password")))
		require.ErrorIs(t, ctx.Err(), context.Canceled)
		return false, nil
	}
	require.NoError(t, loadZfsKey("tank/ROOT"))
	os.Stdout = stdout
	printed, err := os.ReadFile(output.Name())
	require.NoError(t, err)
	require.NotContains(t, string(printed), "Incorrect passphrase")
	require.True(t, allZero(password), "the canceled console password must be wiped")
}
