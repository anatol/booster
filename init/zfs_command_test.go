package main

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExecZfsLoadKeyDiagnostics(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	require.NoError(t, os.WriteFile(dir+"/zfs", []byte("#!/bin/sh\necho 'TLS certificate verification failed' >&2\nexit 1\n"), 0o755))
	ok, err := execZfsLoadKey(context.Background(), "tank/ROOT", nil)
	require.False(t, ok)
	require.ErrorContains(t, err, "zfs load-key tank/ROOT")
	require.ErrorContains(t, err, "TLS certificate verification failed")
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
}

func TestExecZfsLoadKeyIncorrectPassphrase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	require.NoError(t, os.WriteFile(dir+"/zfs", []byte("#!/bin/sh\nread -r password\necho 'Incorrect key provided' >&2\nexit 1\n"), 0o755))
	ok, err := execZfsLoadKey(context.Background(), "tank/ROOT", []byte("wrong-password"))
	require.False(t, ok)
	require.NoError(t, err, "incorrect interactive passwords must remain retryable")
}

func TestExecZfsLoadKeyCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, password := range [][]byte{nil, []byte("ssh-password")} {
		ok, err := execZfsLoadKey(ctx, "tank/ROOT", password)
		require.False(t, ok)
		if password == nil {
			require.ErrorIs(t, err, context.Canceled)
		} else {
			require.NoError(t, err, "SSH cancellation must dismiss the console path")
		}
	}
}
