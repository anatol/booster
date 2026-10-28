package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestZfsImportCommandDeadline(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
	}{
		{"cached", "exec /bin/sleep 2\n"},
		{"uncached", "if [ \"$2\" = '-c' ]; then exit 1; fi\nexec /bin/sleep 2\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origConfig, origDataset := config, zfsDataset
			t.Cleanup(func() { config, zfsDataset = origConfig, origDataset })
			config = InitConfig{BuiltinModules: map[string]bool{"zfs": true}, MountTimeout: 1}
			zfsDataset = "tank/ROOT"
			dir := t.TempDir()
			t.Setenv("PATH", dir)
			require.NoError(t, os.WriteFile(dir+"/zpool", []byte("#!/bin/sh\n"+tc.script), 0o755))
			started := time.Now()
			err := mountZfsRoot()
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.Less(t, time.Since(started), 1500*time.Millisecond)
		})
	}
}

func TestZfsImportRetriesBeforeDeadline(t *testing.T) {
	origConfig, origDataset := config, zfsDataset
	t.Cleanup(func() { config, zfsDataset = origConfig, origDataset })
	config = InitConfig{BuiltinModules: map[string]bool{"zfs": true}, MountTimeout: 1}
	zfsDataset = "tank/ROOT"
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	t.Setenv("ZPOOL_TEST_STATE", dir+"/attempted")
	require.NoError(t, os.WriteFile(dir+"/zpool", []byte("#!/bin/sh\nif [ -e \"$ZPOOL_TEST_STATE\" ]; then exit 0; fi\nif [ \"$2\" != '-c' ]; then : >\"$ZPOOL_TEST_STATE\"; fi\nexit 1\n"), 0o755))
	require.NoError(t, os.WriteFile(dir+"/zfs", []byte("#!/bin/sh\necho 'dataset listing reached' >&2\nexit 1\n"), 0o755))
	err := mountZfsRoot()
	require.ErrorContains(t, err, "dataset listing reached")
	require.NotErrorIs(t, err, context.DeadlineExceeded)
}
