package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestZfsUnattendedKeyRetries(t *testing.T) {
	for _, location := range []string{"https://keys.invalid/root.key", "file:///delayed.key"} {
		t.Run(location, func(t *testing.T) {
			resetZfsHarness(t)
			getZfsPropertyValue = func(string, string) (string, error) { return location, nil }
			dir := t.TempDir()
			t.Setenv("PATH", dir)
			t.Setenv("ZFS_TEST_STATE", dir+"/attempted")
			require.NoError(t, os.WriteFile(dir+"/zfs", []byte("#!/bin/sh\nif [ ! -e \"$ZFS_TEST_STATE\" ]; then\n  : >\"$ZFS_TEST_STATE\"\n  echo 'key source is not ready' >&2\n  exit 1\nfi\nexit 0\n"), 0o755))
			origTimeout := config.MountTimeout
			config.MountTimeout = 1
			t.Cleanup(func() { config.MountTimeout = origTimeout })
			require.NoError(t, loadZfsKey("tank/ROOT"))
		})
	}
}

func TestZfsUnattendedKeyDeadline(t *testing.T) {
	for _, tc := range []struct {
		name       string
		script     string
		diagnostic string
	}{
		{"failed-fetch", "echo 'Could not resolve host: keys.invalid' >&2\nexit 1\n", "Could not resolve host"},
		{"stalled-fetch", "exec /bin/sleep 2\n", "context deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetZfsHarness(t)
			getZfsPropertyValue = func(string, string) (string, error) { return "https://keys.invalid/root.key", nil }
			origTimeout, origDefault := config.MountTimeout, defaultKeyfileDeviceTimeout
			config.MountTimeout, defaultKeyfileDeviceTimeout = 0, 150*time.Millisecond
			t.Cleanup(func() { config.MountTimeout, defaultKeyfileDeviceTimeout = origTimeout, origDefault })
			dir := t.TempDir()
			t.Setenv("PATH", dir)
			require.NoError(t, os.WriteFile(dir+"/zfs", []byte("#!/bin/sh\n"+tc.script), 0o755))
			started := time.Now()
			err := loadZfsKey("tank/ROOT")
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.ErrorContains(t, err, tc.diagnostic)
			require.Less(t, time.Since(started), time.Second)
		})
	}
}
