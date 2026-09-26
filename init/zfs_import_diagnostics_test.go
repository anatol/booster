package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestZfsImportTimeoutDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name       string
		script     string
		diagnostic string
	}{
		{
			"cached-output-before-timeout",
			"echo 'cached import diagnostic' >&2\nexec /bin/sleep 2\n",
			"cached import diagnostic",
		},
		{
			"cached-error-before-silent-scan",
			"if [ \"$2\" = '-c' ]; then echo 'cached import diagnostic' >&2; exit 1; fi\nexec /bin/sleep 2\n",
			"cached import diagnostic",
		},
		{
			"new-scan-output-before-timeout",
			"if [ \"$2\" = '-c' ]; then exit 1; fi\nif [ ! -e \"$ZPOOL_TEST_STATE\" ]; then : >\"$ZPOOL_TEST_STATE\"; echo 'old scan diagnostic' >&2; exit 1; fi\necho 'new scan diagnostic' >&2\nexec /bin/sleep 2\n",
			"new scan diagnostic",
		},
		{
			"no-output-before-timeout",
			"if [ \"$2\" = '-c' ]; then exit 1; fi\nexec /bin/sleep 2\n",
			"increase mount_timeout",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origConfig, origDataset := config, zfsDataset
			t.Cleanup(func() { config, zfsDataset = origConfig, origDataset })
			config = InitConfig{BuiltinModules: map[string]bool{"zfs": true}, MountTimeout: 1}
			zfsDataset = "tank/ROOT"
			dir := t.TempDir()
			t.Setenv("PATH", dir)
			t.Setenv("ZPOOL_TEST_STATE", dir+"/attempted")
			require.NoError(t, os.WriteFile(dir+"/zpool", []byte("#!/bin/sh\n"+tc.script), 0o755))
			started := time.Now()
			err := mountZfsRoot()
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.Less(t, time.Since(started), 1500*time.Millisecond)
			require.ErrorContains(t, err, tc.diagnostic)
			require.ErrorContains(t, err, "zpool import tank timed out after 1s")
			require.NotContains(t, err.Error(), "old scan diagnostic")
			if tc.name == "no-output-before-timeout" {
				require.NotContains(t, err.Error(), "signal: killed")
			}
		})
	}
}
