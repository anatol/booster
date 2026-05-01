package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Goes over host's block devices and verifies generated WWIDs map to /dev/disk/by-id links.
func TestHostDeviceWWID(t *testing.T) {
	ents, err := os.ReadDir("/sys/block")
	require.NoError(t, err)
	matchedWWIDs := 0

	for _, e := range ents {
		device := "/dev/" + e.Name()
		wwids, err := wwid("/dev/" + e.Name())
		if errors.Is(err, fs.ErrPermission) {
			t.Skip("test requires root permission")
		}
		require.NoError(t, err)
		if wwids == nil {
			continue // the block has no wwids
		}

		devPath, err := filepath.EvalSymlinks(device)
		require.NoError(t, err)

		for _, id := range wwids {
			link := filepath.Join("/dev/disk/by-id", id)
			target, err := filepath.EvalSymlinks(link)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			require.NoErrorf(t, err, "invalid WWID symlink %q for %q", link, device)

			require.Equalf(t, devPath, target, "WWID symlink %q points to %q, expected %q", link, target, devPath)
			matchedWWIDs++
		}
	}

	require.Greater(t, matchedWWIDs, 0, "none of generated WWIDs match existing /dev/disk/by-id links")
}
