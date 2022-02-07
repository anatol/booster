package main

import (
	"os"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// Goes over host's block devices and verifies its wwid
func TestHostDeviceWWID(t *testing.T) {
	ents, err := os.ReadDir("/sys/block")
	require.NoError(t, err)
	var generatedWwids []string
	for _, e := range ents {
		wwids, err := wwid("/dev/" + e.Name())
		if os.IsPermission(err) {
			t.Skip("test requires root permission")
		}
		require.NoError(t, err)
		if wwids == nil {
			continue // the block has no wwids
		}
		generatedWwids = append(generatedWwids, wwids...)
	}

	ents, err = os.ReadDir("/dev/disk/by-id")
	require.NoError(t, err)
	var existedWwids []string

	partitionRe, err := regexp.Compile(`-part\d+$`)
	require.NoError(t, err)

	for _, e := range ents {
		if partitionRe.MatchString(e.Name()) {
			// ignore partitions
			continue
		}

		existedWwids = append(existedWwids, e.Name())
	}

	sort.Strings(existedWwids)
	sort.Strings(generatedWwids)
	require.Equal(t, existedWwids, generatedWwids)
}
