package main

import (
	"os"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// Goes over host's block devices and verifies its hw path
func TestHostHwPath(t *testing.T) {
	ents, err := os.ReadDir("/sys/block")
	require.NoError(t, err)
	var generatedPaths []string
	for _, e := range ents {
		path, err := hwPath("/dev/" + e.Name())
		require.NoError(t, err)
		if path == "" {
			continue // the block has no hardware path
		}
		generatedPaths = append(generatedPaths, path)
	}

	ents, err = os.ReadDir("/dev/disk/by-path")
	require.NoError(t, err)
	var existedPaths []string

	partitionRe, err := regexp.Compile(`-part\d+$`)
	require.NoError(t, err)

	compatAtaRe, err := regexp.Compile(`-ata-\d+$`)
	require.NoError(t, err)

	for _, e := range ents {
		if partitionRe.MatchString(e.Name()) {
			// ignore partitions
			continue
		}
		if compatAtaRe.MatchString(e.Name()) {
			// booster does not support compat ATA paths
			continue
		}

		existedPaths = append(existedPaths, e.Name())
	}

	sort.Strings(existedPaths)
	sort.Strings(generatedPaths)
	require.Equal(t, existedPaths, generatedPaths)
}
