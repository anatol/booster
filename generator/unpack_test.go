package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/stretchr/testify/require"
)

type cpioEntry struct {
	name    string
	mode    cpio.FileMode
	content []byte
}

func writeTestCpio(t *testing.T, entries []cpioEntry) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "test.cpio")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()

	w := cpio.NewWriter(f)
	for _, e := range entries {
		h := &cpio.Header{
			Name: e.name,
			Mode: e.mode,
			Size: int64(len(e.content)),
		}
		require.NoError(t, w.WriteHeader(h))
		if len(e.content) > 0 {
			_, err = w.Write(e.content)
			require.NoError(t, err)
		}
	}
	require.NoError(t, w.Close())
	require.NoError(t, f.Close())

	return path
}

func TestUnpackRejectsPathTraversal(t *testing.T) {
	img := writeTestCpio(t, []cpioEntry{
		{name: "../escape.txt", mode: cpio.TypeReg, content: []byte("data")},
	})

	outDir := t.TempDir()
	opts.UnpackCommand.Args.Image = img
	opts.UnpackCommand.Args.OutputDir = outDir

	err := runUnpack()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsafe archive path")
}

func TestUnpackRejectsSymlinkPivot(t *testing.T) {
	img := writeTestCpio(t, []cpioEntry{
		{name: "pivot", mode: cpio.TypeSymlink, content: []byte("/tmp")},
		{name: "pivot/owned.txt", mode: cpio.TypeReg, content: []byte("owned")},
	})

	outDir := t.TempDir()
	opts.UnpackCommand.Args.Image = img
	opts.UnpackCommand.Args.OutputDir = outDir

	err := runUnpack()
	require.Error(t, err)
	require.Contains(t, err.Error(), "symlink")
}
