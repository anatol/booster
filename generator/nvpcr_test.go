package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppendNvPCRDefinitionsMissingDirs(t *testing.T) {
	img, _ := newTestImage(t)
	prev := nvpcrSearchDirs
	t.Cleanup(func() { nvpcrSearchDirs = prev })
	nvpcrSearchDirs = []string{
		filepath.Join(t.TempDir(), "missing-lib"),
		filepath.Join(t.TempDir(), "missing-etc"),
	}
	require.NoError(t, img.appendNvPCRDefinitions())
}

func TestAppendNvPCRDefinitionsPacksFiles(t *testing.T) {
	root := t.TempDir()
	lib := filepath.Join(root, "usr", "lib", "nvpcr")
	etc := filepath.Join(root, "etc", "nvpcr")
	require.NoError(t, os.MkdirAll(lib, 0o755))
	require.NoError(t, os.MkdirAll(etc, 0o755))

	libBody := []byte(`{"name":"hardware","algorithm":"sha256","nvIndex":30474752,"priority":500,"orderly":false}`)
	etcBody := []byte(`{"name":"login","algorithm":"sha256","nvIndex":30474755,"priority":800}`)
	require.NoError(t, os.WriteFile(filepath.Join(lib, "hardware.nvpcr"), libBody, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(lib, "readme.txt"), []byte("ignore"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(etc, "login.nvpcr"), etcBody, 0o644))

	prev := nvpcrSearchDirs
	t.Cleanup(func() { nvpcrSearchDirs = prev })
	nvpcrSearchDirs = []string{lib, etc}

	img, imgPath := newTestImage(t)
	require.NoError(t, img.appendNvPCRDefinitions())

	require.Equal(t, libBody, readImageFile(t, img, imgPath, filepath.Join(lib, "hardware.nvpcr")))

	img, imgPath = newTestImage(t)
	require.NoError(t, img.appendNvPCRDefinitions())
	require.Equal(t, etcBody, readImageFile(t, img, imgPath, filepath.Join(etc, "login.nvpcr")))

	img, imgPath = newTestImage(t)
	require.NoError(t, img.appendNvPCRDefinitions())
	require.Nil(t, readImageFile(t, img, imgPath, filepath.Join(lib, "readme.txt")))
}
