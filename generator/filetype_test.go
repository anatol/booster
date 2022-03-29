package main

import (
	"os"
	"testing"

	"github.com/cavaliergopher/cpio"
	"github.com/stretchr/testify/require"
)

func TestFileType(t *testing.T) {
	dir := t.TempDir()
	check := func(compression, expectedType string) {
		fileName := dir + "/" + compression
		img, err := NewImage(fileName, compression, false)
		require.NoError(t, err)

		require.NoError(t, img.AppendEntry("foo.txt", cpio.TypeReg, []byte("hello, world!")))
		require.NoError(t, img.Close())

		f, err := os.Open(fileName)
		require.NoError(t, err)

		kind, err := filetype(f)
		require.NoError(t, err)

		require.Equal(t, expectedType, kind)
	}

	check("zstd", "zstd")
	check("gzip", "gzip")
	check("xz", "xz")
	check("lz4", "lz4")
	check("none", "cpio")
}
