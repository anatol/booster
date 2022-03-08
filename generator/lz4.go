package main

import (
	"io"
)

// lz4 compressor/decompressor library, wrapper over command-line 'lz4' tool

func newLz4Reader(r io.Reader) (io.ReadCloser, error) {
	return newPipeCommandReader(r, "lz4", "-d", "-c", "-")
}

func newLz4Writer(w io.Writer, legacy bool) (io.WriteCloser, error) {
	args := []string{"-z", "-c"}
	if legacy {
		args = append(args, "-l")
	}
	args = append(args, "-")

	return newPipeCommandWriter(w, "lz4", args...)
}
