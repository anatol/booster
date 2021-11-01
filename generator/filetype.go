package main

import (
	"bytes"
	"io"
	"os"
)

type matcher func(seeker io.ReadSeeker) (bool, error)

var matchers = map[string]matcher{
	"zstd": matchZstd,
	"gzip": matchGzip,
	"xz":   matchXz,
	"lz4":  matchLz4,
	"cpio": matchCpio,
}

func matchBytes(f io.ReadSeeker, offset int64, marker []byte) (bool, error) {
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return false, err
	}
	buff := make([]byte, len(marker))
	if _, err := io.ReadFull(f, buff); err != nil {
		return false, nil
	}
	return bytes.Equal(marker, buff), nil
}

func matchCpio(f io.ReadSeeker) (bool, error) {
	return matchBytes(f, 0, []byte{'0', '7', '0', '7', '0', '1'}) // "new" cpio format
}

func matchLz4(f io.ReadSeeker) (bool, error) {
	return matchBytes(f, 0, []byte{0x02, 0x21, 0x4c, 0x18}) // legacy format used by linux loader
}

func matchXz(f io.ReadSeeker) (bool, error) {
	return matchBytes(f, 0, []byte{0xfd, '7', 'z', 'X', 'Z', 0x00})
}

func matchGzip(f io.ReadSeeker) (bool, error) {
	return matchBytes(f, 0, []byte{0x1f, 0x8b})
}

func matchZstd(f io.ReadSeeker) (bool, error) {
	return matchBytes(f, 0, []byte{0x28, 0xb5, 0x2f, 0xfd})
}

func filetype(r *os.File) (string, error) {
	loc, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", err
	}
	defer r.Seek(loc, io.SeekStart)

	for name, match := range matchers {
		ok, err := match(r)
		if err != nil {
			return "", err
		}
		if ok {
			return name, nil
		}
	}

	return "", nil
}
