package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cavaliercoder/go-cpio"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4"
	"github.com/ulikunitz/xz"
)

var errStop = fmt.Errorf("Stop Processing")

type processCpioEntryFn func(header *cpio.Header, reader *cpio.Reader) error

func processImage(file string, fn processCpioEntryFn) error {
	input, err := os.Open(file)
	if err != nil {
		return err
	}

	var img *cpio.Reader

	kind, err := filetype(input)
	if err != nil {
		return err
	}

	switch kind {
	case "cpio":
		img = cpio.NewReader(input)
	case "zstd":
		zst, err := zstd.NewReader(input)
		if err != nil {
			return err
		}
		defer zst.Close()
		img = cpio.NewReader(zst)
	case "gzip":
		gz, err := gzip.NewReader(input)
		if err != nil {
			return err
		}
		defer gz.Close()
		img = cpio.NewReader(gz)
	case "xz":
		conf := xz.ReaderConfig{}
		if err := conf.Verify(); err != nil {
			return err
		}
		x, err := conf.NewReader(input)
		if err != nil {
			return err
		}
		img = cpio.NewReader(x)
	case "lz4":
		lz := lz4.NewReaderLegacy(input)
		img = cpio.NewReader(lz)
	}

	for {
		hdr, err := img.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		err = fn(hdr, img)
		if err == errStop {
			break
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func runUnpack() error {
	dir := opts.UnpackCommand.Args.OutputDir
	fn := func(hdr *cpio.Header, r *cpio.Reader) error {
		out := filepath.Join(dir, hdr.Name)
		if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
			return err
		}
		m := hdr.Mode &^ cpio.ModePerm
		switch m {
		case cpio.ModeDir:
			if err := os.Mkdir(out, 0755); err != nil {
				return err
			}
		case cpio.ModeSymlink:
			if err := os.Symlink(hdr.Linkname, out); err != nil {
				return err
			}
		case cpio.ModeRegular:
			fout, err := os.Open(out)
			if err != nil {
				return err
			}
			if _, err := io.Copy(fout, r); err != nil {
				return err
			}
		default:
			warning("Unknown mode for file %s: %x", hdr.Name, m)
		}
		return nil
	}
	return processImage(opts.UnpackCommand.Args.Image, fn)
}

func runCat() error {
	fn := func(hdr *cpio.Header, r *cpio.Reader) error {
		if hdr.Name == opts.CatCommand.Args.File {
			if _, err := io.Copy(os.Stdout, r); err != nil {
				return err
			}
			return errStop
		}
		return nil
	}
	return processImage(opts.CatCommand.Args.Image, fn)
}

func runLs() error {
	fn := func(hdr *cpio.Header, r *cpio.Reader) error {
		m := hdr.Mode &^ cpio.ModePerm
		switch m {
		case cpio.ModeDir:
			fmt.Printf("%s/\n", hdr.Name)
		case cpio.ModeSymlink:
			fmt.Printf("%s -> %s\n", hdr.Name, hdr.Linkname)
		case cpio.ModeRegular:
			fmt.Println(hdr.Name)
		default:
			warning("Unknown mode for file %s: %x", hdr.Name, m)
		}
		return nil
	}
	return processImage(opts.LsCommand.Args.Image, fn)
}
