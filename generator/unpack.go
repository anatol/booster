package main

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cavaliergopher/cpio"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

var errStop = fmt.Errorf("Stop Processing")

type processCpioEntryFn func(header *cpio.Header, reader *cpio.Reader) error

func resolveUnpackPath(baseDir, archivePath string) (string, error) {
	cleaned := filepath.Clean(archivePath)
	if cleaned == "." || filepath.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive path %q", archivePath)
	}

	out := filepath.Join(baseDir, cleaned)
	rel, err := filepath.Rel(baseDir, out)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("unsafe archive path %q", archivePath)
	}

	return out, nil
}

func ensureDirNoSymlink(baseDir, targetDir string) error {
	rel, err := filepath.Rel(baseDir, targetDir)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("path escapes unpack root: %s", targetDir)
	}

	current := baseDir
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)

		info, err := os.Lstat(current)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if err := os.Mkdir(current, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
					return err
				}
				continue
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in unpack path: %s", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("path component is not a directory: %s", current)
		}
	}

	return nil
}

func ensurePathNotSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write via symlink path: %s", path)
	}
	return nil
}

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
		lz, err := newLz4Reader(input)
		if err != nil {
			return err
		}
		defer lz.Close()
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
	dir, err := filepath.Abs(opts.UnpackCommand.Args.OutputDir)
	if err != nil {
		return err
	}
	fn := func(hdr *cpio.Header, r *cpio.Reader) error {
		out, err := resolveUnpackPath(dir, hdr.Name)
		if err != nil {
			return err
		}
		if err := ensureDirNoSymlink(dir, filepath.Dir(out)); err != nil {
			return err
		}
		m := hdr.Mode & 0o770000
		switch m {
		case cpio.TypeDir:
			if err := ensurePathNotSymlink(out); err != nil {
				return err
			}
			if err := os.Mkdir(out, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		case cpio.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, out); err != nil {
				return err
			}
		case cpio.TypeSocket:
			fallthrough
		case cpio.TypeBlock:
			fallthrough
		case cpio.TypeChar:
			fallthrough
		case cpio.TypeFifo:
			// for device files create an empty regular file
			if err := ensurePathNotSymlink(out); err != nil {
				return err
			}
			f, err := os.Create(out)
			if err != nil {
				return err
			}
			f.Close()
		case cpio.TypeReg:
			if err := ensurePathNotSymlink(out); err != nil {
				return err
			}
			fout, err := os.Create(out)
			if err != nil {
				return err
			}
			if _, err := io.Copy(fout, r); err != nil {
				return err
			}
		default:
			warning("Unknown type for file %s: %#o", hdr.Name, m)
		}
		return nil
	}
	return processImage(opts.UnpackCommand.Args.Image, fn)
}

func runCat() error {
	var foundFile bool
	fn := func(hdr *cpio.Header, r *cpio.Reader) error {
		if hdr.Name == opts.CatCommand.Args.File {
			if _, err := io.Copy(os.Stdout, r); err != nil {
				return err
			}

			foundFile = true
			return errStop
		}
		return nil
	}

	err := processImage(opts.CatCommand.Args.Image, fn)
	if err != nil {
		return err
	} else if !foundFile {
		return fs.ErrNotExist
	}

	return nil
}

func runLs() error {
	fn := func(hdr *cpio.Header, r *cpio.Reader) error {
		m := hdr.Mode & 0o770000
		switch m {
		case cpio.TypeDir:
			fmt.Printf("%s/\n", hdr.Name)
		case cpio.TypeSymlink:
			fmt.Printf("%s -> %s\n", hdr.Name, hdr.Linkname)
		case cpio.TypeSocket:
			fallthrough
		case cpio.TypeBlock:
			fallthrough
		case cpio.TypeChar:
			fallthrough
		case cpio.TypeFifo:
			fmt.Println(hdr.Name)
		case cpio.TypeReg:
			fmt.Println(hdr.Name)
		default:
			warning("Unknown mode for file %s: %#o", hdr.Name, m)
		}
		return nil
	}
	return processImage(opts.LsCommand.Args.Image, fn)
}
