package main

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/cavaliercoder/go-cpio"
	"github.com/google/renameio"
	"github.com/klauspost/compress/zstd"
)

type Image struct {
	file       *renameio.PendingFile
	compressor io.Closer
	out        *cpio.Writer
	contains   map[string]bool // whether image contains the file
}

func NewImage(path string, compression string) (*Image, error) {
	file, err := renameio.TempFile("", path)
	if err != nil {
		return nil, fmt.Errorf("new image: %v", err)
	}
	if err := file.Chmod(0644); err != nil {
		return nil, err
	}

	var compressor io.WriteCloser
	switch compression {
	case "zstd":
		compressor, err = zstd.NewWriter(file)
	case "gzip":
		compressor = gzip.NewWriter(file)
	case "none":
		compressor = file
	default:
		err = fmt.Errorf("Unknown compression format: %s", compression)
	}
	if err != nil {
		return nil, err
	}
	out := cpio.NewWriter(compressor)

	return &Image{
		file:       file,
		compressor: compressor,
		out:        out,
		contains:   make(map[string]bool),
	}, nil
}

func (img *Image) Cleanup() {
	_ = img.out.Close()
	if img.compressor != img.file {
		_ = img.compressor.Close()
	}
	_ = img.file.Cleanup()
}

func (img *Image) Close() error {
	if err := img.out.Close(); err != nil {
		return err
	}
	if img.compressor != img.file {
		if err := img.compressor.Close(); err != nil {
			return err
		}
	}
	return img.file.CloseAtomicallyReplace()
}

// AppendDirEntry appends directory entry to the image (and its parent if it is needed).
// It does not add the directory content
func (img *Image) AppendDirEntry(dir string) error {
	if img.contains[dir] {
		return nil
	}
	if dir == "/" {
		return nil
	}

	parent := path.Dir(dir)
	if err := img.AppendDirEntry(parent); err != nil {
		return err
	}

	hdr := &cpio.Header{
		Name: strings.TrimPrefix(dir, "/"),
		Mode: cpio.FileMode(0755) | cpio.ModeDir,
	}
	if err := img.out.WriteHeader(hdr); err != nil {
		return fmt.Errorf("AppendDirEntry: %v", err)
	}
	img.contains[dir] = true
	return nil
}

func (img *Image) AppendContent(content []byte, mode os.FileMode, dest string) error {
	if img.contains[dest] {
		return fmt.Errorf("Trying to add a file %s but it already been added to the image", dest)
	}

	// append parent dirs first
	if err := img.AppendDirEntry(path.Dir(dest)); err != nil {
		return err
	}

	hdr := &cpio.Header{
		Name: strings.TrimPrefix(dest, "/"),
		Mode: cpio.FileMode(mode) | cpio.ModeRegular,
		Size: int64(len(content)),
	}
	if err := img.out.WriteHeader(hdr); err != nil {
		return fmt.Errorf("AppendFile: %v", err)
	}
	if _, err := img.out.Write(content); err != nil {
		return err
	}
	img.contains[dest] = true

	const minimalELFSize = 64 // 64 bytes is a size of 64bit ELF header
	if len(content) < minimalELFSize {
		return nil
	}
	// now check if the added file was ELF, then we scan the ELF dependencies and add them as well
	ef, err := elf.NewFile(bytes.NewReader(content))
	if err != nil {
		if _, ok := err.(*elf.FormatError); !ok || !strings.HasPrefix(err.Error(), "bad magic number") {
			// not an ELF
			return fmt.Errorf("cannot open ELF file: %v", err)
		} else {
			return nil
		}
	}
	defer ef.Close()

	if err := img.AppendElfDependencies(ef); err != nil {
		return fmt.Errorf("AppendFile: %v", err)
	}

	return nil
}

// AppendFile appends the file + its dependencies to the ramfs file
// If input is a directory then content is added to the image recursively.
func (img *Image) AppendFile(fn string) error {
	fn = path.Clean(fn)
	if img.contains[fn] {
		return nil
	}

	if err := img.AppendDirEntry(path.Dir(fn)); err != nil {
		return err
	}

	fi, err := os.Lstat(fn)
	if err != nil {
		return fmt.Errorf("AppendFile: %v", err)
	}

	if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		linkTarget, err := os.Readlink(fn)
		if err != nil {
			return fmt.Errorf("AppendFile: %v", err)
		}

		hdr := &cpio.Header{
			Name: strings.TrimPrefix(fn, "/"),
			Mode: cpio.FileMode(fi.Mode().Perm()) | cpio.ModeSymlink,
			Size: int64(len(linkTarget)),
		}
		if err := img.out.WriteHeader(hdr); err != nil {
			return fmt.Errorf("AppendFile: %v", err)
		}
		if _, err := img.out.Write([]byte(linkTarget)); err != nil {
			return fmt.Errorf("AppendFile: %v", err)
		}
		img.contains[fn] = true

		// now add the link target as well
		if !filepath.IsAbs(linkTarget) {
			linkTarget = path.Join(path.Dir(fn), linkTarget)
		}
		if err := img.AppendFile(linkTarget); err != nil {
			return fmt.Errorf("AppendFile: %v", err)
		}
	} else if fi.IsDir() {
		if err := img.AppendDirEntry(fn); err != nil {
			return err
		}

		files, err := ioutil.ReadDir(fn)
		if err != nil {
			return err
		}
		for _, f := range files {
			if err := img.AppendFile(path.Join(fn, f.Name())); err != nil {
				return err
			}
		}
	} else {
		// file
		content, err := ioutil.ReadFile(fn)
		if err != nil {
			return fmt.Errorf("AppendFile: %v", err)
		}

		if err := img.AppendContent(content, fi.Mode().Perm(), fn); err != nil {
			return fmt.Errorf("AppendFile: %v", err)
		}
	}

	return nil
}

func elfSectionContent(s *elf.Section) (string, error) {
	b, err := s.Data()
	if err != nil {
		return "", err
	}
	return string(b[:bytes.IndexByte(b, '\x00')]), nil
}

func (img *Image) AppendElfDependencies(ef *elf.File) error {
	// TODO: use ef.DynString(elf.DT_RPATH) to calculate path to the loaded library
	// or maybe we can parse /etc/ld.so.cache to get location for all libs?

	libs, err := ef.ImportedLibraries()
	if err != nil {
		return fmt.Errorf("AppendElfDependencies: %v", err)
	}

	is := ef.Section(".interp")
	if is != nil {
		interp, err := elfSectionContent(is)
		if err != nil {
			return err
		}
		libs = append(libs, interp)
	}

	for _, p := range libs {
		if !filepath.IsAbs(p) {
			p = filepath.Join("/usr/lib", p)
		}
		err := img.AppendFile(p)
		if err != nil {
			return fmt.Errorf("AppendElfDependencies: %v", err)
		}
	}
	return nil
}
