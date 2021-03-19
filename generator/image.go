package main

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cavaliercoder/go-cpio"
	"github.com/google/renameio"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4"
	"github.com/ulikunitz/xz"
)

type Image struct {
	m sync.Mutex // synchronizes access to shared mutable state

	file          *renameio.PendingFile
	compressor    io.Closer
	out           *cpio.Writer
	contains      set // whether image contains the file
	stripBinaries bool
}

func NewImage(path string, compression string, stripBinaries bool) (*Image, error) {
	file, err := renameio.TempFile("", path)
	if err != nil {
		return nil, err
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
	case "xz":
		conf := xz.WriterConfig{CheckSum: xz.CRC32}
		if err := conf.Verify(); err != nil {
			return nil, err
		}
		compressor, err = conf.NewWriter(file)
	case "lz4":
		compressor = lz4.NewWriterLegacy(file)
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
		file:          file,
		compressor:    compressor,
		out:           out,
		contains:      make(set),
		stripBinaries: stripBinaries,
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
	img.m.Lock()
	if img.contains[dir] {
		img.m.Unlock()
		return nil
	}
	img.contains[dir] = true
	img.m.Unlock()

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
	img.m.Lock()
	err := img.out.WriteHeader(hdr)
	img.m.Unlock()

	return err
}

func stripElf(name string, in []byte, stripAll bool) ([]byte, error) {
	t, err := os.CreateTemp("", "booster.strip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(t.Name())

	if _, err := t.Write(in); err != nil {
		_ = t.Close()
		return nil, err
	}
	_ = t.Close()

	args := []string{"-R", ".note.*", "-R", ".comment", "-R", ".go.buildinfo", "-R", ".gosymtab"}
	if stripAll {
		args = append(args, "--strip-all")
	} else {
		args = append(args, "--strip-unneeded")
	}
	args = append(args, t.Name())
	if out, err := exec.Command("strip", args...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s: %v\n%s", name, err, string(out))
	}

	return os.ReadFile(t.Name())
}

func (img *Image) AppendContent(content []byte, mode os.FileMode, dest string) error {
	img.m.Lock()
	if img.contains[dest] {
		img.m.Unlock()
		warning("trying to add file %s to the image but it is already there", dest)
		return nil
	}
	img.contains[dest] = true
	img.m.Unlock()

	// append parent dirs first
	if err := img.AppendDirEntry(path.Dir(dest)); err != nil {
		return err
	}

	const minimalELFSize = 64 // 64 bytes is a size of 64bit ELF header
	if len(content) >= minimalELFSize {
		// now check if the added file was ELF, then we scan the ELF dependencies and add them as well
		ef, err := elf.NewFile(bytes.NewReader(content))
		if err != nil {
			if _, ok := err.(*elf.FormatError); !ok || !strings.HasPrefix(err.Error(), "bad magic number") {
				// not an ELF
				return fmt.Errorf("cannot open ELF file: %v", err)
			} // else it is a regular non-ELF file
		} else {
			defer ef.Close()

			doStrip := img.stripBinaries
			if strings.HasPrefix(dest, firmwareDir) {
				// some firmware files are actually ELF but we should not run strip on them
				doStrip = false
			}
			if doStrip {
				// do not use --strip-all for modules/shared libs as it fails to load
				isBinary := ef.Type == elf.ET_EXEC
				content, err = stripElf(dest, content, isBinary)
				if err != nil {
					return err
				}
			}

			if err := img.AppendElfDependencies(ef); err != nil {
				return err
			}
		}
	}

	hdr := &cpio.Header{
		Name: strings.TrimPrefix(dest, "/"),
		Mode: cpio.FileMode(mode) | cpio.ModeRegular,
		Size: int64(len(content)),
	}
	img.m.Lock()
	if err := img.out.WriteHeader(hdr); err != nil {
		img.m.Unlock()
		return err
	}
	_, err := img.out.Write(content)
	img.m.Unlock()
	return err
}

// AppendFile appends the file + its dependencies to the ramfs file
// If input is a directory then content is added to the image recursively.
func (img *Image) AppendFile(fn string) error {
	fn = path.Clean(fn)

	img.m.Lock()
	if img.contains[fn] {
		img.m.Unlock()
		return nil
	}
	img.m.Unlock()

	if err := img.AppendDirEntry(path.Dir(fn)); err != nil {
		return err
	}

	fi, err := os.Lstat(fn)
	if err != nil {
		return err
	}

	if fi.Mode()&os.ModeSymlink == os.ModeSymlink {
		// check img.contains again as there might be race-condition between prev check this this update
		img.m.Lock()
		if img.contains[fn] {
			img.m.Unlock()
			return nil
		}
		img.contains[fn] = true
		img.m.Unlock()

		linkTarget, err := os.Readlink(fn)
		if err != nil {
			return err
		}

		hdr := &cpio.Header{
			Name: strings.TrimPrefix(fn, "/"),
			Mode: cpio.FileMode(fi.Mode().Perm()) | cpio.ModeSymlink,
			Size: int64(len(linkTarget)),
		}

		img.m.Lock()
		if err := img.out.WriteHeader(hdr); err != nil {
			img.m.Unlock()
			return err
		}
		if _, err := img.out.Write([]byte(linkTarget)); err != nil {
			img.m.Unlock()
			return err
		}
		img.m.Unlock()

		// now add the link target as well
		if !filepath.IsAbs(linkTarget) {
			linkTarget = path.Join(path.Dir(fn), linkTarget)
		}
		if err := img.AppendFile(linkTarget); err != nil {
			return err
		}
	} else if fi.IsDir() {
		if err := img.AppendDirEntry(fn); err != nil {
			return err
		}

		files, err := os.ReadDir(fn)
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
		content, err := os.ReadFile(fn)
		if err != nil {
			return err
		}

		if err := img.AppendContent(content, fi.Mode().Perm(), fn); err != nil {
			return err
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
		return err
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
			return err
		}
	}
	return nil
}
