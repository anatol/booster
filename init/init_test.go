package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSunderMountFlags(t *testing.T) {
	check := func(input string, flags uintptr, options string) {
		f, o := sunderMountFlags(input)
		if flags != f {
			t.Fatalf("%s: flags expected 0x%x, got 0x%x", input, flags, f)
		}
		if options != o {
			t.Fatalf("%s: options expected %s, got %s", input, options, o)
		}
	}

	check("", 0x0, "")
	check("foobar,atest,eee", 0x0, "foobar,atest,eee")
	check("nodev", unix.MS_NODEV, "")
	check("user_xattr,noatime,nobarrier,nodev,dirsync,lazytime,nolazytime,dev,rw,ro", unix.MS_NOATIME|unix.MS_DIRSYNC|unix.MS_RDONLY, "user_xattr,nobarrier")
}
