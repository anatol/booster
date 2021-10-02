package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSunderMountFlags(t *testing.T) {
	check := func(input string, flags uintptr, options string) {
		f, o := sunderMountFlags(input, 0)
		require.Equal(t, flags, f)
		require.Equal(t, options, o)
	}

	check("", 0x0, "")
	check("foobar,atest,eee", 0x0, "foobar,atest,eee")
	check("foo,nosymfollow,bar", unix.MS_NOSYMFOLLOW, "foo,bar")
	check("nodev", unix.MS_NODEV, "")
	check("user_xattr,noatime,nobarrier,nodev,dirsync,lazytime,nolazytime,dev,rw,ro", unix.MS_NOATIME|unix.MS_DIRSYNC|unix.MS_RDONLY, "user_xattr,nobarrier")
}
