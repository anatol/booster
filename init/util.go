package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"syscall"
)

func MemZeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

func fixedArrayToString(buff []byte) string {
	idx := bytes.IndexByte(buff, 0)
	if idx != -1 {
		buff = buff[:idx]
	}
	return string(buff)
}

func macListContains(value net.HardwareAddr, list []net.HardwareAddr) bool {
	for _, v := range list {
		if bytes.Compare(v, value) == 0 {
			return true
		}
	}
	return false
}

// deviceNo returns major/minor device number for the given device file
func deviceNo(path string) (uint64, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return 0, err

	}
	sys, ok := stat.Sys().(*syscall.Stat_t)

	if !ok {
		return 0, fmt.Errorf("Cannot determine the device major and minor numbers for %s", path)
	}

	return sys.Rdev, nil
}
