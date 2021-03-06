package main

import (
	"bytes"
	"net"
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
