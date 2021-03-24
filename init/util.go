package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
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

type UUID []byte

const uuidLen = 36

var uuidRe = regexp.MustCompile(`[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}`)

// parseUUID parses input string that provides UUID in format that matches uuidRe
func parseUUID(uuid string) (UUID, error) {
	if len(uuid) != uuidLen {
		return nil, fmt.Errorf("expected input length is %d, got length %d", uuidLen, len(uuid))
	}

	if !uuidRe.MatchString(uuid) {
		return nil, fmt.Errorf("invalid UUID format")
	}

	noDashes := strings.Replace(uuid, "-", "", -1)
	return hex.DecodeString(noDashes)
}

func (uuid UUID) toString() string {
	if len(uuid) == 16 {
		// UUID version 4
		return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
	} else {
		// a regular non-UUID id (e.g. MSDOS id)
		return hex.EncodeToString(uuid)
	}
}
