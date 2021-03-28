package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
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
	sys, ok := stat.Sys().(*unix.Stat_t)

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

// stripQuotes removes leading and trailing quote symbols if they wrap the given sentence
func stripQuotes(in string) string {
	l := len(in)
	if in[0] == '"' && in[l-1] == '"' {
		return in[1 : l-1]
	}

	return in
}

func getKernelVersion() (string, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}
	release := uts.Release
	length := bytes.IndexByte(release[:], 0)
	return string(uts.Release[:length]), nil
}

// waitTimeout waits for the waitgroup for the specified max timeout.
// Returns true if waiting timed out.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

// readClock returns value of the clock in usec units
func readClock(clockId int32) (uint64, error) {
	var t unix.Timespec
	err := unix.ClockGettime(clockId, &t)
	if err != nil {
		return 0, err
	}
	return uint64(t.Sec)*1000000 + uint64(t.Nsec)/1000, nil
}

// checkIfInitrd checks whether this binary run in a prepared initrd environment
func checkIfInitrd() error {
	if os.Getpid() != 1 {
		return fmt.Errorf("Booster init binary does not run as PID 1")
	}

	if _, err := os.Stat("/etc/initrd-release"); os.IsNotExist(err) {
		return fmt.Errorf("initrd-release cannot be found")
	}

	return nil
}
