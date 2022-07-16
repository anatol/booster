package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/unix"
)

func memZeroBytes(bytes []byte) {
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
		if bytes.Equal(v, value) {
			return true
		}
	}
	return false
}

func normalizeModuleName(mod string) string {
	return strings.ReplaceAll(mod, "-", "_")
}

// deviceNo returns major/minor device number for the given device file
func deviceNo(path string) (uint64, error) {
	var stat unix.Stat_t
	if err := unix.Stat(path, &stat); err != nil {
		return 0, err
	}

	return stat.Rdev, nil
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
		// a regular non-UUID id (e.g. MS-DOS id)
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
func readClock(clockID int32) (uint64, error) {
	var t unix.Timespec
	err := unix.ClockGettime(clockID, &t)
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

// parseProperties parses input in form of "PROP1=VAL1\nPROP2=VAL2\n..." into a map
func parseProperties(data string) map[string]string {
	re := regexp.MustCompile(`(\w+)=(\S+)`)
	matches := re.FindAllStringSubmatch(data, -1)
	result := make(map[string]string)
	for _, m := range matches {
		result[m[1]] = m[2]
	}

	return result
}

// fromUnicode16 converts NUL ended Unicode16 array to a string
func fromUnicode16(data []byte, by binary.ByteOrder) string {
	n := len(data) / 2
	runes := make([]uint16, n)
	for i := 0; i < n; i++ {
		r := by.Uint16(data[2*i:])
		if r == 0 {
			return string(utf16.Decode(runes[:i]))
		}
		runes[i] = r
	}
	return string(utf16.Decode(runes))
}

func check(err error) {
	if err != nil {
		severe("%v", err)
	}
}

func unwrapExitError(err error) error {
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("%v: %v", err, string(exitErr.Stderr))
	}
	return err
}
