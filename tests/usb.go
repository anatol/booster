package tests

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// The host has one security key, and a test that wants it hands it to qemu for
// the length of a boot, so while that VM runs the key is gone from the host and
// from every other guest.  Enrolling against it from a sibling test then fails
// with "No FIDO devices found".  Tests that claim it take this lock: they still
// run alongside the rest of the suite, just never alongside each other.
var yubikeyMu sync.Mutex

func claimYubikey(t *testing.T) {
	t.Helper()
	yubikeyMu.Lock()
	t.Cleanup(yubikeyMu.Unlock)
}

type usbdev struct {
	bus, device string
}

func (usb usbdev) toQemuParams() []string {
	return []string{"-usb", "-device", "usb-host,hostbus=" + usb.bus + ",hostaddr=" + usb.device}
}

// detectYubikeys checks if yubikeys tokens are present and uses it slot for tests
func detectYubikeys() ([]usbdev, error) {
	out, err := exec.Command("lsusb").CombinedOutput()
	if err != nil {
		return nil, unwrapExitError(err)
	}

	yubikeys := make([]usbdev, 0)

	for l := range strings.SplitSeq(string(out), "\n") {
		if !strings.Contains(l, "Yubikey") {
			continue
		}

		re, err := regexp.Compile(`Bus 0*(\d+) Device 0*(\d+):`)
		if err != nil {
			return nil, err
		}

		m := re.FindAllStringSubmatch(l, -1)
		if m == nil {
			return nil, fmt.Errorf("lsusb does not match bus/device")
		}

		yubikeys = append(yubikeys, usbdev{m[0][1], m[0][2]})
	}

	return yubikeys, nil
}
