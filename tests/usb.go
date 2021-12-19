package tests

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

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
		return nil, err
	}

	yubikeys := make([]usbdev, 0)

	for _, l := range strings.Split(string(out), "\n") {
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
