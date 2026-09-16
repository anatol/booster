package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
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
	t.Cleanup(func() {
		defer yubikeyMu.Unlock()

		// A killed qemu leaves the key without its host drivers, so hand it
		// back before the next test, or the user's own login, wants it.
		keys, err := detectYubikeys()
		if err != nil {
			return
		}
		for _, k := range keys {
			if !k.detached() {
				continue
			}
			if err := k.reattach(); err != nil {
				t.Logf("qemu left the security key without its host drivers and reattaching failed (%v): replug it, or the host has no hidraw for it and pam_u2f, libfido2 and systemd-cryptenroll will all report no device", err)
			}
		}
	})
}

type usbdev struct {
	bus, device string
}

func (usb usbdev) toQemuParams() []string {
	return []string{"-usb", "-device", "usb-host,hostbus=" + usb.bus + ",hostaddr=" + usb.device}
}

// sysfsPath finds the device's directory under /sys/bus/usb/devices, which is
// named by bus and port rather than by the bus and address lsusb reports.
func (usb usbdev) sysfsPath() (string, error) {
	dirs, err := filepath.Glob("/sys/bus/usb/devices/*")
	if err != nil {
		return "", err
	}
	for _, dir := range dirs {
		busnum, err1 := os.ReadFile(filepath.Join(dir, "busnum"))
		devnum, err2 := os.ReadFile(filepath.Join(dir, "devnum"))
		if err1 != nil || err2 != nil {
			continue // an interface directory, not a device
		}
		if atoiTrim(string(busnum)) == atoiTrim(usb.bus) && atoiTrim(string(devnum)) == atoiTrim(usb.device) {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no sysfs entry for usb %v:%v", usb.bus, usb.device)
}

func atoiTrim(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// detached reports whether any HID interface of the device has lost its driver.
// qemu unbinds them to claim the device through usbfs, and rebinds on a clean
// exit; a killed qemu does not, and the host is then left without the hidraw
// nodes that libfido2, systemd-cryptenroll and pam_u2f need.
func (usb usbdev) detached() bool {
	dir, err := usb.sysfsPath()
	if err != nil {
		return false
	}
	ifaces, err := filepath.Glob(dir + "/*:*")
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		class, err := os.ReadFile(filepath.Join(iface, "bInterfaceClass"))
		if err != nil || strings.TrimSpace(string(class)) != "03" { // 03: HID
			continue
		}
		if _, err := os.Stat(filepath.Join(iface, "driver")); err != nil {
			return true
		}
	}
	return false
}

// usbfs ioctls from linux/usbdevice_fs.h, none of which x/sys/unix defines:
// USBDEVFS_IOCTL is _IOWR('U', 18, struct usbdevfs_ioctl), the wrapper that
// carries a per-interface request, and USBDEVFS_CONNECT is _IO('U', 23), the
// request that asks the kernel to bind a driver to one interface again.
const (
	usbdevfsIoctlReq = 0xc0105512
	usbdevfsConnect  = 0x5517
)

// usbdevfsIoctl is struct usbdevfs_ioctl.
type usbdevfsIoctl struct {
	ifno      int32
	ioctlCode int32
	data      uintptr
}

// reattach gives the device's HID interfaces back to the host.  This is what
// libusb_attach_kernel_driver does: ask usbfs to rebind the driver on each
// interface.  It goes through the device node, which logind's uaccess ACL
// already opens to the logged-in user, so no privileges are needed; writing to
// the driver's bind file in sysfs would have needed root.  A usbfs reset is not
// an alternative, it re-enumerates without rebinding.
func (usb usbdev) reattach() error {
	dir, err := usb.sysfsPath()
	if err != nil {
		return err
	}
	ifaces, err := filepath.Glob(dir + "/*:*")
	if err != nil {
		return err
	}

	node := fmt.Sprintf("/dev/bus/usb/%03d/%03d", atoiTrim(usb.bus), atoiTrim(usb.device))
	f, err := os.OpenFile(node, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, iface := range ifaces {
		class, err := os.ReadFile(filepath.Join(iface, "bInterfaceClass"))
		if err != nil || strings.TrimSpace(string(class)) != "03" { // 03: HID
			continue
		}
		if _, err := os.Stat(filepath.Join(iface, "driver")); err == nil {
			continue // already bound
		}
		num, err := os.ReadFile(filepath.Join(iface, "bInterfaceNumber"))
		if err != nil {
			return err
		}
		arg := usbdevfsIoctl{ifno: int32(atoiTrim(string(num))), ioctlCode: usbdevfsConnect}
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), usbdevfsIoctlReq, uintptr(unsafe.Pointer(&arg))); errno != 0 {
			return fmt.Errorf("reattaching interface %v: %v", strings.TrimSpace(string(num)), errno)
		}
	}

	// Binding is asynchronous: the ioctl returns before the hidraw node exists.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !usb.detached() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("interfaces still have no driver")
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
