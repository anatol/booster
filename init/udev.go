package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/anatol/devmapper.go"
	"github.com/anatol/uevent.go"
	"golang.org/x/sys/unix"
)

// validDmEvent checks whether this udev event has correct flags.
// This is similar to checks done by /usr/lib/udev/rules.d/10-dm.rules udev rules.
func validDmEvent(ev *uevent.Uevent) bool {
	dmCookie := ev.Vars["DM_COOKIE"]
	if dmCookie == "" {
		info("udev event does not contain DM_COOKIE")
		return false
	}

	cookie, err := strconv.ParseUint(dmCookie, 0, 32)
	if err != nil {
		info("unable to parse DM_COOKIE value: %s", dmCookie)
		return false
	}

	const (
		DM_UDEV_FLAGS_SHIFT           = 16
		DM_UDEV_DISABLE_DM_RULES_FLAG = 0x0001
		DM_UDEV_PRIMARY_SOURCE_FLAG   = 0x0040
	)
	flags := cookie >> DM_UDEV_FLAGS_SHIFT

	// Quoting https://fossies.org/linux/LVM2/libdm/libdevmapper.h
	//
	// DM_UDEV_PRIMARY_SOURCE_FLAG is automatically appended by
	// libdevmapper for all ioctls generating udev uevents. Once used in
	// udev rules, we know if this is a real "primary sourced" event or not.
	// We need to distinguish real events originated in libdevmapper from
	// any spurious events to gather all missing information (e.g. events
	// generated as a result of "udevadm trigger" command or as a result
	// of the "watch" udev rule).
	if flags&DM_UDEV_PRIMARY_SOURCE_FLAG == 0 {
		info("device mapper event: not a primary source")
		return false
	}

	// Quoting https://fossies.org/linux/LVM2/libdm/libdevmapper.h
	//
	// DM_UDEV_DISABLE_DM_RULES_FLAG is set in case we need to disable
	// basic device-mapper udev rules that create symlinks in /dev/<DM_DIR>
	if flags&DM_UDEV_DISABLE_DM_RULES_FLAG != 0 {
		info("device mapper event: dm rules disabled")
		return false
	}

	return true
}

var udevReader io.ReadCloser

func udevListener() error {
	defer func() {
		// uevent.NewDecoder uses bufio.ReadString() that is blocking. If we try to close the underlying udev file descriptor
		// while bufio tries to read from it then bufio panics. See issues #22, #31 and #153
		// There is no clear way to prevent the panic so we just recover from it here and then safely exit the goroutine.
		if r := recover(); r != nil {
			warning("recovered udevListener panic: %v", r)
		}
	}()

	var err error
	udevReader, err = uevent.NewReader()
	if err != nil {
		return err
	}
	defer udevReader.Close()

	dec := uevent.NewDecoder(udevReader)

	for {
		ev, err := dec.Decode()
		if err == io.EOF {
			// EOF is returned if uevent reader is closed concurrently
			return nil
		}
		if err != nil {
			return err
		}
		debug("udev event %+v", *ev)

		// TODO: run each udev in a separate goroutine
		if modalias, ok := ev.Vars["MODALIAS"]; ok {
			go func() { check(loadModalias(modalias)) }()
		} else if ev.Subsystem == "block" {
			go func() { check(handleBlockDeviceUevent(ev)) }()
		} else if ev.Subsystem == "net" {
			go func() { check(handleNetworkUevent(ev)) }()
		} else if ev.Subsystem == "hidraw" && ev.Action == "add" {
			go func() { hidrawDevices <- ev.Vars["DEVNAME"] }()
		}
	}
}

func handleNetworkUevent(ev *uevent.Uevent) error {
	if ev.Action != "add" {
		return nil
	}

	ifname := ev.Vars["INTERFACE"]
	if ifname == "lo" {
		return nil
	}

	if config.Network == nil {
		info("network is disabled, skipping interface %s", ifname)
		return nil
	}

	if len(config.Network.Interfaces) > 0 {
		i, err := net.InterfaceByName(ifname)
		if err != nil {
			return err
		}

		if !macListContains(i.HardwareAddr, config.Network.Interfaces) {
			info("interface %s is not in 'active' list, skipping it", ifname)
			return nil
		}
	}

	return initializeNetworkInterface(ifname)
}

var dmNameRe = regexp.MustCompile(`dm-\d+`)

func handleBlockDeviceUevent(ev *uevent.Uevent) error {
	devName := ev.Vars["DEVNAME"]

	if dmNameRe.MatchString(devName) {
		// mapper devices should not be added on "add" uevent
		// instead it tracks "readiness" using udev information and adds the block device
		// when it is really ready.
		if !validDmEvent(ev) {
			return nil
		}
		return handleMapperDeviceUevent(ev)
	}

	if ev.Action != "add" {
		return nil
	}

	devPath := "/dev/" + devName

	isPartition := ev.Vars["DEVTYPE"] == "partition"
	if isPartition {
		// if this device represents a partition inside a table (like GPT) then wait till the table is processed
		parts := strings.Split(ev.Devpath, "/")
		tablePath := "/dev/" + parts[len(parts)-2]
		waitForDeviceToProcess(tablePath)
	}

	return addBlockDevice(devPath, !isPartition, nil)
}

// handleMapperDeviceUevent handles device mapper related uevent
// if udev event is valid then it return non-empty string that contains
// new mapper device name (e.g. /dev/mapper/name)
func handleMapperDeviceUevent(ev *uevent.Uevent) error {
	devName := ev.Vars["DEVNAME"]

	major, err := strconv.Atoi(ev.Vars["MAJOR"])
	if err != nil {
		return fmt.Errorf("udev['MAJOR']: %v", err)
	}
	minor, err := strconv.Atoi(ev.Vars["MINOR"])
	if err != nil {
		return fmt.Errorf("udev['MAJOR']: %v", err)
	}
	devNo := unix.Mkdev(uint32(major), uint32(minor))

	info, err := devmapper.InfoByDevno(devNo)
	if err != nil {
		return fmt.Errorf("devmapper.Info(%s): %v", devName, err)
	}

	if err := devMapperUpdateUdevDb(major, minor); err != nil {
		return err
	}

	symlinks := make([]string, 0)
	devPath := "/dev/" + devName

	dmLinkPath := "/dev/mapper/" + info.Name // later we use /dev/mapper/NAME as a mount point
	// setup symlink /dev/mapper/NAME -> /dev/dm-NN
	if err := os.Symlink(devPath, dmLinkPath); err != nil {
		return err
	}
	symlinks = append(symlinks, dmLinkPath)

	if strings.HasPrefix(info.UUID, "LVM-") {
		// for LVM there is a special case - add /dev/VG/LG symlink
		lvmLinkPath := "/dev/" + strings.ReplaceAll(info.Name, "-", "/")
		if err := os.MkdirAll(filepath.Dir(lvmLinkPath), 0o755); err != nil {
			return err
		}
		if err := os.Symlink(devPath, lvmLinkPath); err != nil {
			return err
		}
		symlinks = append(symlinks, lvmLinkPath)
	}

	return addBlockDevice(devPath, false, symlinks)
}

// devMapperUpdateUdevDb writes Udev state to the database.
// It is an equivalent to what "db_persist" udev option does (see 'man 7 udev').
func devMapperUpdateUdevDb(major, minor int) error {
	if err := os.MkdirAll("/run/udev/data/", 0o755); err != nil {
		return err
	}

	dbFile := fmt.Sprintf("/run/udev/data/b%d:%d", major, minor)
	info("writing udev state to %s", dbFile)
	return os.WriteFile(dbFile, []byte("E:DM_UDEV_PRIMARY_SOURCE_FLAG=1\n"), 0o644)
}
