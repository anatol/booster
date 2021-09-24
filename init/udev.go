package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/anatol/devmapper.go"
	"github.com/anatol/uevent.go"
	"golang.org/x/sys/unix"
)

// isValidDmEvent checks whether this udev event has correct flags.
// This is similar to checks done by /usr/lib/udev/rules.d/10-dm.rules udev rules.
func isValidDmEvent(ev *uevent.Uevent) bool {
	dmCookie := ev.Vars["DM_COOKIE"]
	if dmCookie == "" {
		debug("udev event does not contain DM_COOKIE")
		return false
	}

	cookie, err := strconv.ParseUint(dmCookie, 0, 32)
	if err != nil {
		debug("unable to parse DM_COOKIE value: %s", dmCookie)
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
		debug("device mapper event: not a primary source")
		return false
	}

	// Quoting https://fossies.org/linux/LVM2/libdm/libdevmapper.h
	//
	// DM_UDEV_DISABLE_DM_RULES_FLAG is set in case we need to disable
	// basic device-mapper udev rules that create symlinks in /dev/<DM_DIR>
	if flags&DM_UDEV_DISABLE_DM_RULES_FLAG != 0 {
		debug("device mapper event: dm rules disabled")
		return false
	}

	return true
}

var udevReader io.ReadCloser

func udevListener() {
	var err error
	udevReader, err = uevent.NewReader()
	if err != nil {
		log.Fatalf("uevent: %v", err)
	}
	defer udevReader.Close()

	dec := uevent.NewDecoder(udevReader)

	for {
		ev, err := dec.Decode()
		if err == io.EOF {
			// EOF is returned if uevent reader is closed concurrently
			return
		}
		if err != nil {
			severe("uevent: %v", err)
			return
		}
		if udevDebugEnable {
			debug("udev event %+v", *ev)
		}

		if modalias, ok := ev.Vars["MODALIAS"]; ok {
			err = loadModalias(modalias)
		} else if ev.Subsystem == "block" {
			err = handleBlockDeviceUevent(ev)
		} else if ev.Subsystem == "net" {
			err = handleNetworkUevent(ev)
		}

		if err != nil {
			warning("%v", err)
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
		debug("network is disabled, skipping interface %s", ifname)
		return nil
	}

	if len(config.Network.Interfaces) > 0 {
		i, err := net.InterfaceByName(ifname)
		if err != nil {
			return err
		}

		if !macListContains(i.HardwareAddr, config.Network.Interfaces) {
			debug("interface %s is not in 'active' list, skipping it", ifname)
			return nil
		}
	}

	go func() {
		// run network init in a separate goroutine to avoid it blocking with clevis+tang unlocking
		if err := initializeNetworkInterface(ifname); err != nil {
			warning("unable to initialize network interface %s: %v\n", ifname, err)
		}
	}()

	return nil
}

var (
	dmNameRe = regexp.MustCompile(`dm-\d+`)
)

func handleBlockDeviceUevent(ev *uevent.Uevent) error {
	devName := ev.Vars["DEVNAME"]

	if dmNameRe.MatchString(devName) {
		err := handleMapperDeviceUevent(ev)
		if err == errIgnoredMapperEvent {
			err = nil
		}

		return err
	}

	if ev.Action == "add" {
		return addBlockDevice("/dev/" + devName)
	}

	return nil
}

var errIgnoredMapperEvent = fmt.Errorf("ignored device mapper event")

// handleMapperDeviceUevent handles device mapper related uevent
// if udev event is valid then it return non-empty string that contains
// new mapper device name (e.g. /dev/mapper/name)
func handleMapperDeviceUevent(ev *uevent.Uevent) error {
	if !isValidDmEvent(ev) {
		return errIgnoredMapperEvent
	}

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

	devPath := "/dev/" + devName
	dmLinkPath := "/dev/mapper/" + info.Name // later we use /dev/mapper/NAME as a mount point
	// setup symlink /dev/mapper/NAME -> /dev/dm-NN
	if err := os.Symlink(devPath, dmLinkPath); err != nil {
		return err
	}
	if err := addBlockDevice(dmLinkPath); err != nil {
		return err
	}

	if strings.HasPrefix(info.UUID, "LVM-") {
		// for LVM there is a special case - add /dev/VG/LG symlink
		lvmLinkPath := "/dev/" + strings.ReplaceAll(info.Name, "-", "/")
		if err := os.MkdirAll(path.Dir(lvmLinkPath), 0755); err != nil {
			return err
		}
		if err := os.Symlink(devPath, lvmLinkPath); err != nil {
			return err
		}
		if err := addBlockDevice(lvmLinkPath); err != nil {
			return err
		}
	}

	return nil
}

// devMapperUpdateUdevDb writes Udev state to the database.
// It is an equivalent to what "db_persist" udev option does (see 'man 7 udev').
func devMapperUpdateUdevDb(major, minor int) error {
	if err := os.MkdirAll("/run/udev/data/", 0755); err != nil {
		return err
	}

	dbFile := fmt.Sprintf("/run/udev/data/b%d:%d", major, minor)
	debug("writing udev state to %s", dbFile)
	return os.WriteFile(dbFile, []byte("E:DM_UDEV_PRIMARY_SOURCE_FLAG=1\n"), 0644)
}
