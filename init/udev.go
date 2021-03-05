package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/s-urbaniak/uevent"
	"golang.org/x/sys/unix"
)

// isValidDmEvent checks whether this udev event has correct flags.
// This is similar to checks done by /usr/lib/udev/rules.d/10-dm.rules udev rules.
func isValidDmEvent(dmCookie string) bool {
	if dmCookie == "" {
		return false
	}

	cookie, err := strconv.ParseUint(dmCookie, 0, 32)
	if err != nil {
		return false // invalid cookie
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
		return false
	}

	// Quoting https://fossies.org/linux/LVM2/libdm/libdevmapper.h
	//
	// DM_UDEV_DISABLE_DM_RULES_FLAG is set in case we need to disable
	// basic device-mapper udev rules that create symlinks in /dev/<DM_DIR>
	if flags&DM_UDEV_DISABLE_DM_RULES_FLAG != 0 {
		return false
	}

	return true
}

// deviceNo returns major/minor device number for the given device file
func deviceNo(filename string) (uint32, uint32, error) {
	stat, err := os.Stat(filename)
	if err != nil {
		return 0, 0, err
	}
	sys, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("Cannot determine the device major and minor numbers for %s", filename)
	}
	return unix.Major(sys.Rdev), unix.Minor(sys.Rdev), nil

}

// writeUdevDb writes Udev state to the database.
// It is an equivalent to what "db_persist" udev option does (see 'man 7 udev').
func writeUdevDb(dmName string) error {
	major, minor, err := deviceNo("/dev/mapper/" + dmName)
	if err != nil {
		return err
	}

	if err := os.MkdirAll("/run/udev/data/", 0755); err != nil {
		return err
	}

	dbFile := fmt.Sprintf("/run/udev/data/b%d:%d", major, minor)
	debug("writing udev state to %s", dbFile)
	return os.WriteFile(dbFile, []byte("E:DM_UDEV_PRIMARY_SOURCE_FLAG=1\n"), 0644)
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
		ev, err := dec.Decode() // TODO: there is a race condition with closing udevReader that causes panic in bufio.go
		if err != nil {
			log.Fatalf("uevent: %v", err)
		}
		debug("udev event %+v", ev)

		if modalias, ok := ev.Vars["MODALIAS"]; ok {
			if err := loadModalias(modalias); err != nil {
				debug("unable to load modalias %s: %v", modalias, err)
				continue
			}
		} else if devname, ok := ev.Vars["DEVNAME"]; ok {
			if ev.Subsystem != "block" {
				continue
			}

			if strings.HasPrefix(devname, "dm-") {
				cookie := ev.Vars["DM_COOKIE"]
				if !isValidDmEvent(cookie) {
					debug("skipping device mapper device %s because of DM_COOKIE: %s", devname, cookie)
					continue
				}
			} else if ev.Action != "add" {
				continue
			}

			go func() {
				// run luks log-in init in a separate goroutine as it is a slow operation
				if err := devAdd(ev.Devpath, devname); err != nil {
					fmt.Printf("devAdd: %v\n", err)
				}
			}()
		} else if ev.Subsystem == "net" && ev.Action == "add" {
			if config.Network == nil {
				continue
			}
			ifname := ev.Vars["INTERFACE"]
			go func() {
				// run network init in a separate goroutine to avoid it blocking with clevis+tang unlocking
				if err := initializeNetworkInterface(ifname); err != nil {
					fmt.Printf("unable to initialize network interface %s: %v\n", ifname, err)
				}
			}()
		}
	}
}

func writeResolvConf(servers []net.IP) error {
	var resolvConf bytes.Buffer
	for _, ip := range servers {
		resolvConf.WriteString("nameserver ")
		resolvConf.WriteString(ip.String())
		resolvConf.WriteByte('\n')
	}
	resolvConf.WriteString("search .\n")

	return os.WriteFile("/etc/resolv.conf", resolvConf.Bytes(), 0644)
}
