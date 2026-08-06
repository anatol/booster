package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"
)

// Registration and readiness for multi-device btrfs volumes.  A volume becomes
// mountable only once the kernel has been told about every member, which is what
// the scan below does; the wait then blocks until the module reports the set
// complete.

/* this should be 4k */
type btrfsIoctlVolArgs struct {
	fs   int64
	name [4088]uint8
}

const (
	BTRFS_IOCTL_MAGIC            uintptr = 0x94
	BTRFS_IOCTL_NR_SCAN_DEV      uintptr = 4
	BTRFS_IOCTL_NR_DEVICES_READY uintptr = 39
)

// openBtrfsControl loads the btrfs module (the control node only exists once the
// module is in) and opens /dev/btrfs-control together with the ioctl argument
// struct pointing at dev.
func openBtrfsControl(dev string) (*os.File, *btrfsIoctlVolArgs, error) {
	wg := loadModules("btrfs")
	wg.Wait()

	controlFile, err := os.OpenFile("/dev/btrfs-control", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}

	args := &btrfsIoctlVolArgs{}
	copy(args.name[:], dev)
	return controlFile, args, nil
}

// btrfsScanDevice registers a btrfs member with the kernel module, as `btrfs
// device scan` and udev's btrfs rules do on a regular boot.  A multi-device
// volume becomes ready only once every member has been scanned, and the
// readiness ioctl below scans just the device it is asked about — so without
// this, only members that happen to match root= are ever registered.
func btrfsScanDevice(dev string) error {
	controlFile, args, err := openBtrfsControl(dev)
	if err != nil {
		return err
	}
	defer controlFile.Close()

	BTRFS_IOC_SCAN_DEV := iow(BTRFS_IOCTL_MAGIC, BTRFS_IOCTL_NR_SCAN_DEV, unsafe.Sizeof(*args))
	return ioctl(controlFile.Fd(), BTRFS_IOC_SCAN_DEV, uintptr(unsafe.Pointer(args)))
}

// Wait until all devices of a multiple-device filesystem are scanned and registered within the kernel module
func waitForBtrfsDevicesReady(dev string) error {
	controlFile, args, err := openBtrfsControl(dev)
	if err != nil {
		return err
	}
	defer controlFile.Close()

	/* these three should all be uintptr */
	ioctlFd := controlFile.Fd()
	BTRFS_IOC_DEVICES_READY := ior(BTRFS_IOCTL_MAGIC, BTRFS_IOCTL_NR_DEVICES_READY, unsafe.Sizeof(*args))
	ptrBtrfsIoctlVolArgs := uintptr(unsafe.Pointer(args))

	/* prepare to wait */
	const btrfsTimeout time.Duration = 10 * time.Minute
	timeNow := time.Now()
	timeStart := timeNow
	timeEnd := timeStart.Add(btrfsTimeout)

	/* actually wait */
	for timeNow.Before(timeEnd) {
		ready, err := ioctlCheckZero(ioctlFd, BTRFS_IOC_DEVICES_READY, ptrBtrfsIoctlVolArgs)
		if err != nil {
			return err
		}
		timeElapsed := timeNow.Sub(timeStart)
		if ready {
			if timeElapsed > time.Second {
				info("Multi-device btrfs at %v became fully assembled", dev)
			} else {
				debug("Btrfs at %v is ready without wait, this should only happen for single-device btrfs or the last one in multi-device btrfs", dev)
			}
			return nil
		} else if timeElapsed < time.Second {
			info("Start waiting for multi-device btrfs at %v to become fullly assembled, timeout 10 minutes", dev)
		}
		info("Waiting for multi-device btrfs at %v to become fullly assembled, waited %v", dev, timeElapsed)
		time.Sleep(time.Second)
		timeNow = time.Now()
	}
	return fmt.Errorf("Timeout waiting for multi-device btrfs at %v to become fully assembled", dev)
}
