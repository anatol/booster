package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/moby/sys/mountinfo"
)

type RootMountInfo struct {
	seenDevices []string // Track the ones we've seen to avoid infinite recursion

	rootMountInfo *mountinfo.Info
	parentDevices []*BlockDeviceInfo
}

type BlockDeviceInfo struct {
	name    string
	major   uint32
	minor   uint32
	devtype string
}

func (o *RootMountInfo) GetSysfsPath(majmin string) string {
	return "/sys/dev/block/" + majmin
}

func (o *RootMountInfo) GetRootDevice() error {
	mnts, err := mountinfo.GetMounts(mountinfo.SingleEntryFilter("/"))
	if err != nil {
		return err
	} else if len(mnts) == 0 {
		return fmt.Errorf("GetMounts returned no results")
	}

	o.rootMountInfo = mnts[0]

	return err
}

func (o *RootMountInfo) GetBlockDeviceInfo(devPath string) (*BlockDeviceInfo, error) {
	devNum, err := os.ReadFile(devPath + "/dev")
	if err != nil {
		return nil, err
	}

	var devMajor, devMinor uint32
	num, err := fmt.Sscanf(string(devNum), "%d:%d", &devMajor, &devMinor)
	if err != nil {
		return nil, err
	}
	if num != 2 {
		return nil, fmt.Errorf("GetBlockDeviceInfo: Failed parsing %s/dev", devPath)
	}

	devInfo := &BlockDeviceInfo{}
	devInfo.name = filepath.Base(devPath)
	devInfo.major = devMajor
	devInfo.minor = devMinor
	devInfo.devtype = devInfo.GetDeviceType(devPath)

	debug("GetBlockDeviceInfo: name=%s, dev=%d:%d, devtype=%s", devInfo.name, devInfo.major, devInfo.minor, devInfo.devtype)

	return devInfo, nil
}

func (o *RootMountInfo) GetDeviceParents(devPath string) ([]*BlockDeviceInfo, error) {
	var devs []*BlockDeviceInfo
	var files []os.DirEntry

	devPath = o.realpath(devPath)

	if slices.Contains(o.seenDevices, filepath.Base(devPath)) {
		return devs, nil
	}

	devInfo, err := o.GetBlockDeviceInfo(devPath)
	if err != nil {
		return nil, err
	}
	o.seenDevices = append(o.seenDevices, devInfo.name)

	devs = append(devs, devInfo)

	slavesPath := devPath + "/slaves"
	if files, err = os.ReadDir(slavesPath); err != nil {
		return devs, nil
	}

	for _, file := range files {
		parents, err := o.GetDeviceParents(slavesPath + "/" + file.Name())
		if err != nil {
			debug("GetDeviceParents: ignoring inner error: %v", err)
			continue
		}
		devs = append(devs, parents...)
	}

	return devs, nil
}

func (o *RootMountInfo) realpath(path string) string {
	if resolvedPath, err := filepath.EvalSymlinks(path); err == nil {
		if absPath, err := filepath.Abs(resolvedPath); err == nil {
			return absPath
		}
	}
	return path
}

func (o *BlockDeviceInfo) GetDeviceType(devPath string) string {
	var devType []byte
	var err error

	// If this is a device-mapper device
	// just return the lowercased UUID prefix
	// The ones we're interested in will be "CRYPT-" or "LVM-"
	devType, err = os.ReadFile(devPath + "/dm/uuid")
	if err == nil {
		if prefix, _, ok := bytes.Cut(devType, []byte("-")); ok {
			return strings.ToLower(string(prefix))
		}
	}

	// Is it a partition?
	// Partitions will be at /sys/.../sda/sda1 or /sys/.../mmcblk0/mmcblk0p1
	parentName := filepath.Base(filepath.Dir(devPath))
	devName := filepath.Base(devPath)

	// Strip parentName from devName
	// parentName: sda
	// devName: sda2 -> 2
	if suffix, ok := strings.CutPrefix(devName, parentName); ok {
		// If devName was mmcblk0p1, we need to also strip the leading p
		suffix = strings.TrimPrefix(suffix, "p")
		debug("GetDeviceType: parent=%s, dev=%s", parentName, devName)

		if _, err := strconv.Atoi(suffix); err == nil {
			return "part"
		}
	}

	return "disk"
}

func GetRootMountInfo() (*RootMountInfo, error) {
	root := &RootMountInfo{}
	if err := root.GetRootDevice(); err != nil {
		return nil, err
	}

	majminRoot := fmt.Sprintf("%d:%d", root.rootMountInfo.Major, root.rootMountInfo.Minor)
	rootPath := root.GetSysfsPath(majminRoot)

	devs, err := root.GetDeviceParents(rootPath)
	if err != nil {
		return nil, err
	}
	root.parentDevices = devs

	return root, nil
}
