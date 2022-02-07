package main

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/yookoala/realpath"
)

func hwPath(device string) (string, error) {
	name := path.Base(device)

	sysfs, err := sysfsPathForBlock(name)
	if err != nil {
		return "", err
	}

	p := ""
	parent := sysfs
	for parent != "/" {
		subsystem, err := sysfsSubsystem(parent)
		if err != nil {
			return "", err
		}

		sysname := path.Base(parent)

		skipped := false
		switch subsystem {
		case "pci":
			p = prependPath("pci-"+sysname, p)
			parent, err = sysfsSkipSubsystem(parent, "pci")
			if err != nil {
				return "", err
			}
			skipped = true
		case "scsi":
			data, err := sysfsAttributeValue(parent, "uevent")
			if err != nil {
				return "", err
			}
			props := parseProperties(data)
			if props["DEVTYPE"] != "scsi_device" {
				break
			}

			var host, bus, target, lun int
			num, err := fmt.Sscanf(sysname, "%d:%d:%d:%d", &host, &bus, &target, &lun)
			if err != nil {
				return "", err
			}
			if num != 4 {
				break
			}

			ataRE, err := regexp.Compile(`^.*/ata\d+/`)
			if err != nil {
				return "", err
			}
			if ata := ataRE.FindString(parent); ata != "" {
				base := path.Base(ata)
				portNo, err := sysfsAttributeValue(ata+"/ata_port/"+base, "port_no")
				if err != nil {
					return "", err
				}
				if bus != 0 {
					/* Devices behind port multiplier have a bus != 0 */
					p = prependPath(fmt.Sprintf("ata-%s.%d.0", portNo, bus), p)
				} else {
					/* Master/slave are distinguished by target id */
					p = prependPath(fmt.Sprintf("ata-%s.%d", portNo, target), p)
				}
			} else {
				p = prependPath("scsi-"+sysname, p)
			}
		case "nvme":
			nsid, err := sysfsAttributeValue(sysfs, "nsid")
			if err != nil {
				return "", err
			}
			p = prependPath("nvme-"+nsid, p)
			parent, err = sysfsSkipSubsystem(parent, "nvme")
			if err != nil {
				return "", err
			}
			skipped = true
		case "usb":
			port := sysname[strings.IndexByte(sysname, '-')+1:]
			p = prependPath("usb-0:"+port, p)
			parent, err = sysfsSkipSubsystem(parent, "usb")
			if err != nil {
				return "", err
			}
			skipped = true
		}
		if !skipped {
			parent = path.Dir(parent)
		}
	}
	return p, nil
}

func prependPath(prefix, hwPath string) string {
	if hwPath != "" {
		return prefix + "-" + hwPath
	}
	return prefix
}

func sysfsSkipSubsystem(p, subsystem string) (string, error) {
	for p != "/" {
		s, err := sysfsSubsystem(p)
		if err != nil {
			return "", err
		}
		if s != subsystem {
			break
		}
		p = path.Dir(p)
	}

	return p, nil
}

func sysfsSubsystem(sysPath string) (string, error) {
	l, err := os.Readlink(path.Join(sysPath, "subsystem"))
	if os.IsNotExist(err) {
		return "", nil
	}
	return path.Base(l), err
}

func sysfsAttributeValue(sysPath, attr string) (string, error) {
	for sysPath != "/" {
		data, err := os.ReadFile(path.Join(sysPath, attr))
		sysPath = path.Dir(sysPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		return string(bytes.TrimSpace(data)), nil
	}
	return "", os.ErrNotExist
}

func sysfsSubsystems(sysPath string) (map[string]bool, error) {
	result := make(map[string]bool)
	for sysPath != "/" {
		l, err := sysfsSubsystem(sysPath)
		if err != nil {
			return nil, err
		}
		sysPath = path.Dir(sysPath)
		if l == "" {
			continue
		}
		result[path.Base(l)] = true
	}
	return result, nil
}

func sysfsPathForBlock(dev string) (string, error) {
	return realpath.Realpath("/sys/block/" + dev)
}
