package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type refFormat uint8

const (
	refPath           refFormat = iota // path to the block device, e.g. "/dev/sda".
	refGptType                         // type of gpt partition
	refGptUUID                         // uuid of the gpt partition
	refGptUUIDPartoff                  // offset against a gpt partition with uuid
	refGptLabel
	refFsUUID
	refFsLabel
	refHwPath
	refWwID
)

// The are many ways a user can specify root partition (using name, fs uuid, fs label, gpt attribute, ...).
// This struct abstracts this information and provides a convenient matching functions.
type deviceRef struct {
	format refFormat
	data   interface{}
}

type gptPartoffData struct {
	uuid   UUID
	offset int
}

func (d *deviceRef) matchesBlkInfo(blk *blkInfo) bool {
	switch d.format {
	case refPath:
		path := d.data.(string)

		if path == blk.path {
			return true
		}
		for _, sym := range blk.symlinks {
			if path == sym {
				return true
			}
		}

		return false
	case refFsUUID:
		return bytes.Equal(d.data.(UUID), blk.uuid)
	case refFsLabel:
		return d.data.(string) == blk.label
	case refHwPath:
		return blk.hwPath != "" && d.data.(string) == blk.hwPath
	case refWwID:
		for _, id := range blk.wwid {
			if d.data.(string) == id {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func calculateDevPath(parent string, partition int) string {
	name := parent
	// some drivers use 'p' prefix for the partition number. TODO: find out where it is codified.
	if strings.HasPrefix(parent, "/dev/nvme") || strings.HasPrefix(parent, "/dev/mmcblk") {
		name += "p"
	}
	name += strconv.Itoa(partition + 1) // devname partitions start with "1"
	return name
}

// checks if the reference is a gpt-specific and if yes then tries to resolve it to a device name
func (d *deviceRef) resolveGptRef(blk *blkInfo) {
	if !d.dependsOnGpt() {
		return
	}

	gpt := blk.data.(gptData)

	for _, p := range gpt.partitions {
		switch d.format {
		case refGptType:
			if bytes.Equal(d.data.(UUID), p.typeGUID) {
				partitionPath := calculateDevPath(blk.path, p.num)
				if rootAutodiscoveryMode {
					info("autodiscovery: partition %s matches root", partitionPath)
					if p.attributes&gptPartitionAttributeDoNotAutomount != 0 {
						info("autodiscovery: partition %s has 'do not mount' GPT attribute, skip it", partitionPath)
						continue
					}
					if p.attributes&gptPartitionAttributeReadOnly != 0 {
						info("autodiscovery: partition %s has 'read-only' GPT attribute", partitionPath)
						rootAutodiscoveryMountFlags |= unix.MS_RDONLY
					}
				}
				*d = deviceRef{refPath, partitionPath}
			}
		case refGptUUID:
			if bytes.Equal(d.data.(UUID), p.uuid) {
				*d = deviceRef{refPath, calculateDevPath(blk.path, p.num)}
			}
		case refGptUUIDPartoff:
			data := d.data.(gptPartoffData)
			if bytes.Equal(data.uuid, p.uuid) {
				*d = deviceRef{refPath, calculateDevPath(blk.path, p.num+data.offset)}
			}
		case refGptLabel:
			if d.data.(string) == p.name {
				*d = deviceRef{refPath, calculateDevPath(blk.path, p.num)}
			}
		}
	}

	if d.format == refWwID {
		for _, id := range blk.wwid {
			partPrefix := id + "-part"
			ref := d.data.(string)
			if strings.HasPrefix(ref, partPrefix) {
				num, err := strconv.Atoi(ref[len(partPrefix):])
				if err != nil {
					info("unable to parse partition number for %s", ref)
					return
				}
				*d = deviceRef{refPath, calculateDevPath(blk.path, num-1)}
			}
		}
	} else if d.format == refHwPath {
		if blk.hwPath != "" {
			partPrefix := blk.hwPath + "-part"
			ref := d.data.(string)
			if strings.HasPrefix(ref, partPrefix) {
				num, err := strconv.Atoi(ref[len(partPrefix):])
				if err != nil {
					info("unable to parse partition number for %s", ref)
					return
				}
				*d = deviceRef{refPath, calculateDevPath(blk.path, num-1)}
			}
		}
	}
}

func (d *deviceRef) dependsOnGpt() bool {
	return d.format == refGptType ||
		d.format == refGptUUID ||
		d.format == refGptUUIDPartoff ||
		d.format == refGptLabel ||
		// both hwpath and wwid might include the parent device reference + "-partNN" suffix
		d.format == refHwPath ||
		d.format == refWwID
}

// checks whether given partition table contains active EFI service partition
func (gpt *gptData) containsEsp() bool {
	for _, p := range gpt.partitions {
		if bytes.Equal(activeEfiEspGUID, p.uuid) {
			return true
		}
	}

	return false
}

var rootAutodiscoveryGptTypes = map[string]string{
	"amd64": "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
	"386":   "44479540-f297-41b2-9af7-d131d5f0458a",
	"arm":   "69dad710-2ce4-4e3c-b16c-21a1d49abed3",
	"arm64": "b921b045-1df0-41c3-af44-4c6f280d3fae",
	//"itanium": "993d8d3d-f80e-4225-855a-9daf8ed7ea97",
}

func parseDeviceRef(param string) (*deviceRef, error) {
	if strings.HasPrefix(param, "UUID=") {
		uuid := strings.TrimPrefix(param, "UUID=")

		u, err := parseUUID(stripQuotes(uuid))
		if err != nil {
			return nil, fmt.Errorf("unable to parse UUID parameter %s: %v", param, err)
		}
		return &deviceRef{refFsUUID, u}, nil
	}
	if strings.HasPrefix(param, "/dev/disk/by-uuid/") {
		uuid := strings.TrimPrefix(param, "/dev/disk/by-uuid/")
		u, err := parseUUID(stripQuotes(uuid))
		if err != nil {
			return nil, fmt.Errorf("unable to parse UUID parameter %s: %v", param, err)
		}
		return &deviceRef{refFsUUID, u}, nil
	}
	if strings.HasPrefix(param, "LABEL=") {
		label := strings.TrimPrefix(param, "LABEL=")
		return &deviceRef{refFsLabel, label}, nil
	}
	if strings.HasPrefix(param, "/dev/disk/by-label/") {
		label := strings.TrimPrefix(param, "/dev/disk/by-label/")
		return &deviceRef{refFsLabel, label}, nil
	}
	if strings.HasPrefix(param, "PARTUUID=") {
		uuid := strings.TrimPrefix(param, "PARTUUID=")

		if idx := strings.Index(uuid, "/PARTNROFF="); idx != -1 {
			param := uuid[idx+11:]
			uuid = uuid[:idx]
			partnoff, err := strconv.Atoi(param)
			if err != nil {
				return nil, fmt.Errorf("unable to parse PARTNROFF= value %s", param)
			}
			u, err := parseUUID(stripQuotes(uuid))
			if err != nil {
				return nil, fmt.Errorf("unable to parse UUID parameter %s: %v", param, err)
			}
			return &deviceRef{refGptUUIDPartoff, gptPartoffData{u, partnoff}}, nil
		} else {
			u, err := parseUUID(stripQuotes(uuid))
			if err != nil {
				return nil, fmt.Errorf("unable to parse UUID parameter %s: %v", param, err)
			}
			return &deviceRef{refGptUUID, u}, nil
		}
	}
	if strings.HasPrefix(param, "/dev/disk/by-partuuid/") {
		uuid := strings.TrimPrefix(param, "/dev/disk/by-partuuid/")
		u, err := parseUUID(stripQuotes(uuid))
		if err != nil {
			return nil, fmt.Errorf("unable to parse UUID parameter %s: %v", param, err)
		}
		return &deviceRef{refGptUUID, u}, nil
	}
	if strings.HasPrefix(param, "PARTLABEL=") {
		label := strings.TrimPrefix(param, "PARTLABEL=")
		return &deviceRef{refGptLabel, label}, nil
	}
	if strings.HasPrefix(param, "/dev/disk/by-partlabel/") {
		label := strings.TrimPrefix(param, "/dev/disk/by-partlabel/")
		return &deviceRef{refGptLabel, label}, nil
	}
	if strings.HasPrefix(param, "HWPATH=") {
		path := strings.TrimPrefix(param, "HWPATH=")
		return &deviceRef{refHwPath, path}, nil
	}
	if strings.HasPrefix(param, "/dev/disk/by-path/") {
		path := strings.TrimPrefix(param, "/dev/disk/by-path/")
		return &deviceRef{refHwPath, path}, nil
	}
	if strings.HasPrefix(param, "WWID=") {
		id := strings.TrimPrefix(param, "WWID=")
		return &deviceRef{refWwID, id}, nil
	}
	if strings.HasPrefix(param, "/dev/disk/by-id/") {
		id := strings.TrimPrefix(param, "/dev/disk/by-id/")
		return &deviceRef{refWwID, id}, nil
	}
	if strings.HasPrefix(param, "/dev/") {
		return &deviceRef{refPath, param}, nil
	}

	return nil, fmt.Errorf("unable to parse the device reference")
}
