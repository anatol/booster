package main

import (
	"bytes"
	"fmt"
	"slices"
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
	data   any
}

type gptPartoffData struct {
	uuid   UUID
	offset int
}

func (blk *blkInfo) matchesRef(d *deviceRef) bool {
	if d == nil {
		return false
	}

	switch d.format {
	case refPath:
		path := d.data.(string)

		if path == blk.path {
			return true
		}
		return slices.Contains(blk.symlinks, path)
	case refFsUUID:
		return bytes.Equal(d.data.(UUID), blk.uuid)
	case refFsLabel:
		return d.data.(string) == blk.label
	case refHwPath:
		return blk.hwPath != "" && d.data.(string) == blk.hwPath
	case refWwID:
		return slices.Contains(blk.wwid, d.data.(string))
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
func (blk *blkInfo) resolveGptRef(d *deviceRef) {
	if d == nil {
		return
	}

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
	if after, ok := strings.CutPrefix(param, "UUID="); ok {
		uuid := after

		u, err := parseUUID(uuid)
		if err != nil {
			return nil, fmt.Errorf("unable to parse UUID parameter %s: %v", param, err)
		}
		return &deviceRef{refFsUUID, u}, nil
	}
	if after, ok := strings.CutPrefix(param, "/dev/disk/by-uuid/"); ok {
		uuid := after
		u, err := parseUUID(uuid)
		if err != nil {
			return nil, fmt.Errorf("unable to parse UUID parameter %s: %v", param, err)
		}
		return &deviceRef{refFsUUID, u}, nil
	}
	if after, ok := strings.CutPrefix(param, "LABEL="); ok {
		label := after
		return &deviceRef{refFsLabel, label}, nil
	}
	if after, ok := strings.CutPrefix(param, "/dev/disk/by-label/"); ok {
		label := after
		return &deviceRef{refFsLabel, label}, nil
	}
	if after, ok := strings.CutPrefix(param, "PARTUUID="); ok {
		uuid := after

		if idx := strings.Index(uuid, "/PARTNROFF="); idx != -1 {
			param := uuid[idx+11:]
			uuid = uuid[:idx]
			partnoff, err := strconv.Atoi(param)
			if err != nil {
				return nil, fmt.Errorf("unable to parse PARTNROFF= value %s", param)
			}
			u, err := parseUUID(uuid)
			if err != nil {
				return nil, fmt.Errorf("unable to parse UUID parameter %s: %v", param, err)
			}
			return &deviceRef{refGptUUIDPartoff, gptPartoffData{u, partnoff}}, nil
		} else {
			u, err := parseUUID(uuid)
			if err != nil {
				return nil, fmt.Errorf("unable to parse UUID parameter %s: %v", param, err)
			}
			return &deviceRef{refGptUUID, u}, nil
		}
	}
	if after, ok := strings.CutPrefix(param, "/dev/disk/by-partuuid/"); ok {
		uuid := after
		u, err := parseUUID(uuid)
		if err != nil {
			return nil, fmt.Errorf("unable to parse UUID parameter %s: %v", param, err)
		}
		return &deviceRef{refGptUUID, u}, nil
	}
	if after, ok := strings.CutPrefix(param, "PARTLABEL="); ok {
		label := after
		return &deviceRef{refGptLabel, label}, nil
	}
	if after, ok := strings.CutPrefix(param, "/dev/disk/by-partlabel/"); ok {
		label := after
		return &deviceRef{refGptLabel, label}, nil
	}
	if after, ok := strings.CutPrefix(param, "HWPATH="); ok {
		path := after
		return &deviceRef{refHwPath, path}, nil
	}
	if after, ok := strings.CutPrefix(param, "/dev/disk/by-path/"); ok {
		path := after
		return &deviceRef{refHwPath, path}, nil
	}
	if after, ok := strings.CutPrefix(param, "WWID="); ok {
		id := after
		return &deviceRef{refWwID, id}, nil
	}
	if after, ok := strings.CutPrefix(param, "/dev/disk/by-id/"); ok {
		id := after
		return &deviceRef{refWwID, id}, nil
	}
	if strings.HasPrefix(param, "/dev/") {
		return &deviceRef{refPath, param}, nil
	}

	return nil, fmt.Errorf("unable to parse the device reference")
}
