package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

type blkInfo struct {
	format string // gpt, dos, ext4, btrfs, ...
	uuid   string
	label  string
}

// readBlkInfo block device information. Returns nil if the format was not detected.
func readBlkInfo(path string) (*blkInfo, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	type probeFn func(r io.ReaderAt) *blkInfo
	probes := []probeFn{probeGpt, probeMbr, probeLuks, probeExt4, probeBtrfs, probeXfs}
	for _, fn := range probes {
		info := fn(r)
		if info != nil {
			debug("blkinfo for %s: type=%s UUID=%s LABEL=%s", path, info.format, info.uuid, info.label)
			return info, nil
		}
	}

	return nil, fmt.Errorf("cannot detect block device type")
}

func probeGpt(r io.ReaderAt) *blkInfo {
	const (
		// https://wiki.osdev.org/GPT
		tableHeaderOffset = 0x200
		signatureOffset   = 0x0
		guidOffset        = 0x38
	)
	signature := make([]byte, 8)
	if _, err := r.ReadAt(signature, tableHeaderOffset+signatureOffset); err != nil {
		return nil
	}
	if !bytes.Equal(signature, []byte("EFI PART")) {
		return nil
	}

	guid := make([]byte, 16)
	if _, err := r.ReadAt(guid, tableHeaderOffset+guidOffset); err != nil {
		return nil
	}
	uuid := fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		guid[3], guid[2], guid[1], guid[0],
		guid[5], guid[4],
		guid[7], guid[6],
		guid[8], guid[9],
		guid[10], guid[11], guid[12], guid[13], guid[14], guid[15])
	return &blkInfo{"gpt", uuid, ""}
}

func probeMbr(r io.ReaderAt) *blkInfo {
	const (
		// https://wiki.osdev.org/GPT
		bootSignatureOffset = 0x1fe
		bootSignature       = "\x55\xaa"
		diskSignatureOffset = 0x01bc
		idOffset            = 0x1b8
	)
	signature := make([]byte, 2)
	if _, err := r.ReadAt(signature, bootSignatureOffset); err != nil {
		return nil
	}
	if string(signature) != bootSignature {
		return nil
	}

	if _, err := r.ReadAt(signature, diskSignatureOffset); err != nil {
		return nil
	}
	if string(signature) != "\x00\x00" && string(signature) != "\x5a\x5a" {
		return nil
	}

	idBytes := make([]byte, 4)
	if _, err := r.ReadAt(idBytes, idOffset); err != nil {
		return nil
	}
	id := binary.LittleEndian.Uint32(idBytes)
	return &blkInfo{"mbr", fmt.Sprintf("%08x", id), ""}
}

func probeLuks(r io.ReaderAt) *blkInfo {
	// https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf
	// both LUKS v1 and v2 have the same magic and UUID offset
	const (
		uuidOffset    = 0xa8
		labelV2Offset = 0x18
	)
	magic := make([]byte, 6)
	if _, err := r.ReadAt(magic, 0x0); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte("LUKS\xba\xbe")) {
		return nil
	}

	buff := make([]byte, 2)
	if _, err := r.ReadAt(buff, 6); err != nil {
		return nil
	}
	version := int(buff[0])<<8 + int(buff[1])

	uuid := make([]byte, 40)
	if _, err := r.ReadAt(uuid, uuidOffset); err != nil {
		return nil
	}

	var label string
	if version == 2 {
		// Only LUKS 2 has label support
		buff := make([]byte, 48)
		if _, err := r.ReadAt(buff, labelV2Offset); err != nil {
			return nil
		}
		label = fixedArrayToString(buff)
	}

	return &blkInfo{"luks", fixedArrayToString(uuid), label}
}

func probeExt4(r io.ReaderAt) *blkInfo {
	const (
		// from fs/ext4/ext4.h
		extSuperblockOffset = 0x400
		extMagicOffset      = 0x38
		extUUIDOffset       = 0x68
		extLabelOffset      = 0x78
		extMagic            = "\x53\xef"
	)

	magic := make([]byte, 2)
	if _, err := r.ReadAt(magic, extSuperblockOffset+extMagicOffset); err != nil {
		return nil
	}
	if string(magic) != extMagic {
		return nil
	}
	id := make([]byte, 16)
	if _, err := r.ReadAt(id, extSuperblockOffset+extUUIDOffset); err != nil {
		return nil
	}
	label := make([]byte, 16)
	if _, err := r.ReadAt(label, extSuperblockOffset+extLabelOffset); err != nil {
		return nil
	}
	uuid := fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		id[0], id[1], id[2], id[3],
		id[4], id[5],
		id[6], id[7],
		id[8], id[9],
		id[10], id[11], id[12], id[13], id[14], id[15])
	return &blkInfo{"ext4", uuid, fixedArrayToString(label)}
}

func probeBtrfs(r io.ReaderAt) *blkInfo {
	// https://btrfs.wiki.kernel.org/index.php/On-disk_Format
	const (
		btrfsSuperblockOffset = 0x10000
		btrfsMagicOffset      = 0x40
		btrfsUUIDOffset       = 0x11b
		btrfsLabelOffset      = 0x12b
		btrfsMagic            = "_BHRfS_M"
	)

	magic := make([]byte, 8)
	if _, err := r.ReadAt(magic, btrfsSuperblockOffset+btrfsMagicOffset); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte(btrfsMagic)) {
		return nil
	}
	id := make([]byte, 16)
	if _, err := r.ReadAt(id, btrfsSuperblockOffset+btrfsUUIDOffset); err != nil {
		return nil
	}
	label := make([]byte, 256)
	if _, err := r.ReadAt(label, btrfsSuperblockOffset+btrfsLabelOffset); err != nil {
		return nil
	}
	uuid := fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		id[0], id[1], id[2], id[3],
		id[4], id[5],
		id[6], id[7],
		id[8], id[9],
		id[10], id[11], id[12], id[13], id[14], id[15])
	return &blkInfo{"btrfs", uuid, fixedArrayToString(label)}
}

func probeXfs(r io.ReaderAt) *blkInfo {
	// https://righteousit.wordpress.com/2018/05/21/xfs-part-1-superblock
	const (
		xfsSuperblockOffset = 0x0
		xfsMagicOffset      = 0x0
		xfsUUIDOffset       = 0x20
		xfsLabelOffset      = 0x6c
		xfsMagic            = "XFSB"
	)

	magic := make([]byte, 4)
	if _, err := r.ReadAt(magic, xfsSuperblockOffset+xfsMagicOffset); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte(xfsMagic)) {
		return nil
	}
	id := make([]byte, 16)
	if _, err := r.ReadAt(id, xfsSuperblockOffset+xfsUUIDOffset); err != nil {
		return nil
	}
	label := make([]byte, 12)
	if _, err := r.ReadAt(label, xfsSuperblockOffset+xfsLabelOffset); err != nil {
		return nil
	}
	uuid := fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		id[0], id[1], id[2], id[3],
		id[4], id[5],
		id[6], id[7],
		id[8], id[9],
		id[10], id[11], id[12], id[13], id[14], id[15])
	return &blkInfo{"xfs", uuid, fixedArrayToString(label)}
}
