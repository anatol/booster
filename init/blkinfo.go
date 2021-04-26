package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"unicode/utf16"
)

type blkInfo struct {
	format string // gpt, dos, ext4, btrfs, ...
	isFs   bool   // specifies if the format a mountable filesystem
	uuid   UUID
	label  string
}

var errUnknownBlockType = fmt.Errorf("cannot detect block device type")

// readBlkInfo block device information. Returns nil if the format was not detected.
func readBlkInfo(path string) (*blkInfo, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	type probeFn func(r io.ReaderAt) *blkInfo
	probes := []probeFn{probeGpt, probeMbr, probeLuks, probeExt4, probeBtrfs, probeXfs, probeF2fs, probeLvmPv}
	for _, fn := range probes {
		info := fn(r)
		if info != nil {
			debug("blkinfo for %s: type=%s UUID=%s LABEL=%s", path, info.format, info.uuid.toString(), info.label)
			return info, nil
		}
	}

	return nil, errUnknownBlockType
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

	d := make([]byte, 16)
	if _, err := r.ReadAt(d, tableHeaderOffset+guidOffset); err != nil {
		return nil
	}
	uuid := []byte{d[3], d[2], d[1], d[0],
		d[5], d[4],
		d[7], d[6],
		d[8], d[9],
		d[10], d[11], d[12], d[13], d[14], d[15]}
	return &blkInfo{"gpt", false, uuid, ""}
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

	b := make([]byte, 4)
	if _, err := r.ReadAt(b, idOffset); err != nil {
		return nil
	}
	id := []byte{b[3], b[2], b[1], b[0]} // little endian
	return &blkInfo{"mbr", false, id, ""}
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

	data := make([]byte, 40)
	if _, err := r.ReadAt(data, uuidOffset); err != nil {
		return nil
	}
	uuidStr := string(data[:uuidLen])
	uuid, err := parseUUID(uuidStr)
	if err != nil {
		warning("unable to parse luks uuid %s: %v", uuidStr, err)
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

	return &blkInfo{"luks", false, uuid, label}
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
	uuid := make([]byte, 16)
	if _, err := r.ReadAt(uuid, extSuperblockOffset+extUUIDOffset); err != nil {
		return nil
	}
	label := make([]byte, 16)
	if _, err := r.ReadAt(label, extSuperblockOffset+extLabelOffset); err != nil {
		return nil
	}
	return &blkInfo{"ext4", true, uuid, fixedArrayToString(label)}
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
	uuid := make([]byte, 16)
	if _, err := r.ReadAt(uuid, btrfsSuperblockOffset+btrfsUUIDOffset); err != nil {
		return nil
	}
	label := make([]byte, 256)
	if _, err := r.ReadAt(label, btrfsSuperblockOffset+btrfsLabelOffset); err != nil {
		return nil
	}
	return &blkInfo{"btrfs", true, uuid, fixedArrayToString(label)}
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
	return &blkInfo{"xfs", true, id, fixedArrayToString(label)}
}

func probeF2fs(r io.ReaderAt) *blkInfo {
	// https://github.com/torvalds/linux/blob/master/include/linux/f2fs_fs.h
	const (
		f2fsSuperblockOffset = 0x400
		f2fsMagicOffset      = 0x0
		f2fsUUIDOffset       = 0x6c
		f2fsLabelOffset      = 0x7c
		f2fsMagic            = "\x10\x20\xF5\xF2"
	)

	magic := make([]byte, 4)
	if _, err := r.ReadAt(magic, f2fsSuperblockOffset+f2fsMagicOffset); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte(f2fsMagic)) {
		return nil
	}
	uuid := make([]byte, 16)
	if _, err := r.ReadAt(uuid, f2fsSuperblockOffset+f2fsUUIDOffset); err != nil {
		return nil
	}
	buf := make([]byte, 512)
	if _, err := r.ReadAt(buf, f2fsSuperblockOffset+f2fsLabelOffset); err != nil {
		return nil
	}
	runes := make([]uint16, 256)
	err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &runes)
	if err != nil {
		return nil
	}
	for i, r := range runes {
		// find the first NUL symbol and trim the array to it
		if r == 0 {
			runes = runes[:i]
			break
		}
	}
	label := string(utf16.Decode(runes))
	return &blkInfo{"f2fs", true, uuid, label}
}

func probeLvmPv(r io.ReaderAt) *blkInfo {
	// https://github.com/libyal/libvslvm/blob/main/documentation/Logical%20Volume%20Manager%20(LVM)%20format.asciidoc
	const (
		lvmHeaderOffset     = 0x200
		lvmMagicOffset      = 0x0
		lvmMagic            = "LABELONE"
		lvmTypeMagicOffset  = 0x18
		lvmTypeMagic        = "LVM2 001"
		lvmHeaderSizeOffset = 0x14
		lvmUUIDOffset       = 0x0 // offset wrt volume header
	)

	magic := make([]byte, 8)
	if _, err := r.ReadAt(magic, lvmHeaderOffset+lvmMagicOffset); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte(lvmMagic)) {
		return nil
	}
	if _, err := r.ReadAt(magic, lvmHeaderOffset+lvmTypeMagicOffset); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte(lvmTypeMagic)) {
		return nil
	}

	buf := make([]byte, 4)
	if _, err := r.ReadAt(buf, lvmHeaderOffset+lvmHeaderSizeOffset); err != nil {
		return nil
	}
	headerSize := binary.LittleEndian.Uint32(buf)

	uuid := make([]byte, 32)
	if _, err := r.ReadAt(uuid, int64(lvmHeaderOffset+headerSize+lvmUUIDOffset)); err != nil {
		return nil
	}
	return &blkInfo{"lvm", true, uuid, ""}
}
