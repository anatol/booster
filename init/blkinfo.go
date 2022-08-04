package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type blkInfo struct {
	path     string
	symlinks []string // symlinks to 'path'
	format   string   // gpt, dos, ext4, btrfs, ...
	isFs     bool     // specifies if the format a mountable filesystem
	uuid     UUID
	label    string
	hwPath   string      // TODO: compute it lazy
	wwid     []string    // TODO: compute it lazy
	data     interface{} // type specific data
}

var errUnknownBlockType = fmt.Errorf("cannot detect block device type")

// readBlkInfo block device information. Returns nil if the format was not detected.
func readBlkInfo(path string) (*blkInfo, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	type probeFn func(f *os.File) *blkInfo
	// FAT signature is similar to MBR + some restrictions. Check fat before mbr.
	probes := []probeFn{probeGpt, probeFat, probeMbr, probeLuks, probeExt4, probeBtrfs, probeXfs, probeF2fs, probeLvmPv, probeMdraid, probeSwap}
	for _, fn := range probes {
		blk := fn(r)
		if blk == nil {
			continue
		}

		info("blkinfo for %s: type=%s UUID=%s LABEL=%s", path, blk.format, blk.uuid.toString(), blk.label)
		blk.path = path
		return blk, nil
	}

	return nil, errUnknownBlockType
}

const (
	gptPartitionAttributeSystem             = 1 << 0
	gptPartitionAttributeHideFromEfi        = 1 << 1
	gptPartitionAttributeLegacyBIOSBootable = 1 << 2
	gptPartitionAttributeReadOnly           = 1 << 60
	gptPartitionAttributeHidden             = 1 << 62
	gptPartitionAttributeDoNotAutomount     = 1 << 63
)

type gptPart struct {
	num        int // index of the partition int the gpt table
	typeGUID   UUID
	uuid       UUID
	name       string
	attributes uint64
}

type gptData struct {
	partitions []gptPart
}

func probeGpt(f *os.File) *blkInfo {
	const (
		// https://wiki.osdev.org/GPT
		tableHeaderOffsetSector = 1
		signatureOffset         = 0x0
		guidOffset              = 0x38
		partLocationOffset      = 0x48

		defaultSectorSize = 512
	)

	lbaSize, err := unix.IoctlGetInt(int(f.Fd()), unix.BLKSSZGET)
	if err != nil {
		debug("unable to get sector size for %s: %v", f.Name(), err)
		lbaSize = defaultSectorSize
	}
	tableHeaderOffset := tableHeaderOffsetSector * int64(lbaSize)

	signature := make([]byte, 8)
	if _, err := f.ReadAt(signature, tableHeaderOffset+signatureOffset); err != nil {
		return nil
	}
	if !bytes.Equal(signature, []byte("EFI PART")) {
		return nil
	}

	buff := make([]byte, 16)

	if _, err := f.ReadAt(buff, tableHeaderOffset+guidOffset); err != nil {
		return nil
	}
	uuid := convertGptUUID(buff)

	if _, err := f.ReadAt(buff[:16], tableHeaderOffset+partLocationOffset); err != nil {
		return nil
	}
	partLba := binary.LittleEndian.Uint64(buff[0:8])
	partNum := binary.LittleEndian.Uint32(buff[8:12])
	partSize := binary.LittleEndian.Uint32(buff[12:16])
	lbaOffset := partLba * uint64(lbaSize)

	var parts []gptPart
	buf := make([]byte, partSize)
	zeroUUID := make([]byte, 16) // zero UUID used as a marker for unused partitions
	for i := uint32(0); i < partNum; i++ {
		start := lbaOffset + uint64(i*partSize)
		if _, err := f.ReadAt(buf, int64(start)); err != nil {
			return nil
		}
		typeGUID := convertGptUUID(buf[0:0x10])
		if bytes.Equal(typeGUID, zeroUUID) {
			continue
		}
		partUUID := convertGptUUID(buf[0x10:0x20])
		attributes := binary.LittleEndian.Uint64(buf[0x30:0x38])
		name := fromUnicode16(buf[0x38:], binary.LittleEndian)
		part := gptPart{int(i), typeGUID, partUUID, name, attributes}

		parts = append(parts, part)
	}

	return &blkInfo{format: "gpt", uuid: uuid, data: gptData{parts}}
}

func convertGptUUID(d []byte) []byte {
	return []byte{
		d[3], d[2], d[1], d[0],
		d[5], d[4],
		d[7], d[6],
		d[8], d[9],
		d[10], d[11], d[12], d[13], d[14], d[15],
	}
}

func probeMbr(f *os.File) *blkInfo {
	const (
		// https://wiki.osdev.org/MBR
		bootSignatureOffset = 0x1fe
		bootSignature       = "\x55\xaa"
		diskSignatureOffset = 0x01bc
		idOffset            = 0x1b8
	)
	signature := make([]byte, 2)
	if _, err := f.ReadAt(signature, bootSignatureOffset); err != nil {
		return nil
	}
	if string(signature) != bootSignature {
		return nil
	}

	if _, err := f.ReadAt(signature, diskSignatureOffset); err != nil {
		return nil
	}
	if string(signature) != "\x00\x00" && string(signature) != "\x5a\x5a" {
		return nil
	}

	b := make([]byte, 4)
	if _, err := f.ReadAt(b, idOffset); err != nil {
		return nil
	}
	id := []byte{b[3], b[2], b[1], b[0]} // little endian
	return &blkInfo{format: "mbr", uuid: id}
}

func probeFat(f *os.File) *blkInfo {
	const (
		// https://wiki.osdev.org/FAT
		bpsSignatureOffset   = 0x0
		bpsSignature         = "\xeb\x3c\x90" // the 2nd byte might be different
		bootSignatureOffset  = 0x1fe
		bootSignature        = "\x55\xaa"
		fat16SignatureOffset = 0x026
		fat16IdOffset        = 0x027
		fat16LabelOffset     = 0x02b
		fat32SignatureOffset = 0x042
		fat32IdOffset        = 0x043
		fat32LabelOffset     = 0x047
		fatLabelLength       = 11
	)
	signature := make([]byte, 2)
	if _, err := f.ReadAt(signature, bootSignatureOffset); err != nil {
		return nil
	}
	if string(signature) != bootSignature {
		return nil
	}

	signature = make([]byte, 3)
	if _, err := f.ReadAt(signature, bpsSignatureOffset); err != nil {
		return nil
	}
	if signature[0] != []byte(bpsSignature)[0] || signature[2] != []byte(bpsSignature)[2] {
		return nil
	}

	signature = make([]byte, 1)
	if _, err := f.ReadAt(signature, fat16SignatureOffset); err != nil {
		return nil
	}
	if signature[0] == 0x28 || signature[0] == 0x29 {
		// fat16
		b := make([]byte, 4)
		if _, err := f.ReadAt(b, fat16IdOffset); err != nil {
			return nil
		}
		id := []byte{b[3], b[2], b[1], b[0]} // little endian

		label := make([]byte, fatLabelLength)
		if _, err := f.ReadAt(label, fat16LabelOffset); err != nil {
			return nil
		}
		label = bytes.TrimRight(label, " ")

		return &blkInfo{format: "fat", uuid: id, label: string(label)}
	}

	if _, err := f.ReadAt(signature, fat32SignatureOffset); err != nil {
		return nil
	}
	if signature[0] == 0x28 || signature[0] == 0x29 {
		// fat16
		b := make([]byte, 4)
		if _, err := f.ReadAt(b, fat32IdOffset); err != nil {
			return nil
		}
		id := []byte{b[3], b[2], b[1], b[0]} // little endian

		label := make([]byte, fatLabelLength)
		if _, err := f.ReadAt(label, fat32LabelOffset); err != nil {
			return nil
		}
		label = bytes.TrimRight(label, " ")

		return &blkInfo{format: "fat", uuid: id, label: string(label)}
	}

	return nil
}

func probeLuks(f *os.File) *blkInfo {
	// https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf
	// both LUKS v1 and v2 have the same magic and UUID offset
	const (
		uuidOffset    = 0xa8
		labelV2Offset = 0x18
	)
	magic := make([]byte, 6)
	if _, err := f.ReadAt(magic, 0x0); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte("LUKS\xba\xbe")) {
		return nil
	}

	buff := make([]byte, 2)
	if _, err := f.ReadAt(buff, 6); err != nil {
		return nil
	}
	version := int(buff[0])<<8 + int(buff[1])

	data := make([]byte, 40)
	if _, err := f.ReadAt(data, uuidOffset); err != nil {
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
		if _, err := f.ReadAt(buff, labelV2Offset); err != nil {
			return nil
		}
		label = fixedArrayToString(buff)
	}

	return &blkInfo{format: "luks", uuid: uuid, label: label}
}

func probeExt4(f *os.File) *blkInfo {
	const (
		// from fs/ext4/ext4.h
		extSuperblockOffset = 0x400
		extMagicOffset      = 0x38
		extUUIDOffset       = 0x68
		extLabelOffset      = 0x78
		extMagic            = "\x53\xef"
	)

	magic := make([]byte, 2)
	if _, err := f.ReadAt(magic, extSuperblockOffset+extMagicOffset); err != nil {
		return nil
	}
	if string(magic) != extMagic {
		return nil
	}
	uuid := make([]byte, 16)
	if _, err := f.ReadAt(uuid, extSuperblockOffset+extUUIDOffset); err != nil {
		return nil
	}
	label := make([]byte, 16)
	if _, err := f.ReadAt(label, extSuperblockOffset+extLabelOffset); err != nil {
		return nil
	}
	return &blkInfo{format: "ext4", isFs: true, uuid: uuid, label: fixedArrayToString(label)}
}

func probeBtrfs(f *os.File) *blkInfo {
	// https://btrfs.wiki.kernel.org/index.php/On-disk_Format
	const (
		btrfsSuperblockOffset = 0x10000
		btrfsMagicOffset      = 0x40
		btrfsUUIDOffset       = 0x11b
		btrfsLabelOffset      = 0x12b
		btrfsMagic            = "_BHRfS_M"
	)

	magic := make([]byte, 8)
	if _, err := f.ReadAt(magic, btrfsSuperblockOffset+btrfsMagicOffset); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte(btrfsMagic)) {
		return nil
	}
	uuid := make([]byte, 16)
	if _, err := f.ReadAt(uuid, btrfsSuperblockOffset+btrfsUUIDOffset); err != nil {
		return nil
	}
	label := make([]byte, 256)
	if _, err := f.ReadAt(label, btrfsSuperblockOffset+btrfsLabelOffset); err != nil {
		return nil
	}
	return &blkInfo{format: "btrfs", isFs: true, uuid: uuid, label: fixedArrayToString(label)}
}

func probeXfs(f *os.File) *blkInfo {
	// https://righteousit.wordpress.com/2018/05/21/xfs-part-1-superblock
	const (
		xfsSuperblockOffset = 0x0
		xfsMagicOffset      = 0x0
		xfsUUIDOffset       = 0x20
		xfsLabelOffset      = 0x6c
		xfsMagic            = "XFSB"
	)

	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, xfsSuperblockOffset+xfsMagicOffset); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte(xfsMagic)) {
		return nil
	}
	id := make([]byte, 16)
	if _, err := f.ReadAt(id, xfsSuperblockOffset+xfsUUIDOffset); err != nil {
		return nil
	}
	label := make([]byte, 12)
	if _, err := f.ReadAt(label, xfsSuperblockOffset+xfsLabelOffset); err != nil {
		return nil
	}
	return &blkInfo{format: "xfs", isFs: true, uuid: id, label: fixedArrayToString(label)}
}

func probeF2fs(f *os.File) *blkInfo {
	// https://github.com/torvalds/linux/blob/master/include/linux/f2fs_fs.h
	const (
		f2fsSuperblockOffset = 0x400
		f2fsMagicOffset      = 0x0
		f2fsUUIDOffset       = 0x6c
		f2fsLabelOffset      = 0x7c
		f2fsMagic            = "\x10\x20\xF5\xF2"
	)

	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, f2fsSuperblockOffset+f2fsMagicOffset); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte(f2fsMagic)) {
		return nil
	}
	uuid := make([]byte, 16)
	if _, err := f.ReadAt(uuid, f2fsSuperblockOffset+f2fsUUIDOffset); err != nil {
		return nil
	}
	buf := make([]byte, 512)
	if _, err := f.ReadAt(buf, f2fsSuperblockOffset+f2fsLabelOffset); err != nil {
		return nil
	}
	label := fromUnicode16(buf, binary.LittleEndian)
	return &blkInfo{format: "f2fs", isFs: true, uuid: uuid, label: label}
}

func probeLvmPv(f *os.File) *blkInfo {
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
	if _, err := f.ReadAt(magic, lvmHeaderOffset+lvmMagicOffset); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte(lvmMagic)) {
		return nil
	}
	if _, err := f.ReadAt(magic, lvmHeaderOffset+lvmTypeMagicOffset); err != nil {
		return nil
	}
	if !bytes.Equal(magic, []byte(lvmTypeMagic)) {
		return nil
	}

	buf := make([]byte, 4)
	if _, err := f.ReadAt(buf, lvmHeaderOffset+lvmHeaderSizeOffset); err != nil {
		return nil
	}
	headerSize := binary.LittleEndian.Uint32(buf)

	uuid := make([]byte, 32)
	if _, err := f.ReadAt(uuid, int64(lvmHeaderOffset+headerSize+lvmUUIDOffset)); err != nil {
		return nil
	}
	return &blkInfo{format: "lvm", isFs: true, uuid: uuid}
}

const (
	levelMultipath = 0xfffffffc
	levelLinear    = 0xffffffff
	levelRaid0     = 0
	levelRaid1     = 1
	levelRaid4     = 4
	levelRaid5     = 5
	levelRaid6     = 6
	levelRaid10    = 10
)

type mdraidData struct {
	level uint32
}

func probeMdraid(f *os.File) *blkInfo {
	// https://raid.wiki.kernel.org/index.php/RAID_superblock_formats
	const (
		mdraidHeaderOffset = 0x1000
		mdraidMagicOffset  = 0x0
		mdraidMagic        = 0xa92b4efc
		mdraidVersioOffset = 0x4
		mdraidUUIDOffset   = 0x10
		mdraidLevelOffset  = 0x48
	)

	magic := make([]byte, 4)
	if _, err := f.ReadAt(magic, mdraidHeaderOffset+mdraidMagicOffset); err != nil {
		return nil
	}
	if binary.LittleEndian.Uint32(magic) != mdraidMagic {
		return nil
	}

	version := make([]byte, 4)
	if _, err := f.ReadAt(version, mdraidHeaderOffset+mdraidVersioOffset); err != nil {
		return nil
	}
	if binary.LittleEndian.Uint32(version) != 1 {
		return nil
	}

	uuid := make([]byte, 16)
	if _, err := f.ReadAt(uuid, int64(mdraidHeaderOffset+mdraidUUIDOffset)); err != nil {
		return nil
	}

	levelBuff := make([]byte, 4)
	if _, err := f.ReadAt(levelBuff, int64(mdraidHeaderOffset+mdraidLevelOffset)); err != nil {
		return nil
	}
	level := binary.LittleEndian.Uint32(levelBuff)

	data := mdraidData{level: level}

	return &blkInfo{format: "mdraid", isFs: true, uuid: uuid, data: data}
}

func probeSwap(f *os.File) *blkInfo {
	// https://elixir.bootlin.com/linux/latest/source/include/linux/swap.h
	const (
		swapMagicOffset = 4086
		swapMagicLength = 10
		swapUUIDOffset  = 1036
		swapLabeOffset  = 1052
	)

	magic := make([]byte, 10)
	if _, err := f.ReadAt(magic, swapMagicOffset); err != nil {
		return nil
	}
	if string(magic) != "SWAP-SPACE" && string(magic) != "SWAPSPACE2" && string(magic) != "S1SUSPEND\x00" {
		return nil
	}

	uuid := make([]byte, 16)
	if _, err := f.ReadAt(uuid, swapUUIDOffset); err != nil {
		return nil
	}

	label := make([]byte, 16)
	if _, err := f.ReadAt(label, swapLabeOffset); err != nil {
		return nil
	}
	label = bytes.TrimRight(label, "\x00")

	return &blkInfo{format: "swap", isFs: true, uuid: uuid, label: string(label)}
}
