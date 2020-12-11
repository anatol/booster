package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

var errNotFound = errors.New("not found")

func blkid(path string) (string, string, error) {
	r, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer r.Close()

	type probeFn func(r io.ReaderAt) (string, string, error)
	probes := []probeFn{probeGpt, probeMbr, probeLuks, probeExt4, probeBtrfs, probeXfs}
	for _, fn := range probes {
		format, uuid, err := fn(r)
		if err == nil {
			return format, uuid, nil
		}
	}

	return "", "", fmt.Errorf("cannot detect block type")
}

func probeGpt(r io.ReaderAt) (string, string, error) {
	const (
		// https://wiki.osdev.org/GPT
		tableHeaderOffset = 0x200
		signatureOffset   = 0x0
		guidOffset        = 0x38
	)
	signature := make([]byte, 8)
	if _, err := r.ReadAt(signature, tableHeaderOffset+signatureOffset); err != nil {
		return "", "", err
	}
	if !bytes.Equal(signature, []byte("EFI PART")) {
		return "", "", errNotFound
	}

	guid := make([]byte, 16)
	if _, err := r.ReadAt(guid, tableHeaderOffset+guidOffset); err != nil {
		return "", "", err
	}
	return "gpt", fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		guid[3], guid[2], guid[1], guid[0],
		guid[5], guid[4],
		guid[7], guid[6],
		guid[8], guid[9],
		guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]), nil
}

func probeMbr(r io.ReaderAt) (string, string, error) {
	const (
		// https://wiki.osdev.org/GPT
		bootSignatureOffset = 0x1fe
		bootSignature       = "\x55\xaa"
		diskSignatureOffset = 0x01bc
		idOffset            = 0x1b8
	)
	signature := make([]byte, 2)
	if _, err := r.ReadAt(signature, bootSignatureOffset); err != nil {
		return "", "", err
	}
	if string(signature) != bootSignature {
		return "", "", errNotFound
	}

	if _, err := r.ReadAt(signature, diskSignatureOffset); err != nil {
		return "", "", err
	}
	if string(signature) != "\x00\x00" && string(signature) != "\x5a\x5a" {
		return "", "", errNotFound
	}

	idBytes := make([]byte, 4)
	if _, err := r.ReadAt(idBytes, idOffset); err != nil {
		return "", "", err
	}
	id := binary.LittleEndian.Uint32(idBytes)
	return "mbr", fmt.Sprintf("%08x", id), nil
}

func probeLuks(r io.ReaderAt) (string, string, error) {
	// https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf
	// both LUKS v1 and v2 have the same magic and UUID offset
	const (
		uuidOffset = 0xa8
	)
	magic := make([]byte, 6)
	if _, err := r.ReadAt(magic, 0x0); err != nil {
		return "", "", err
	}
	if !bytes.Equal(magic, []byte("LUKS\xba\xbe")) {
		return "", "", errNotFound
	}
	uuid := make([]byte, 40)
	if _, err := r.ReadAt(uuid, uuidOffset); err != nil {
		return "", "", err
	}
	return "luks", string(uuid[:bytes.IndexByte(uuid, 0)]), nil
}

func probeExt4(r io.ReaderAt) (string, string, error) {
	const (
		// from fs/ext4/ext4.h
		extSuperblockOffset = 0x400
		extMagicOffset      = 0x38
		extUUIDOffset       = 0x68
		extMagic            = "\x53\xef"
	)

	magic := make([]byte, 2)
	if _, err := r.ReadAt(magic, extSuperblockOffset+extMagicOffset); err != nil {
		return "", "", err
	}
	if string(magic) != extMagic {
		return "", "", errNotFound
	}
	uuid := make([]byte, 16)
	if _, err := r.ReadAt(uuid, extSuperblockOffset+extUUIDOffset); err != nil {
		return "", "", err
	}
	return "ext4", fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5],
		uuid[6], uuid[7],
		uuid[8], uuid[9],
		uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]), nil
}

func probeBtrfs(r io.ReaderAt) (string, string, error) {
	// https://btrfs.wiki.kernel.org/index.php/On-disk_Format
	const (
		btrfsSuperblockOffset = 0x10000
		btrfsMagicOffset      = 0x40
		btrfsUUIDOffset       = 0x11b
		btrfsMagic            = "_BHRfS_M"
	)

	magic := make([]byte, 8)
	if _, err := r.ReadAt(magic, btrfsSuperblockOffset+btrfsMagicOffset); err != nil {
		return "", "", err
	}
	if !bytes.Equal(magic, []byte(btrfsMagic)) {
		return "", "", errNotFound
	}
	uuid := make([]byte, 16)
	if _, err := r.ReadAt(uuid, btrfsSuperblockOffset+btrfsUUIDOffset); err != nil {
		return "", "", err
	}
	return "btrfs", fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5],
		uuid[6], uuid[7],
		uuid[8], uuid[9],
		uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]), nil
}

func probeXfs(r io.ReaderAt) (string, string, error) {
	// https://righteousit.wordpress.com/2018/05/21/xfs-part-1-superblock
	const (
		xfsSuperblockOffset = 0x0
		xfsMagicOffset      = 0x0
		xfsUUIDOffset       = 0x20
		xfsMagic            = "XFSB"
	)

	magic := make([]byte, 4)
	if _, err := r.ReadAt(magic, xfsSuperblockOffset+xfsMagicOffset); err != nil {
		return "", "", err
	}
	if !bytes.Equal(magic, []byte(xfsMagic)) {
		return "", "", errNotFound
	}
	uuid := make([]byte, 16)
	if _, err := r.ReadAt(uuid, xfsSuperblockOffset+xfsUUIDOffset); err != nil {
		return "", "", err
	}
	return "xfs", fmt.Sprintf(
		"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5],
		uuid[6], uuid[7],
		uuid[8], uuid[9],
		uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]), nil
}
