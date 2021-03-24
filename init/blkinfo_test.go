package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"testing"
)

func blkInfoTest(format, cmd, label string, deviceSizeMb int64) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		f, err := os.CreateTemp("", "blk")
		if err != nil {
			log.Fatal(err)
		}
		fname := f.Name()
		defer os.Remove(fname)

		size := deviceSizeMb * 1024 * 1024

		if err := f.Truncate(size); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		var uuid []byte
		var uuidStr string

		if format != "mbr" {
			uuidStr = "0d7b09a9-8928-4451-8037-21f7a329fed8"
			uuid, err = parseUUID(uuidStr)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			uuidStr = "2beab180"
			uuid, err = hex.DecodeString(uuidStr)
			if err != nil {
				t.Fatal(err)
			}
		}
		command := fmt.Sprintf(cmd, label, uuidStr, fname)
		cmd := exec.Command("/bin/sh", "-c", command)
		if testing.Verbose() {
			fmt.Printf("running: %s\n", command)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		if err := cmd.Run(); err != nil {
			t.Fatalf("running '%s': %v", command, err)
		}

		info, err := readBlkInfo(fname)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if info.format != format {
			t.Errorf("blkinfo(%s) format = %v, want %v", fname, info.format, format)
		}
		if !bytes.Equal(info.uuid, uuid) {
			t.Errorf("blkinfo(%s) uuid = %v, want %v", format, info.uuid.toString(), uuid)
		}
		if info.label != label {
			t.Errorf("blkinfo(%s) label = %v, want %v", format, info.label, label)
		}

	}
}

func TestBlkInfo(t *testing.T) {
	t.Run("ext4", blkInfoTest("ext4", "mkfs.ext4 -L %[1]s -U %[2]s %[3]s", "labff3233", 10))
	t.Run("btrfs", blkInfoTest("btrfs", "mkfs.btrfs -L %[1]s -U %[2]s %[3]s", "gf43rfsfd3rf23sdfsdfs", 130))
	t.Run("xfs", blkInfoTest("xfs", "mkfs.xfs -L %[1]s -m uuid=%[2]s %[3]s", "alabel11", 100))
	t.Run("f2fs", blkInfoTest("f2fs", "mkfs.f2fs -l %[1]s -U %[2]s %[3]s", "alabel11", 100))
	t.Run("luks1", blkInfoTest("luks", "cryptsetup luksFormat -q --type=luks1 --iter-time=1 --uuid=%[2]s %[3]s <<< 'tetspassphrase'", "", 10)) // luks1 does not support labels
	t.Run("luks2", blkInfoTest("luks", "cryptsetup luksFormat -q --type=luks2 --iter-time=1 --uuid=%[2]s --label=%[1]s %[3]s <<< 'tetspassphrase'", "fdskfskdljfs", 10))
	t.Run("gpt", blkInfoTest("gpt", "fdisk %[3]s <<< 'g\nx\ni\n%[2]s\nr\nw\n'", "", 10))
	t.Run("mbr", blkInfoTest("mbr", "fdisk %[3]s <<< 'o\nx\ni\n0x%[2]s\nr\nw\n'", "", 10))
}
