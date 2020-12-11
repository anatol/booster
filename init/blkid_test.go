package main

import (
	"testing"
)

func TestBlkid(t *testing.T) {
	type testcase struct{ file, fstype, uuid string }
	tests := []testcase{
		{"testdata/gpt_header.bin", "gpt", "6d7bcc78-33ac-462a-998a-1fa7c9daf661"},
		{"testdata/luks_header.bin", "luks", "0d7b09a9-8928-4451-8037-21f7a329fed8"},
		{"testdata/ext4_superblock.bin", "ext4", "1fa04de7-30a9-4183-93e9-1b0061567121"},
		{"testdata/btrfs_superblock.bin", "btrfs", "7f95b123-5fbf-4b84-af9d-daf2a541c527"},
		{"testdata/xfs_superblock.bin", "xfs", "35d49b10-058b-44be-ba53-6e3d5c07da35"},
		{"testdata/mbr_header.bin", "mbr", "88acdfc5"},
	}

	for _, tc := range tests {
		fstype, uuid, err := blkid(tc.file)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if fstype != tc.fstype {
			t.Errorf("blkid(%s) = %v, want %v", tc.file, fstype, tc.fstype)
		}
		if uuid != tc.uuid {
			t.Errorf("blkid(%s) = %v, want %v", tc.file, uuid, tc.uuid)
		}
	}
}
