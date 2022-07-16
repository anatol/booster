package main

import (
	"encoding/hex"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func checkFs(t *testing.T, name, fstype, uuidStr, label string, size int64, script string, data interface{}) {
	if !fileExists("assets") {
		require.NoError(t, os.Mkdir("assets", 0o755))
	}

	asset := "assets/" + name
	if !fileExists(asset) {
		script = strings.ReplaceAll(script, "$OUTPUT", asset)
		script = strings.ReplaceAll(script, "$UUID", uuidStr)
		script = strings.ReplaceAll(script, "$LABEL", label)

		f, err := os.Create(asset)
		require.NoError(t, err)
		_ = f.Close()
		require.NoError(t, os.Truncate(asset, size*1024*1024))

		if err := shell(script); err != nil {
			_ = os.Remove(asset)
			require.NoError(t, err)
		}
	}

	info, err := readBlkInfo(asset)
	require.NoError(t, err)
	require.Equal(t, fstype, info.format)
	var uuid UUID
	if fstype == "mbr" || fstype == "fat" || fstype == "mdraid" {
		uuid, err = hex.DecodeString(uuidStr)
	} else if fstype == "lvm" {
		uuid = []byte(strings.ReplaceAll(uuidStr, "-", ""))
	} else {
		uuid, err = parseUUID(uuidStr)
	}
	require.NoError(t, err)
	require.Equal(t, uuid, info.uuid)
	require.Equal(t, label, info.label)
	require.Equal(t, data, info.data)
}

func shell(script string, env ...string) error {
	sh := exec.Command("bash", "-o", "errexit", "-c", script)
	sh.Env = append(os.Environ(), env...)

	if testing.Verbose() {
		sh.Stdout = os.Stdout
		sh.Stderr = os.Stderr
	}
	return sh.Run()
}

func fileExists(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}

func TestBlkInfo(t *testing.T) {
	checkFs(t, "fat", "fat", "2a341c62", "FATLBL", 10, "mkfs.vfat -F32 -n $LABEL -i $UUID $OUTPUT", nil)
	checkFs(t, "ext4", "ext4", "717be5ba-d42d-4aaa-b846-8a23cc7471b0", "extlabel", 10, "mkfs.ext4 -L $LABEL -U $UUID $OUTPUT", nil)
	checkFs(t, "btrfs", "btrfs", "1884e1eb-186f-4b1b-af11-45ea80da8e3c", "btrfs111", 200, "mkfs.btrfs -L $LABEL -U $UUID $OUTPUT", nil)
	checkFs(t, "xfs", "xfs", "ee7cad9a-0202-4c00-a320-418a9276d70d", "xfs44", 100, "mkfs.xfs -L $LABEL -m uuid=$UUID $OUTPUT", nil)
	checkFs(t, "f2fs", "f2fs", "6af49bb0-0bd8-4b82-a1d1-286dfe37d729", "test1привет", 100, "mkfs.f2fs -l $LABEL -U $UUID $OUTPUT", nil)
	checkFs(t, "luks1", "luks", "6faf1e59-9999-4da4-97f9-c815e7353777", "", 100, "cryptsetup luksFormat -q --type=luks1 --iter-time=1 --uuid=$UUID $OUTPUT <<< 'tetspassphrase'", nil)
	checkFs(t, "luks2", "luks", "51df71ed-8e4a-4a7a-956d-b782706a52d1", "bazz", 10, "cryptsetup luksFormat -q --type=luks2 --iter-time=1 --uuid=$UUID --label=$LABEL $OUTPUT <<< 'tetspassphrase'", nil)
	checkFs(t, "swap", "swap", "5f3d4e16-3fa4-42fe-a64d-2dc6685bcc7e", "eightly", 10, "mkswap --uuid $UUID --label $LABEL $OUTPUT", nil)

	typeGUID := []byte{203, 52, 81, 177, 53, 176, 64, 249, 160, 234, 133, 102, 237, 5, 222, 109}
	sector1UUID := []byte{83, 69, 58, 7, 155, 238, 67, 151, 166, 20, 158, 143, 163, 135, 10, 114}
	sector2UUID := []byte{62, 161, 141, 185, 105, 31, 69, 94, 164, 13, 32, 212, 38, 177, 150, 95}
	checkFs(t, "gpt", "gpt", "c26fcabe-8010-4bff-a066-8c73e76dbb32", "", 10, "gdisk $OUTPUT <<< 'o\ny\nx\ng\n$UUID\nm\nn\n\n\n+2M\ncb3451b1-35b0-40f9-a0ea-8566ed05de6d\nc\nсектор1\nx\nc\n53453a07-9bee-4397-a614-9e8fa3870a72\nm\nn\n\n\n+2M\ncb3451b1-35b0-40f9-a0ea-8566ed05de6d\nc\n2\nhello\nx\nc\n2\n3ea18db9-691f-455e-a40d-20d426b1965f\na\n2\n60\n\nw\ny\n'",
		gptData{partitions: []gptPart{{
			num:      0,
			typeGUID: typeGUID,
			uuid:     sector1UUID,
			name:     "сектор1",
		}, {
			num:        1,
			typeGUID:   typeGUID,
			uuid:       sector2UUID,
			name:       "hello",
			attributes: gptPartitionAttributeReadOnly,
		}}})
	checkFs(t, "mbr", "mbr", "2beab180", "", 1, "fdisk $OUTPUT <<< 'o\nx\ni\n0x$UUID\nr\nw\n'", nil)

	createLVM := `
trap 'sudo losetup -d $lodev' EXIT

lodev=$(sudo losetup -f --show $OUTPUT)
sudo pvcreate -u $UUID --norestorefile $lodev`
	checkFs(t, "lvm", "lvm", "Iy3Z8K-49rL-KK4W-NE9C-FZe5-5qWL-lCg9hj", "", 10, createLVM, nil)

	createMdraid := `
trap 'sudo mdadm --stop /dev/md/BlkInfoTest; sudo losetup -d $lodev' EXIT

lodev=$(sudo losetup -f --show $OUTPUT)
sudo mdadm --create --force --verbose --level=0 --raid-devices=1 --uuid=9ee4ce4c:c179141f:33b05b33:980ece9a /dev/md/BlkInfoTest $lodev`
	checkFs(t, "mdraid", "mdraid", "9ee4ce4cc179141f33b05b33980ece9a", "", 10, createMdraid, mdraidData{levelRaid0})
}
