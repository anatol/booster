package tests

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

type assetGenerator struct {
	script string
	env    []string
}

var assetGenerators = map[string]assetGenerator{
	"ext4.img":                 {"ext4.sh", []string{"FS_UUID=5c92fc66-7315-408b-b652-176dc554d370", "FS_LABEL=atestlabel12"}},
	"luks1.img":                {"luks.sh", []string{"LUKS_VERSION=1", "LUKS_PASSWORD=1234", "LUKS_UUID=f0c89fd5-7e1e-4ecc-b310-8cd650bd5415", "FS_UUID=ec09a1ea-d43c-4262-b701-bf2577a9ab27"}},
	"luks2.img":                {"luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=639b8fdd-36ba-443e-be3e-e5b335935502", "FS_UUID=7bbf9363-eb42-4476-8c1c-9f1f4d091385"}},
	"luks1.clevis.tpm2.img":    {"luks.sh", []string{"LUKS_VERSION=1", "LUKS_PASSWORD=1234", "LUKS_UUID=28c2e412-ab72-4416-b224-8abd116d6f2f", "FS_UUID=2996cec0-16fd-4f1d-8bf3-6606afa77043", "CLEVIS_PIN=tpm2", "CLEVIS_CONFIG={}"}},
	"luks1.clevis.tang.img":    {"luks.sh", []string{"LUKS_VERSION=1", "LUKS_PASSWORD=1234", "LUKS_UUID=4cdaa447-ef43-42a6-bfef-89ebb0c61b05", "FS_UUID=c23aacf4-9e7e-4206-ba6c-af017934e6fa", "CLEVIS_PIN=tang", `CLEVIS_CONFIG={"url":"http://10.0.2.100:5697", "adv":"assets/tang/key.pub"}`}},
	"luks2.clevis.tpm2.img":    {"luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=3756ba2c-1505-4283-8f0b-b1d1bd7b844f", "FS_UUID=c3cc0321-fba8-42c3-ad73-d13f8826d8d7", "CLEVIS_PIN=tpm2", "CLEVIS_CONFIG={}"}},
	"luks2.clevis.tang.img":    {"luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=f2473f71-9a68-4b16-ae54-8f942b2daf50", "FS_UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a", "CLEVIS_PIN=tang", `CLEVIS_CONFIG={"url":"http://10.0.2.100:5697", "adv":"assets/tang/key.pub"}`}},
	"luks2.clevis.yubikey.img": {"luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=f2473f71-9a61-4b16-ae54-8f942b2daf52", "FS_UUID=7acb3a9e-9b50-4aa2-9965-e41ae8467d8a", "CLEVIS_PIN=yubikey", `CLEVIS_CONFIG={"slot":2}`}},
	"luks2.clevis.remote.img":  {"luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=f2473f71-9a61-4b16-ae54-8f942b2daf22", "FS_UUID=7acb3a9e-9b51-4aa2-9965-e41ae8467d8a", "CLEVIS_PIN=remote", `CLEVIS_CONFIG={"adv":"assets/remote/key.pub", "port":34551}`}},
	// camellia is a loadable module at Arch and it is a good candidate to verify loading it works correctly
	"luks2.external.module.img":   {"luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=ad575500-a9e3-4692-b1b2-eed95a6e8ce2", "FS_UUID=0118f2b1-3c4f-4eff-9663-b58447ad797c", `LUKS_PARAMS=-c camellia-xts-plain64 -s 512 -h sha512 -i 8000 --pbkdf argon2id --pbkdf-memory 4100000`}},
	// luks2.keyfile_offset.img: LUKS2 image enrolled with a keyfile that has a 512-byte random
	// preamble before the real key material.  Tests keyfile-offset= and keyfile-size= in crypttab.
	// The keyfile (preamble+key) is written to KEYFILE_OUTPUT alongside the image.
	"luks2.keyfile_offset.img": {"luks_keyfile_offset.sh", []string{
		"LUKS_UUID=c0d3f4a5-b6e7-4809-9abc-def012345678",
		"FS_UUID=d1e2f3a4-c5b6-4789-abcd-ef0123456789",
		"KEYFILE_OUTPUT=assets/luks2.keyfile_offset.key",
	}},
	// luks2.detached_header.img: LUKS2 image whose header is stored in a separate file.
	// Tests crypttab header= and rd.luks.header= detached-header unlock.
	// The header file is written to HEADER_OUTPUT alongside the image.
	"luks2.detached_header.img": {"luks_detached_header.sh", []string{
		"LUKS_UUID=cbd49694-81de-41bd-a850-0d934aff8328",
		"FS_UUID=781780d2-bf67-4a17-9ca8-fd22336c1b2e",
		"HEADER_OUTPUT=assets/luks2.detached_header.hdr",
	}},
	// luks2.detached_header.hdrdev.img: small ext4 device containing luks2.detached_header.hdr
	// at /root.hdr.  Used by TestLUKS2DetachedHeaderCmdlineOnDevice to exercise the
	// rd.luks.header=UUID=/root.hdr:UUID=<devuuid> cmdline path (headerDeviceRef != nil).
	// Depends on luks2.detached_header.img having been generated first (creates the .hdr file).
	"luks2.detached_header.hdrdev.img": {"luks_detached_header_device.sh", []string{
		"HDRDEV_UUID=e2d8f1a3-7b4c-4e9d-a1b2-3c4d5e6f7a8b",
		"HEADER_INPUT=assets/luks2.detached_header.hdr",
	}},
	// luks2.keyfile_device.img and its companion keydev are both created by a single generator run.
	"luks2.keyfile_device.img": {"luks_keyfile_device.sh", []string{
		"LUKS_UUID=7c2a39be-15d1-4b71-9f2e-5c4d1a3b8e6f",
		"FS_UUID=a3d8e2c1-4f7b-4e9c-b2a1-6d5f3c8e1a7b",
		"KEYDEV_UUID=f1e2d3c4-b5a6-4789-8abc-def123456789",
		"KEYDEV_OUTPUT=assets/luks2.keyfile_device.keydev.img",
	}},
	// luks2.btrfs_two_a.img + luks2.btrfs_two_a2.img: two LUKS2 drives with the
	// SAME passphrase forming a btrfs RAID1.  Tests passphrase cache (enter once,
	// both drives unlock automatically).
	"luks2.btrfs_two_a.img": {"luks_btrfs_two.sh", []string{
		"LUKS_UUID1=a1b2c3d4-1111-4111-8111-111111111111",
		"LUKS_UUID2=a2b2c3d4-2222-4222-8222-222222222222",
		"LUKS_PASSWORD1=1234",
		"LUKS_PASSWORD2=1234",
		"FS_UUID=a3b2c3d4-3333-4333-8333-333333333333",
		"OUTPUT2=assets/luks2.btrfs_two_a2.img",
	}},
	// luks2.btrfs_two_b.img + luks2.btrfs_two_b2.img: two LUKS2 drives with
	// DIFFERENT passphrases forming a btrfs RAID1.  Tests that booster prompts
	// for each passphrase and waits for both drives before mounting btrfs.
	"luks2.btrfs_two_b.img": {"luks_btrfs_two.sh", []string{
		"LUKS_UUID1=b1b2c3d4-1111-4111-8111-111111111112",
		"LUKS_UUID2=b2b2c3d4-2222-4222-8222-222222222223",
		"LUKS_PASSWORD1=1234",
		"LUKS_PASSWORD2=5678",
		"FS_UUID=b3b2c3d4-3333-4333-8333-333333333334",
		"OUTPUT2=assets/luks2.btrfs_two_b2.img",
	}},
	"gpt.img":                   {"gpt.sh", []string{"FS_UUID=e5404205-ac6a-4e94-bb3b-14433d0af7d1", "FS_LABEL=newpart"}},
	"gpt_4ksector.img":          {"gpt_4ksector.sh", nil},
	"lvm.img":                   {"lvm.sh", []string{"FS_UUID=74c9e30c-506f-4106-9f61-a608466ef29c", "FS_LABEL=lvmr00t"}},
	"mdraid_raid1.img":          {"mdraid_raid1.sh", []string{"FS_UUID=98b1a905-3c72-42f0-957a-6c23b303b1fd", "FS_LABEL=boosmdraid"}},
	"mdraid_raid5.img":          {"mdraid_raid5.sh", []string{"FS_UUID=e62c7dc0-5728-4571-b475-7745de2eef1e", "FS_LABEL=boosmdraid"}},
	"btrfs_raid0.img":           {"btrfs_raid0.sh", []string{"FS_UUID=5eaa0c1c-e1dc-4be7-9b03-9f1ed5a87289"}},
	"archlinux.ext4.raw":        {"archlinux_ext4.sh", nil},
	"archlinux.btrfs.raw":       {"archlinux_btrfs.sh", []string{"LUKS_PASSWORD=hello"}},
	"voidlinux.img":             {"voidlinux.sh", nil},
	"alpinelinux.img":           {"alpinelinux.sh", nil},
	"systemd-fido2.img":         {"systemd_fido2.sh", []string{"LUKS_UUID=b12cbfef-da87-429f-ac96-7dda7232c189", "FS_UUID=bb351f0d-07f2-4fe4-bc53-d6ae39fa1c23", "LUKS_PASSWORD=567", "FIDO2_PIN=1111"}}, // use yubikey-manager-qt (or fido2-token -C) to setup FIDO2 pin value to 1111
	"systemd-tpm2.img":          {"systemd_tpm2.sh", []string{"LUKS_UUID=5cbc48ce-0e78-4c6b-ac90-a8a540514b90", "FS_UUID=d8673e36-d4a3-4408-a87d-be0cb79f91a2", "LUKS_PASSWORD=567"}},
	"systemd-tpm2-withpin.img":  {"systemd_tpm2.sh", []string{"LUKS_UUID=8bb97618-7ef4-4c93-b4f7-f2cb17cf7da1", "FS_UUID=26dbbe17-9af9-4322-bb5f-c1d74a40e618", "LUKS_PASSWORD=9999", "CRYPTENROLL_TPM2_PIN=foo654"}},
	"systemd-recovery.img":      {"systemd_recovery.sh", []string{"LUKS_UUID=62020168-58b9-4095-a3d0-176403353d20", "FS_UUID=b0cfeb48-c1e2-459d-a327-4d611804ac24", "LUKS_PASSWORD=2211"}},
	"swap.raw":                  {"swap.sh", nil},
	"zfs.img":                   {"zfs.sh", nil},
	"zfs_encrypted.img":         {"zfs.sh", []string{"ZFS_PASSPHRASE=encrypted"}},

	// non-images
	"tpm2/tpm2-00.permall.pristine": {"swtpm.sh", nil},
	"tang/key.pub":                  {"tang.sh", nil},
}

func checkAsset(file string) error {
	if !strings.HasPrefix(file, "assets/") {
		fmt.Println("asset path has to start with assets/ prefix")
		return nil
	}

	name := file[7:]
	gen, ok := assetGenerators[name]
	if !ok {
		return fmt.Errorf("no generator for asset %s", file)
	}
	if exists := fileExists(file); exists {
		return nil
	}

	if testing.Verbose() {
		fmt.Printf("Generating asset %s\n", name)
	}
	env := append(gen.env, "OUTPUT="+file)
	err := shell("generators/"+gen.script, env...)
	if err != nil {
		_ = os.Remove(file)
	}
	return err
}
