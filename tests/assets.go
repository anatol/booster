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
	"gpt.img":                  {"gpt.sh", []string{"FS_UUID=e5404205-ac6a-4e94-bb3b-14433d0af7d1", "FS_LABEL=newpart"}},
	"gpt_4ksector.img":         {"gpt_4ksector.sh", nil},
	"lvm.img":                  {"lvm.sh", []string{"FS_UUID=74c9e30c-506f-4106-9f61-a608466ef29c", "FS_LABEL=lvmr00t"}},
	"mdraid_raid1.img":         {"mdraid_raid1.sh", []string{"FS_UUID=98b1a905-3c72-42f0-957a-6c23b303b1fd", "FS_LABEL=boosmdraid"}},
	"mdraid_raid5.img":         {"mdraid_raid5.sh", []string{"FS_UUID=e62c7dc0-5728-4571-b475-7745de2eef1e", "FS_LABEL=boosmdraid"}},
	"archlinux.ext4.raw":       {"archlinux_ext4.sh", nil},
	"archlinux.btrfs.raw":      {"archlinux_btrfs.sh", []string{"LUKS_PASSWORD=hello"}},
	"voidlinux.img":            {"voidlinux.sh", nil},
	"alpinelinux.img":          {"alpinelinux.sh", nil},
	"systemd-fido2.img":        {"systemd_fido2.sh", []string{"LUKS_UUID=b12cbfef-da87-429f-ac96-7dda7232c189", "FS_UUID=bb351f0d-07f2-4fe4-bc53-d6ae39fa1c23", "LUKS_PASSWORD=567", "FIDO2_PIN=1111"}}, // use yubikey-manager-qt (or fido2-token -C) to setup FIDO2 pin value to 1111
	"systemd-tpm2.img":         {"systemd_tpm2.sh", []string{"LUKS_UUID=5cbc48ce-0e78-4c6b-ac90-a8a540514b90", "FS_UUID=d8673e36-d4a3-4408-a87d-be0cb79f91a2", "LUKS_PASSWORD=567"}},
	"systemd-recovery.img":     {"systemd_recovery.sh", []string{"LUKS_UUID=62020168-58b9-4095-a3d0-176403353d20", "FS_UUID=b0cfeb48-c1e2-459d-a327-4d611804ac24", "LUKS_PASSWORD=2211"}},
	"swap.raw":                 {"swap.sh", nil},
	"zfs.img":                  {"zfs.sh", nil},

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
