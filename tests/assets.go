package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	"luks2.external.module.img": {"luks.sh", []string{"LUKS_VERSION=2", "LUKS_PASSWORD=1234", "LUKS_UUID=ad575500-a9e3-4692-b1b2-eed95a6e8ce2", "FS_UUID=0118f2b1-3c4f-4eff-9663-b58447ad797c", `LUKS_PARAMS=-c camellia-xts-plain64 -s 512 -h sha512 -i 8000 --pbkdf argon2id --pbkdf-memory 4100000`}},
	// luks2.detached_header.img: LUKS2 image whose header is stored in a separate file.
	// Tests rd.luks.header= detached-header unlock via kernel cmdline.
	// The header file is written to HEADER_OUTPUT alongside the image.
	"luks2.detached_header.img": {"luks_detached_header.sh", []string{
		"LUKS_UUID=cbd49694-81de-41bd-a850-0d934aff8328",
		"FS_UUID=781780d2-bf67-4a17-9ca8-fd22336c1b2e",
		"HEADER_OUTPUT=assets/luks2.detached_header.hdr",
	}},
	// luks2.keyfile_device.img and its companion keydev are both created by a single generator run.
	"luks2.keyfile_device.img": {"luks_keyfile_device.sh", []string{
		"LUKS_UUID=7c2a39be-15d1-4b71-9f2e-5c4d1a3b8e6f",
		"FS_UUID=a3d8e2c1-4f7b-4e9c-b2a1-6d5f3c8e1a7b",
		"KEYDEV_UUID=f1e2d3c4-b5a6-4789-8abc-def123456789",
		"KEYDEV_OUTPUT=assets/luks2.keyfile_device.keydev.img",
	}},
	// luks2.detached_header.hdrdev.img: small ext4 device containing luks2.detached_header.hdr
	// at /root.hdr.  Used by TestLUKS2DetachedHeaderCmdlineOnDevice to exercise the
	// rd.luks.header=UUID=/root.hdr:UUID=<devuuid> cmdline path (headerDeviceRef != nil).
	// Depends on luks2.detached_header.img having been generated first (creates the .hdr file).
	"luks2.detached_header.hdrdev.img": {"luks_detached_header_device.sh", []string{
		"HDRDEV_UUID=e2d8f1a3-7b4c-4e9d-a1b2-3c4d5e6f7a8b",
		"HEADER_INPUT=assets/luks2.detached_header.hdr",
	}},
	"gpt.img":             {"gpt.sh", []string{"FS_UUID=e5404205-ac6a-4e94-bb3b-14433d0af7d1", "FS_LABEL=newpart"}},
	"gpt_4ksector.img":    {"gpt_4ksector.sh", nil},
	"lvm.img":             {"lvm.sh", []string{"FS_UUID=74c9e30c-506f-4106-9f61-a608466ef29c", "FS_LABEL=lvmr00t"}},
	"mdraid_raid1.img":    {"mdraid_raid1.sh", []string{"FS_UUID=98b1a905-3c72-42f0-957a-6c23b303b1fd", "FS_LABEL=boosmdraid"}},
	"mdraid_raid5.img":    {"mdraid_raid5.sh", []string{"FS_UUID=e62c7dc0-5728-4571-b475-7745de2eef1e", "FS_LABEL=boosmdraid"}},
	"btrfs_raid0.img":     {"btrfs_raid0.sh", []string{"FS_UUID=5eaa0c1c-e1dc-4be7-9b03-9f1ed5a87289"}},
	"archlinux.ext4.raw":  {"archlinux_ext4.sh", nil},
	"archlinux.btrfs.raw": {"archlinux_btrfs.sh", []string{"LUKS_PASSWORD=hello"}},
	"voidlinux.img":       {"voidlinux.sh", nil},
	"alpinelinux.img":     {"alpinelinux.sh", nil},
	// systemd-fido2-nodev.img: LUKS2 with a fake systemd-fido2 token injected
	// directly into the header (random credential — never matches a real device).
	// Used to test the token-timeout fallback path without physical FIDO2 hardware.
	"systemd-fido2-nodev.img": {"luks_fido2_nodev.sh", []string{
		"LUKS_UUID=a6cdb03e-ad77-440a-8a93-28ad97de3b00",
		"FS_UUID=0cb4665f-65a0-4acc-9710-05163af16f19",
		"LUKS_PASSWORD=567",
	}},
	"systemd-tpm2.img":         {"systemd_tpm2.sh", []string{"LUKS_UUID=5cbc48ce-0e78-4c6b-ac90-a8a540514b90", "FS_UUID=d8673e36-d4a3-4408-a87d-be0cb79f91a2", "LUKS_PASSWORD=567"}},
	"systemd-tpm2-withpin.img": {"systemd_tpm2.sh", []string{"LUKS_UUID=8bb97618-7ef4-4c93-b4f7-f2cb17cf7da1", "FS_UUID=26dbbe17-9af9-4322-bb5f-c1d74a40e618", "LUKS_PASSWORD=9999", "CRYPTENROLL_TPM2_PIN=foo654"}},
	// systemd-tpm2-pin-passphrase.img: LUKS2 with both a TPM2+PIN token and a
	// passphrase slot.  Used to test empty-PIN skip (falls through to passphrase)
	// and PIN exhaustion (3 wrong tries → passphrase fallback).
	"systemd-tpm2-pin-passphrase.img": {"systemd_tpm2.sh", []string{"LUKS_UUID=f3e4d5c6-b7a8-4901-c234-d5e6f7a8b9c0", "FS_UUID=a4b5c6d7-e8f9-4012-d345-e6f7a8b9c0d1", "LUKS_PASSWORD=567", "CRYPTENROLL_TPM2_PIN=foo654", "KEEP_PASSPHRASE_SLOT=1"}},
	// systemd-tpm2-nopcr-pin.img: TPM2+PIN token enrolled without PCR binding.
	// Exercises the policyPCRSession path where len(pcrs)==0 so only PolicyPassword
	// is applied (no PolicyPCR call).  Regression test for the bug where an empty
	// PCR selection still mutated the policy digest, causing auth failure.
	"systemd-tpm2-nopcr-pin.img": {"systemd_tpm2.sh", []string{"LUKS_UUID=d9ef7bf3-b4f8-4271-9f3c-df63d457fcc6", "FS_UUID=6abcf123-4182-452b-9c87-a769dc344e3b", "LUKS_PASSWORD=567", "CRYPTENROLL_TPM2_PIN=foo654", "CRYPTENROLL_TPM2_PCRS="}},
	"systemd-tpm2-srk.img":       {"systemd_tpm2.sh", []string{"LUKS_UUID=c09debc6-6a06-4317-94f5-0916bb9ea1c8", "FS_UUID=5a6daa83-ea51-47dd-a38b-2b66d5cc8428", "LUKS_PASSWORD=567"}},
	// systemd-tpm2-legacy-pin.img: v252-254 format token — tpm2_srk present but
	// no tpm2_salt, PIN auth via SHA256(pin) without PBKDF2.  Generated with
	// raw tpm2-tools rather than systemd-cryptenroll to be independent of the
	// installed systemd version.  Requires tpm2-tools; test skips if absent.
	"systemd-tpm2-legacy-pin.img": {"systemd_tpm2_legacy_pin.sh", []string{"LUKS_UUID=1e8a6049-18a7-48df-a4f6-edc80650e19f", "FS_UUID=b0d4b4c2-cef2-43b5-a063-e3379a49f79c", "LUKS_PASSWORD=567", "CRYPTENROLL_TPM2_PIN=foo654"}},
	"systemd-recovery.img":        {"systemd_recovery.sh", []string{"LUKS_UUID=62020168-58b9-4095-a3d0-176403353d20", "FS_UUID=b0cfeb48-c1e2-459d-a327-4d611804ac24", "LUKS_PASSWORD=2211"}},
	// luks2.shared_pass.img: GPT disk with two LUKS2 partitions sharing the same
	// passphrase.  Partition 1 has no inner filesystem; partition 2 has ext4.
	// Used by TestPassphraseCache to verify single-prompt unlock (issue #306).
	"luks2.shared_pass.img": {"luks_shared_pass.sh", []string{
		"LUKS_UUID1=a4c8e2f6-1b3d-4678-9ace-0f2468ace024",
		"LUKS_UUID2=b5d9f307-2c4e-4789-ab1f-1e3579bdf135",
		"FS_UUID=c6ea04b8-3d5f-4890-bc2e-2f468ace0246",
		"LUKS_PASSWORD=1234",
	}},
	// luks2.btrfs_raid1.img: GPT disk with two LUKS2 partitions each wrapping a
	// btrfs RAID1 member, both sharing the same passphrase.
	// Used by TestLuksBtrfsRaid1 to verify single-prompt unlock of LUKS-on-btrfs.
	"luks2.btrfs_raid1.img": {"luks_btrfs_raid1.sh", []string{
		"LUKS_UUID1=d7fb15c9-4e6a-4901-cd3f-3a579bdf1357",
		"LUKS_UUID2=e8ac26da-5f7b-4012-de40-4b68ace02468",
		"FS_UUID=f9bd37eb-607c-4123-ef51-5c79bdf13579",
		"LUKS_PASSWORD=1234",
	}},
	"swap.raw":          {"swap.sh", nil},
	"zfs.img":           {"zfs.sh", nil},
	"zfs_encrypted.img": {"zfs.sh", []string{"ZFS_PASSPHRASE=encrypted"}},

	// non-images
	"tpm2/tpm2-00.permall.pristine": {"swtpm.sh", nil},
	"tang/key.pub":                  {"tang.sh", nil},
}

var (
	assetGenMu    sync.Mutex
	assetGenLocks = make(map[string]*sync.Mutex)
)

func lockAssetGeneration(name string) func() {
	assetGenMu.Lock()
	mu := assetGenLocks[name]
	if mu == nil {
		mu = &sync.Mutex{}
		assetGenLocks[name] = mu
	}
	assetGenMu.Unlock()

	mu.Lock()
	return mu.Unlock
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
	unlock := lockAssetGeneration(name)
	defer unlock()

	if exists := fileExists(file); exists {
		enforceReadOnlyAssetOutputs(file, gen.env)
		return nil
	}

	if testing.Verbose() {
		fmt.Printf("Generating asset %s\n", name)
	}
	env := append(gen.env, "OUTPUT="+file)
	err := shell("generators/"+gen.script, env...)
	if err != nil {
		_ = os.Remove(file)
		return err
	}
	enforceReadOnlyAssetOutputs(file, env)
	return nil
}

func isReadOnlyAssetFile(path string) bool {
	if !strings.HasPrefix(filepath.Clean(path), "assets/") {
		return false
	}
	switch filepath.Ext(path) {
	case ".img", ".raw", ".iso":
		return true
	default:
		return false
	}
}

func enforceReadOnlyAssetOutputs(output string, env []string) {
	_ = setReadOnlyIfAssetImage(output)
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		if strings.HasSuffix(key, "_OUTPUT") {
			_ = setReadOnlyIfAssetImage(value)
		}
	}
}

func setReadOnlyIfAssetImage(path string) error {
	if !isReadOnlyAssetFile(path) {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return os.Chmod(path, info.Mode()&^0o222)
}
