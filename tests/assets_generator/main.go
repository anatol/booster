package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/anatol/vmtest"
	"golang.org/x/crypto/ssh"
)

var verbose = flag.Bool("verbose", false, "output debug info to console")

const assetsDir = "../assets"
const initBinaryPath = "init"
const rootfsBuilderBinaryPath = "rootfs_builder"

var imagesToBuild = map[string][]string{
	"ext4": {"-fsUuid", "5c92fc66-7315-408b-b652-176dc554d370", "-fsLabel", "atestlabel12"},

	"luks1": {"-luksVersion", "1", "-luksPassword", "1234", "-luksUuid", "f0c89fd5-7e1e-4ecc-b310-8cd650bd5415", "-fsUuid", "ec09a1ea-d43c-4262-b701-bf2577a9ab27"},
	"luks2": {"-luksVersion", "2", "-luksPassword", "1234", "-luksUuid", "639b8fdd-36ba-443e-be3e-e5b335935502", "-fsUuid", "7bbf9363-eb42-4476-8c1c-9f1f4d091385"},

	"luks1.clevis.tpm2": {"-luksVersion", "1", "-luksPassword", "1234", "-luksUuid", "28c2e412-ab72-4416-b224-8abd116d6f2f", "-fsUuid", "2996cec0-16fd-4f1d-8bf3-6606afa77043", "-luksClevisPin", "tpm2", "-luksClevisConfig", "{}"},
	"luks1.clevis.tang": {"-luksVersion", "1", "-luksPassword", "1234", "-luksUuid", "4cdaa447-ef43-42a6-bfef-89ebb0c61b05", "-fsUuid", "c23aacf4-9e7e-4206-ba6c-af017934e6fa", "-luksClevisPin", "tang", "-luksClevisConfig", `{"url":"http://10.0.2.100:5697", "adv":"../assets/tang/adv.jwk"}`},
	"luks2.clevis.tpm2": {"-luksVersion", "2", "-luksPassword", "1234", "-luksUuid", "3756ba2c-1505-4283-8f0b-b1d1bd7b844f", "-fsUuid", "c3cc0321-fba8-42c3-ad73-d13f8826d8d7", "-luksClevisPin", "tpm2", "-luksClevisConfig", "{}"},
	"luks2.clevis.tang": {"-luksVersion", "2", "-luksPassword", "1234", "-luksUuid", "f2473f71-9a68-4b16-ae54-8f942b2daf50", "-fsUuid", "7acb3a9e-9b50-4aa2-9965-e41ae8467d8a", "-luksClevisPin", "tang", "-luksClevisConfig", `{"url":"http://10.0.2.100:5697", "adv":"../assets/tang/adv.jwk"}`},
}

// generate tang keys
func assetsTangInit() error {
	tangDir := assetsDir + "/tang"
	_ = os.Mkdir(tangDir, 0755)
	tangKeysCmd := exec.Command("/usr/lib/tangd-keygen", tangDir, "sig", "exc")
	if *verbose {
		tangKeysCmd.Stdout = os.Stdout
		tangKeysCmd.Stderr = os.Stderr
	}
	if err := tangKeysCmd.Run(); err != nil {
		return fmt.Errorf("tangd-keygen: %v", err)
	}

	// build advertisement for the keys
	// tang before version v7 had script tangd-update that generated advertisement file
	// but now we need to build it manually by launching tangd and making "GET /adv" request to it.
	tangAdvCmd := exec.Command("/usr/lib/tangd", tangDir)
	tangAdvCmd.Stdin = strings.NewReader("GET /adv HTTP/1.1\n\n")
	var outb bytes.Buffer
	tangAdvCmd.Stdout = &outb
	if *verbose {
		tangAdvCmd.Stderr = os.Stderr
	}
	if err := tangAdvCmd.Run(); err != nil {
		return fmt.Errorf("tangd: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(outb.Bytes())), nil)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return os.WriteFile(path.Join(tangDir, "adv.jwk"), body, 0644)
}

func assetsInit() error {
	_ = os.Mkdir(assetsDir, 0755)

	if err := compileInitForTests(initBinaryPath); err != nil {
		return err
	}
	if err := compileRootfsBuilder(rootfsBuilderBinaryPath); err != nil {
		return err
	}

	err := assetsTangInit()
	if err != nil {
		return err
	}

	tpmStateDir := assetsDir + "/tpm2"
	_ = os.Mkdir(tpmStateDir, 0755)
	swtpmSetup := exec.Command("swtpm_setup", "--tpm-state", tpmStateDir, "--tpm2", "--ecc", "--create-ek-cert", "--create-platform-cert", "--lock-nvram")
	if *verbose {
		swtpmSetup.Stdout = os.Stdout
		swtpmSetup.Stderr = os.Stderr
	}
	if err := swtpmSetup.Run(); err != nil {
		return err
	}

	return nil
}

func sudoBash(script string) error {
	sh := exec.Command("sudo", "/bin/sh", "-s")
	sh.Stdin = strings.NewReader(script)
	if *verbose {
		sh.Stdout = os.Stdout
		sh.Stderr = os.Stderr
	}
	return sh.Run()

}

// based on instructions from https://github.com/anatol/vmtest/blob/master/docs/prepare_image.md
const createExt4Image = `
set -e

raw=$(mktemp)
dd if=/dev/zero of=$raw bs=1G count=1
mkfs.ext4 $raw
loopdev=$(losetup -fP --show $raw)
mount=$(mktemp -d)
mount $loopdev $mount
pacstrap -c $mount base openssh
genfstab -U $mount > $mount/etc/fstab
cat $mount/etc/fstab # echo fstab to logs

echo "[Match]
Name=*

[Network]
DHCP=yes" > $mount/etc/systemd/network/20-wired.network

sed -i '/^root/ { s/:x:/::/ }' $mount/etc/passwd
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' $mount/etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/' $mount/etc/ssh/sshd_config

arch-chroot $mount systemctl enable sshd systemd-networkd
umount $mount
losetup -d $loopdev
rm -r $mount

mv $raw ../assets/archlinux.ext4.raw
`

const createBtrfsImage = `
set -e

raw=$(mktemp)
dd if=/dev/zero of=$raw bs=1G count=1
passphrase="hello"
cryptdev=/dev/mapper/booster.tests.btrfs
cryptsetup luksFormat -q --uuid=724151bb-84be-493c-8e32-53e123c8351b --perf-no_read_workqueue --perf-no_write_workqueue --type luks2 --cipher aes-xts-plain64 --key-size 512 --iter-time 2000 --pbkdf argon2id --hash sha3-512 $raw <<< "$passphrase"
cryptsetup --allow-discards --perf-no_read_workqueue --perf-no_write_workqueue --persistent open $raw booster.tests.btrfs <<< "$passphrase"
mkfs.btrfs -L Arch --uuid=15700169-8c12-409d-8781-37afa98442a8 $cryptdev
mount=$(mktemp -d)
mount $cryptdev $mount
btrfs sub create $mount/@
btrfs sub create $mount/@home
btrfs sub create $mount/@srv
btrfs sub create $mount/@var
umount $mount
mount -o noatime,compress-force=zstd,commit=120,space_cache=v2,ssd,discard=async,autodefrag,subvol=@ $cryptdev $mount
mkdir -p $mount/{home,srv,var}
mount -o noatime,compress-force=zstd,commit=120,space_cache=v2,ssd,discard=async,autodefrag,subvol=@home $cryptdev $mount/home
mount -o noatime,compress-force=zstd,commit=120,space_cache=v2,ssd,discard=async,autodefrag,subvol=@srv $cryptdev $mount/srv
mount -o noatime,compress-force=zstd,commit=120,space_cache=v2,ssd,discard=async,autodefrag,subvol=@var $cryptdev $mount/var
pacstrap -c $mount base openssh
genfstab -U $mount > $mount/etc/fstab
cat $mount/etc/fstab # echo fstab to logs

echo "[Match]
Name=*

[Network]
DHCP=yes" > $mount/etc/systemd/network/20-wired.network

sed -i '/^root/ { s/:x:/::/ }' $mount/etc/passwd
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' $mount/etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/' $mount/etc/ssh/sshd_config

arch-chroot $mount systemctl enable sshd systemd-networkd
umount $mount/{home,srv,var}
umount $mount
cryptsetup close booster.tests.btrfs
rm -r $mount

mv $raw ../assets/archlinux.btrfs.raw
`

func buildArchLinuxImages() error {
	err := sudoBash(createExt4Image)
	if err != nil {
		return err
	}

	err = sudoBash(createBtrfsImage)
	if err != nil {
		return err
	}

	return nil
}

func assetsBuildLocal() error {
	for id, params := range imagesToBuild {
		if err := runBuilderLocal(id, params); err != nil {
			return err
		}
	}

	if err := buildArchLinuxImages(); err != nil {
		return err
	}

	if err := chownCurrentUser(assetsDir); err != nil {
		return err
	}

	return nil
}

func assetsBuildQemu() error {
	if err := regenerateCow(); err != nil {
		log.Fatal(err)
	}

	vm, err := runBuilderVm()
	if err != nil {
		return err
	}
	defer vm.Kill()

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	scpAddress := "scp://root@localhost:10022/"
	if err := scp(initBinaryPath, scpAddress); err != nil {
		return err
	}
	if err := scp(rootfsBuilderBinaryPath, scpAddress); err != nil {
		return err
	}

	conn, err := ssh.Dial("tcp", ":10022", config)
	if err != nil {
		return err
	}
	defer conn.Close()

	for id, params := range imagesToBuild {
		if err := runBuilderInQemu(conn, scpAddress, id, params); err != nil {
			return err
		}
	}

	return nil
}

func runBuilderInQemu(conn *ssh.Client, scpAddress string, id string, params []string) error {
	if *verbose {
		log.Printf("Run qemu builder for '%s'\n", id)
	}
	sess, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	builderCmd := fmt.Sprintf("./rootfs_builder -id %s", id) + strings.Join(params, " ")
	if *verbose {
		builderCmd += " -verbose"
	}
	output, err := sess.CombinedOutput(builderCmd)
	if *verbose {
		fmt.Print(string(output))
	}
	if err != nil {
		return err
	}

	if err := scp(scpAddress+id+".img", assetsDir+"/"); err != nil {
		return err
	}
	return nil
}

func runBuilderLocal(id string, extraParams []string) error {
	if *verbose {
		log.Printf("Run local builder for '%s'\n", id)
	}

	params := []string{"./rootfs_builder", "-id", id}
	params = append(params, extraParams...)
	if *verbose {
		params = append(params, "-verbose")
	}

	cmd := exec.Command("sudo", params...)
	if *verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rootfs_builder: %v", err)
	}
	imageFile := id + ".img"
	if err := os.Rename(imageFile, assetsDir+"/"+id+".img"); err != nil {
		return err
	}

	return nil
}

func chownCurrentUser(file string) error {
	u, err := user.Current()
	if err != nil {
		return err
	}
	return exec.Command("sudo", "chown", u.Username+":"+u.Username, "-R", file).Run()
}

func runBuilderVm() (*vmtest.Qemu, error) {
	params := []string{"-net", "user,hostfwd=tcp::10022-:22", "-net", "nic", "-m", "8G", "-smp", strconv.Itoa(runtime.NumCPU())}
	if os.Getenv("TEST_DISABLE_KVM") != "1" {
		params = append(params, "-enable-kvm", "-cpu", "host")
	}
	opts := vmtest.QemuOptions{
		OperatingSystem: vmtest.OS_LINUX,
		Kernel:          "bzImage",
		Params:          params,
		Disks:           []vmtest.QemuDisk{{"rootfs.cow", "qcow2"}}, // use Copy-On-Write file on top of backing file 'qemu-img create -o backing_file=rootfs.raw,backing_fmt=raw -f qcow2 rootfs.cow'
		Append:          []string{"root=/dev/sda", "rw"},
		Verbose:         *verbose,
		Timeout:         50 * time.Second,
	}
	// Run QEMU instance
	if *verbose {
		fmt.Println("Starting up fsroot image builder virtual machine")
	}
	return vmtest.NewQemu(&opts)
}

func compileInitForTests(output string) error {
	return exec.Command("gcc", "-static", "-o", output, "../init/init.c").Run()
}

func compileRootfsBuilder(output string) error {
	output, err := filepath.Abs(output)
	if err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	defer os.Chdir(cwd)

	if err := os.Chdir("../rootfs_builder"); err != nil {
		return err
	}
	return exec.Command("go", "build", "-o", output).Run()
}

func scp(from, to string) error {
	cmd := exec.Command("scp", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", from, to)
	if *verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

// regenerate *.cow file to drop all user-specific changes
func regenerateCow() error {
	cmd := exec.Command("qemu-img", "create", "-o", "backing_file=rootfs.raw,backing_fmt=raw", "-f", "qcow2", "rootfs.cow")
	if *verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

func main() {
	flag.Parse()

	if err := assetsInit(); err != nil {
		log.Fatal(err)
	}

	if err := assetsBuildLocal(); err != nil {
		log.Fatal(err)
	}
}
