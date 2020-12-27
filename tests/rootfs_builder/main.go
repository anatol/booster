package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/tych0/go-losetup" // fork of github.com/freddierice/go-losetup
)

var id = flag.String("id", "", "unique id for the build invocation, the output image file will be called $id.img")
var initBinary = flag.String("initBinary", "init", "location of init binary to use for the rootfs")
var luksVersion = flag.Int("luksVersion", 0, "encryption format for the rootfs image, 0 means no encryption used")
var luksPassword = flag.String("luksPassword", "", "password for LUKS partition")
var luksClevisPin = flag.String("luksClevisPin", "", "clevis pin used to bind the partition")
var luksClevisConfig = flag.String("luksClevisConfig", "", "clevis pin config")
var luksUuid = flag.String("luksUuid", "", "UUID for LUKS partition")
var fsUuid = flag.String("fsUuid", "", "UUID for filesystem partition")
var fsLabel = flag.String("fsLabel", "", "Label for the filesystem")
var verbose = flag.Bool("verbose", false, "output debug info to console")

func copyFile(src, dest string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()

	d, err := os.OpenFile(dest, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return err
	}
	defer d.Close()

	_, err = io.Copy(d, s)
	return err
}

func run() error {
	flag.Parse()
	if *id == "" {
		return fmt.Errorf("Please provide build id with -id flag")
	}

	output := *id + ".img"
	outputFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	imageSize := 40 * 1024 * 1024 // 40 MiB
	if err := outputFile.Truncate(int64(imageSize)); err != nil {
		return err
	}

	var fsDev string
	if *luksVersion == 0 {
		// we have a raw image with ext4 filesystem, but mount requires a block device
		loopDev, err := losetup.Attach(output, 0, false)
		if err != nil {
			return err
		}
		defer loopDev.Detach()

		fsDev = loopDev.Path()
	} else {
		if *luksPassword == "" {
			return fmt.Errorf("Please provide luks password with -luksPassword")
		}
		luksType := fmt.Sprintf("luks%d", *luksVersion)
		luksParams := []string{"luksFormat", "--type", luksType, output}
		if *luksUuid != "" {
			luksParams = append(luksParams, "--uuid", *luksUuid)
		}

		formatCmd := exec.Command("cryptsetup", luksParams...)
		formatCmd.Stdin = strings.NewReader(*luksPassword)
		if *verbose {
			formatCmd.Stdout = os.Stdout
			formatCmd.Stderr = os.Stderr
		}
		if err := formatCmd.Run(); err != nil {
			return fmt.Errorf("cryptsetup luksFormat: %v", err)
		}

		if *luksClevisPin == "tpm2" {
			swtpmCmd := exec.Command("swtpm", "socket", "--tpmstate", "dir=../assets/tpm2", "--tpm2", "--server", "type=tcp,port=2321", "--ctrl", "type=tcp,port=2322", "--flags", "not-need-init,startup-clear")
			if *verbose {
				swtpmCmd.Stdout = os.Stdout
				swtpmCmd.Stderr = os.Stderr
			}
			if err := swtpmCmd.Start(); err != nil {
				return err
			}
			defer swtpmCmd.Process.Kill()
		}

		if *luksClevisPin != "" {
			clevisCmd := exec.Command("clevis", "luks", "bind", "-y", "-k", "-", "-d", output, *luksClevisPin, *luksClevisConfig)
			if *luksClevisPin == "tpm2" || strings.Contains(*luksClevisConfig, "luks2") {
				// custom TPM2TOOLS_TCTI does not work due to https://github.com/latchset/clevis/issues/244
				clevisCmd.Env = append(os.Environ(), "TPM2TOOLS_TCTI=swtpm")
			}

			clevisCmd.Stdin = strings.NewReader(*luksPassword)
			if *verbose {
				clevisCmd.Stdout = os.Stdout
				clevisCmd.Stderr = os.Stderr
			}
			if err := clevisCmd.Run(); err != nil {
				return fmt.Errorf("clevis bind: %v", err)
			}
		}

		volumeName := *id
		openCmd := exec.Command("cryptsetup", "open", output, volumeName)
		openCmd.Stdin = strings.NewReader(*luksPassword)
		if *verbose {
			openCmd.Stdout = os.Stdout
			openCmd.Stderr = os.Stderr
		}
		if err := openCmd.Run(); err != nil {
			return fmt.Errorf("cryptsetup open: %v", err)
		}
		defer exec.Command("cryptsetup", "close", volumeName).Run()
		fsDev = "/dev/mapper/" + volumeName
	}

	mkfsParams := []string{fsDev}
	if *fsUuid != "" {
		mkfsParams = append(mkfsParams, "-U", *fsUuid)
	}
	if *fsLabel != "" {
		mkfsParams = append(mkfsParams, "-L", *fsLabel)
	}
	mkfsCmd := exec.Command("mkfs.ext4", mkfsParams...)
	if *verbose {
		mkfsCmd.Stdout = os.Stdout
		mkfsCmd.Stderr = os.Stderr
	}
	if err := mkfsCmd.Run(); err != nil {
		return fmt.Errorf("mkfs.ext4: %v", err)
	}

	mountPoint := *id + ".mount"
	if err := os.Mkdir(mountPoint, 0755); err != nil {
		return err
	}
	defer os.Remove(mountPoint)

	if err := syscall.Mount(fsDev, mountPoint, "ext4", syscall.MS_NOATIME, ""); err != nil {
		return err
	}
	defer syscall.Unmount(mountPoint, 0)

	// copy our init to the image
	if err := os.Mkdir(mountPoint+"/sbin", 0755); err != nil {
		return err
	}
	initDest := mountPoint + "/sbin/init"
	if err := copyFile(*initBinary, initDest); err != nil {
		return err
	}
	if err := os.Chmod(initDest, 0755); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		//os.Remove(*id + ".img")
		log.Fatal(err)
	}
}
