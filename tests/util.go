package tests

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/anatol/tang.go"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const kernelsDir = "/usr/lib/modules"

var kernelVersions map[string]string

func copy(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	return io.Copy(destination, source)
}

// Note: if you see tpm2 tests fail with "integrity check failed" error make sure you pull clevis changes from
// https://github.com/latchset/clevis/issues/244
func startSwtpm() (*os.Process, []string, error) {
	_ = os.Mkdir("assets", 0755)

	if err := checkAsset("assets/tpm2/tpm2-00.permall.pristine"); err != nil {
		return nil, nil, err
	}

	_ = os.Remove("assets/tpm2/.lock")
	_ = os.Remove("assets/swtpm-sock") // sometimes process crashes and leaves this file
	if _, err := copy("assets/tpm2/tpm2-00.permall.pristine", "assets/tpm2/tpm2-00.permall"); err != nil {
		return nil, nil, err
	}

	cmd := exec.Command("swtpm", "socket", "--tpmstate", "dir=assets/tpm2", "--tpm2", "--ctrl", "type=unixio,path=assets/swtpm-sock", "--flags", "not-need-init")
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	// wait till swtpm really starts
	if err := waitForFile("assets/swtpm-sock", 5*time.Second); err != nil {
		return nil, nil, err
	}

	return cmd.Process, []string{"-chardev", "socket,id=chrtpm,path=assets/swtpm-sock", "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0"}, nil
}

func startTangd() (*tang.NativeServer, []string, error) {
	_ = os.Mkdir("assets", 0755)

	if err := checkAsset("assets/tang/adv.json"); err != nil {
		return nil, nil, err
	}

	tangd, err := tang.NewNativeServer("assets/tang", 0)
	if err != nil {
		return nil, nil, err
	}

	return tangd, []string{"-nic", fmt.Sprintf("user,id=n1,restrict=on,guestfwd=tcp:10.0.2.100:5697-tcp:localhost:%d", tangd.Port)}, nil
}

func waitForFile(filename string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		_, err := os.Stat(filename)
		if err == nil {
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("waitForFile: %v", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %v", filename)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func runSSHCommand(t *testing.T, conn *ssh.Client, command string) string {
	sessAnalyze, err := conn.NewSession()
	require.NoError(t, err)
	defer sessAnalyze.Close()

	out, err := sessAnalyze.CombinedOutput(command)
	require.NoError(t, err)

	return string(out)
}

func shell(script string, env ...string) error {
	sh := exec.Command("bash", "-o", "errexit", script)
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

func detectKernelVersion() (map[string]string, error) {
	files, err := os.ReadDir(kernelsDir)
	if err != nil {
		return nil, err
	}
	kernels := make(map[string]string)
	for _, f := range files {
		ver := f.Name()
		vmlinux := filepath.Join(kernelsDir, ver, "vmlinuz")
		if _, err := os.Stat(vmlinux); err != nil {
			continue
		}
		pkgbase, err := os.ReadFile(filepath.Join(kernelsDir, ver, "pkgbase"))
		if err != nil {
			return nil, err
		}
		pkgbase = bytes.TrimSpace(pkgbase)

		kernels[string(pkgbase)] = ver
	}
	return kernels, nil
}
