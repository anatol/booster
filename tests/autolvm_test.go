package tests

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type AutoLVMInitConfig struct {
	EnableLVM bool `yaml:",omitempty"`
}

func AutoLVMScript(script string, env ...string) error {
	if testing.Verbose() {
		fmt.Printf("Running script %s\n", script)
	}
	err := shell(script, env...)
	return err
}

func TestAutoLVM(t *testing.T) {
	tmp := t.TempDir()
	mntPoint := filepath.Join(tmp, "mount")

	require.NoError(t, checkAsset("assets/lvm.img"))

	if err := AutoLVMScript("scripts/autolvm_pre.sh", "OUTPUT=assets/lvm.img", "MNTPOINT="+mntPoint); err != nil {
		t.Skip("Setup script failed")
	}
	defer AutoLVMScript("scripts/autolvm_post.sh", "OUTPUT=assets/lvm.img", "MNTPOINT="+mntPoint)

	outputFile, err := generateInitRamfs(tmp, Opts{
		enableAutoLVM:    true,
		generatorEnvvars: []string{"BOOSTER_TEST_ROOT_MOUNTPOINT=" + mntPoint},
	})
	require.NoError(t, err)

	// Extract generated config
	configString, err := exec.Command(binariesDir+"/generator", "cat", outputFile, "etc/booster.init.yaml").Output()
	require.NoError(t, err)

	var config AutoLVMInitConfig
	yaml.Unmarshal(configString, &config)
	require.True(t, config.EnableLVM)

}

func TestAutoLVMDisabled(t *testing.T) {
	tmp := t.TempDir()
	mntPoint := filepath.Join(tmp, "mount")

	require.NoError(t, checkAsset("assets/lvm.img"))

	if err := AutoLVMScript("scripts/autolvm_pre.sh", "OUTPUT=assets/lvm.img", "MNTPOINT="+mntPoint); err != nil {
		t.Skip("Setup script failed")
	}
	defer AutoLVMScript("scripts/autolvm_post.sh", "OUTPUT=assets/lvm.img", "MNTPOINT="+mntPoint)

	outputFile, err := generateInitRamfs(tmp, Opts{
		enableLVM:        false,
		generatorEnvvars: []string{"BOOSTER_TEST_ROOT_MOUNTPOINT=" + mntPoint},
	})
	require.NoError(t, err)

	// Extract generated config
	configString, err := exec.Command(binariesDir+"/generator", "cat", outputFile, "etc/booster.init.yaml").Output()
	require.NoError(t, err)

	var config AutoLVMInitConfig
	yaml.Unmarshal(configString, &config)
	require.False(t, config.EnableLVM)

}
