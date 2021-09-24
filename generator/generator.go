package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cavaliercoder/go-cpio"
	"gopkg.in/yaml.v3"
)

// An internal structure that represents configuration for the generator.
// It is essentially combination of UserConfig + flags
type generatorConfig struct {
	networkConfigType       netConfigType
	networkStaticConfig     *networkStaticConfig
	networkActiveInterfaces []net.HardwareAddr
	universal               bool
	modules                 []string // extra modules to add
	modulesForceLoad        []string // extra modules to load at the boot time
	compression             string
	timeout                 time.Duration
	extraFiles              []string
	output                  string
	forceOverwrite          bool // overwrite output file
	initBinary              string
	kernelVersion           string
	modulesDir              string
	debug                   bool
	readDeviceAliases       func() (set, error)
	readHostModules         func() (set, error)
	readModprobeOptions     func() (map[string]string, error)
	stripBinaries           bool
	enableLVM               bool
	enableMdraid            bool
	mdraidConfigPath        string

	// virtual console configs
	enableVirtualConsole     bool
	vconsolePath, localePath string
}

type networkStaticConfig struct {
	ip         string
	gateway    string
	dnsServers string // comma-separated list
}

type netConfigType int

const (
	netOff netConfigType = iota
	netDhcp
	netStatic
)

const (
	imageModulesDir = "/usr/lib/modules/"
	firmwareDir     = "/usr/lib/firmware/"
)

// This is default modules list checked by booster. It either specifies a name of the module
// or whole directory that added recursively. Dependencies of these scanned modules are added as well.
//
// In case of 'universal' build all specified modules are added to the image.
// In case of 'host' build only modules for active devices are added.
var defaultModulesList = []string{
	"kernel/fs/",
	"kernel/arch/x86/crypto/",
	"kernel/crypto/",
	"kernel/drivers/input/serio/",
	"kernel/drivers/input/keyboard/",
	"kernel/drivers/net/ethernet/",
	"kernel/drivers/md/",
	"kernel/drivers/char/tpm/",
	"kernel/drivers/usb/host/",
	"kernel/drivers/hid/usbhid/",
	"hid_generic", "sd_mod", "ahci",
	"sdhci", "sdhci_pci", "mmc_block", // mmc
	"nvme", "usb_storage",
	"virtio_pci", "virtio_blk", "virtio_scsi", "virtio_crypto",
}

func generateInitRamfs(conf *generatorConfig) error {
	if _, err := os.Stat(conf.output); (err == nil || !os.IsNotExist(err)) && !conf.forceOverwrite {
		return fmt.Errorf("File %v exists, please specify -force if you want to overwrite it", conf.output)
	}

	img, err := NewImage(conf.output, conf.compression, conf.stripBinaries)
	if err != nil {
		return err
	}
	defer img.Cleanup()

	if err := appendCompatibilitySymlinks(img); err != nil {
		return err
	}

	if err := img.appendInitBinary(conf.initBinary); err != nil {
		return err
	}

	if err := img.appendExtraFiles(conf.extraFiles); err != nil {
		return err
	}

	if conf.enableLVM {
		conf.modules = append(conf.modules, "dm_mod", "dm_snapshot", "dm_mirror", "dm_cache", "dm_cache_smq", "dm_thin_pool")
		conf.modulesForceLoad = append(conf.modulesForceLoad, "dm_mod")
		if err := img.appendExtraFiles([]string{"lvm"}); err != nil {
			return err
		}
	}

	if conf.enableMdraid {
		// preload md_mod for speed. Level-specific drivers (e.g. raid1, raid456) are going to be detected loaded at boot-time
		conf.modulesForceLoad = append(conf.modulesForceLoad, "md_mod")

		if err := img.appendExtraFiles([]string{"mdadm"}); err != nil {
			return err
		}

		mdadmConf := conf.mdraidConfigPath
		if mdadmConf == "" {
			mdadmConf = "/etc/mdadm.conf"
		}
		content, err := os.ReadFile(mdadmConf)
		if err != nil {
			return err
		}
		if err := img.AppendContent("/etc/mdadm.conf", 0644, content); err != nil {
			return err
		}
	}

	kmod, err := img.appendModules(conf)
	if err != nil {
		return err
	}

	if conf.enableMdraid {
		if err := kmod.activateModules(true, true, "kernel/drivers/md/"); err != nil {
			return err
		}
	}

	var vconsole *VirtualConsole
	if conf.enableVirtualConsole {
		vconsole, err = img.enableVirtualConsole(conf.vconsolePath, conf.localePath)
		if err != nil {
			return err
		}
	}

	kmod.filterModprobeForRequiredModules()

	if err := img.appendInitConfig(conf, kmod, vconsole); err != nil {
		return err
	}

	// appending initrd-release file per recommendation from https://systemd.io/INITRD_INTERFACE/
	if err := img.AppendContent("/etc/initrd-release", 0644, []byte{}); err != nil {
		return err
	}

	return img.Close()
}

// appendCompatibilitySymlinks appends symlinks for compatibility with older firmware that loads extra files from non-standard locations
func appendCompatibilitySymlinks(img *Image) error {
	symlinks := []struct{ src, target string }{
		{"/lib", "/usr/lib"},
		{"/usr/local/lib", "/usr/lib"},
		{"/usr/sbin", "/usr/bin"},
		{"/bin", "/usr/bin"},
		{"/sbin", "/usr/bin"},
		{"/usr/local/bin", "/usr/bin"},
		{"/usr/local/sbin", "/usr/bin"},
		{"/var/run", "/run"},
		{"/usr/lib64", "/usr/lib"},
		{"/lib64", "/usr/lib"},
	}

	for _, l := range symlinks {
		mode := cpio.FileMode(0777) | cpio.ModeSymlink
		if err := img.AppendEntry(l.src, mode, []byte(l.target)); err != nil {
			return err
		}
	}
	return nil
}

func (img *Image) appendInitBinary(initBinary string) error {
	content, err := os.ReadFile(initBinary)
	if err != nil {
		return fmt.Errorf("%s: %v", initBinary, err)
	}
	return img.AppendContent("/init", 0755, content)
}

func (img *Image) appendExtraFiles(binaries []string) error {
	for _, f := range binaries {
		if !strings.HasPrefix(f, "/") {
			// simple names like "strace" are resolved as binaries under /usr/bin
			f = "/usr/bin/" + f
		}

		if err := img.AppendFile(f); err != nil {
			return err
		}
	}
	return nil
}

func (img *Image) appendFirmwareFiles(modName string, fws []string) error {
	for _, fw := range fws {
		fwPath := firmwareDir + fw
		if _, err := os.Stat(fwPath); os.IsNotExist(err) {
			debug("module %s depends on firmware %s but the firmware file does not exist", modName, fw)
			continue
		}
		if err := img.AppendFile(fwPath); err != nil {
			return err
		}
	}
	return nil
}

func (img *Image) appendInitConfig(conf *generatorConfig, kmod *Kmod, vconsole *VirtualConsole) error {
	var initConfig InitConfig // config for init stored to /etc/booster.init.yaml

	initConfig.MountTimeout = int(conf.timeout.Seconds())
	initConfig.Kernel = conf.kernelVersion
	initConfig.ModuleDependencies = kmod.dependencies
	initConfig.ModulePostDependencies = kmod.postDependencies
	initConfig.ModulesForceLoad = kmod.selectNonBuiltinModules(conf.modulesForceLoad)
	initConfig.ModprobeOptions = kmod.modprobeOptions
	initConfig.BuiltinModules = kmod.builtinModules
	initConfig.VirtualConsole = vconsole
	initConfig.EnableLVM = conf.enableLVM
	initConfig.EnableMdraid = conf.enableMdraid

	if conf.networkConfigType == netDhcp {
		initConfig.Network = &InitNetworkConfig{}
		initConfig.Network.Dhcp = true
	} else if conf.networkConfigType == netStatic {
		initConfig.Network = &InitNetworkConfig{}
		initConfig.Network.IP = conf.networkStaticConfig.ip
		initConfig.Network.Gateway = conf.networkStaticConfig.gateway
		initConfig.Network.DNSServers = conf.networkStaticConfig.dnsServers
	}
	if conf.networkActiveInterfaces != nil {
		initConfig.Network.Interfaces = conf.networkActiveInterfaces
	}

	content, err := yaml.Marshal(initConfig)
	if err != nil {
		return err
	}

	return img.AppendContent(initConfigPath, 0644, content)
}

func (img *Image) appendModules(conf *generatorConfig) (*Kmod, error) {
	kmod, err := NewKmod(conf)
	if err != nil {
		return nil, err
	}

	// some kernels might be compiled without some of the modules (e.g. virtio) from the predefined list
	// generator should not fail if a module is not detected
	if err := kmod.activateModules(true, false, defaultModulesList...); err != nil {
		return nil, err
	}
	if err := kmod.activateModules(false, true, conf.modules...); err != nil {
		return nil, err
	}
	if err := kmod.activateModules(false, true, conf.modulesForceLoad...); err != nil {
		return nil, err
	}

	// cbc module is a hard requirement for "encrypted_keys"
	// https://github.com/torvalds/linux/blob/master/security/keys/encrypted-keys/encrypted.c#L42
	kmod.addExtraDep("encrypted_keys", "cbc")

	if err := kmod.resolveDependencies(); err != nil {
		return nil, err
	}
	if err := kmod.addModulesToImage(img); err != nil {
		return nil, err
	}

	// collect aliases for required modules only
	aliases, err := kmod.filterAliasesForRequiredModules(conf)
	if err != nil {
		return nil, err
	}
	if err := img.appendAliasesFile(aliases); err != nil {
		return nil, err
	}

	for m := range kmod.hostModules {
		if !kmod.requiredModules[m] {
			debug("module '%s' currently used at the host but was not added to the image", m)
		}
	}

	return kmod, nil
}

func (img *Image) appendAliasesFile(aliases []alias) error {
	var buff bytes.Buffer
	for _, a := range aliases {
		buff.WriteString(a.pattern)
		buff.WriteString(" ")
		buff.WriteString(a.module)
		buff.WriteString("\n")
	}
	return img.AppendContent(imageModulesDir+"booster.alias", 0644, buff.Bytes())
}
