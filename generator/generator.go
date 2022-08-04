package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/cavaliergopher/cpio"
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
	readHostModules         func(kernelVer string) (set, error)
	readModprobeOptions     func() (map[string]string, error)
	stripBinaries           bool
	enableLVM               bool
	enableMdraid            bool
	mdraidConfigPath        string
	enableZfs               bool
	zfsImportParams         string
	zfsCachePath            string

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

var (
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
	"kernel/drivers/md/",
	"kernel/drivers/char/tpm/",
	"kernel/drivers/usb/host/",
	"kernel/drivers/hid/",
	"kernel/drivers/ata/",
	"hid_generic", "sd_mod", "ahci",
	"sdhci", "sdhci_acpi", "sdhci_pci", "mmc_block", // mmc
	"nvme", "usb_storage", "uas",
	"efivarfs",
	"virtio_pci", "virtio_blk", "virtio_scsi", "virtio_crypto",
}

func generateInitRamfs(conf *generatorConfig) error {
	if _, err := os.Stat(conf.output); (err == nil || !os.IsNotExist(err)) && !conf.forceOverwrite {
		return fmt.Errorf("File %v exists, please specify --force if you want to overwrite it", conf.output)
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

	if err := img.appendExtraFiles(conf.extraFiles...); err != nil {
		return err
	}

	kmod, err := NewKmod(conf)
	if err != nil {
		return err
	}

	// some kernels might be compiled without some of the modules (e.g. virtio) from the predefined list
	// generator should not fail if a module is not detected
	if err := kmod.activateModules(true, false, defaultModulesList...); err != nil {
		return err
	}
	if err := kmod.activateModules(false, true, conf.modules...); err != nil {
		return err
	}
	if err := kmod.activateModules(false, true, conf.modulesForceLoad...); err != nil {
		return err
	}

	// cbc module is a hard requirement for "encrypted_keys"
	// https://github.com/torvalds/linux/blob/master/security/keys/encrypted-keys/encrypted.c#L42
	kmod.addExtraDep("encrypted_keys", "cbc")

	if conf.networkConfigType != netOff {
		if err := kmod.activateModules(true, false, "kernel/drivers/net/ethernet/"); err != nil {
			return err
		}
	}

	if conf.enableLVM {
		if err := kmod.activateModules(false, false, "dm_mod", "dm_snapshot", "dm_mirror", "dm_cache", "dm_cache_smq", "dm_thin_pool"); err != nil {
			return err
		}

		conf.modulesForceLoad = append(conf.modulesForceLoad, "dm_mod")
		if err := img.appendExtraFiles("lvm"); err != nil {
			return err
		}
	}

	if conf.enableMdraid {
		if err := kmod.activateModules(true, true, "kernel/drivers/md/"); err != nil {
			return err
		}

		// preload md_mod for speed. Level-specific drivers (e.g. raid1, raid456) are going to be detected loaded at boot-time
		conf.modulesForceLoad = append(conf.modulesForceLoad, "md_mod")

		if err := img.appendExtraFiles("mdadm"); err != nil {
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
		if err := img.AppendContent("/etc/mdadm.conf", 0o644, content); err != nil {
			return err
		}
	}

	if conf.enableZfs {
		if err := kmod.activateModules(false, true, "zfs"); err != nil {
			return err
		}
		conf.modulesForceLoad = append(conf.modulesForceLoad, "zfs")

		if err := img.appendExtraFiles("zpool", "zfs"); err != nil {
			return err
		}

		zfsCachePath := conf.zfsCachePath
		if zfsCachePath == "" {
			zfsCachePath = "/etc/zfs/zpool.cache"
		}
		content, err := os.ReadFile(zfsCachePath)
		if err != nil {
			return err
		}
		if err := img.AppendContent("/etc/zfs/zpool.cache", 0o644, content); err != nil {
			return err
		}

		if err := img.AppendFile("/etc/default/zfs"); err != nil {
			return err
		}
	}

	if err := kmod.resolveDependencies(); err != nil {
		return err
	}
	if err := kmod.addModulesToImage(img); err != nil {
		return err
	}

	// collect aliases for required modules only
	aliases, err := kmod.filterAliasesForRequiredModules(conf)
	if err != nil {
		return err
	}
	if err := img.appendAliasesFile(aliases); err != nil {
		return err
	}

	kmod.filterModprobeForRequiredModules()

	var vconsole *VirtualConsole
	if conf.enableVirtualConsole {
		vconsole, err = img.enableVirtualConsole(conf.vconsolePath, conf.localePath)
		if err != nil {
			return err
		}
	}

	if err := img.appendInitConfig(conf, kmod, vconsole); err != nil {
		return err
	}

	// appending initrd-release file per recommendation from https://systemd.io/INITRD_INTERFACE/
	if err := img.AppendContent("/etc/initrd-release", 0o644, []byte{}); err != nil {
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
		// Ensure that target always exist which may not be the
		// case if we only install files from /lib or /bin.
		if err := img.AppendDirEntry(l.target); err != nil {
			return err
		}

		mode := cpio.FileMode(0o777) | cpio.TypeSymlink
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
	return img.AppendContent("/init", 0o755, content)
}

func (img *Image) appendExtraFiles(binaries ...string) error {
	for _, f := range binaries {
		if !filepath.IsAbs(f) {
			// If the given name is not an absolute path, assume that it refers
			// to an executable and lookup the path to the executable using $PATH.
			var err error
			f, err = exec.LookPath(f)
			if err != nil {
				return err
			}
		}

		if err := img.AppendFile(f); err != nil {
			return err
		}
	}
	return nil
}

func findFwFile(fw string) (string, error) {
	supportedFwExt := []string{
		"",
		".xz", // https://archlinux.org/news/linux-firmware-202201190c6a7b3-2-requires-kernel-53-and-package-splitting/
	}

	fwBasePath := firmwareDir + fw
	for _, ext := range supportedFwExt {
		fwPath := fwBasePath + ext
		if _, err := os.Stat(fwPath); err == nil {
			return fwPath, nil
		} else if os.IsNotExist(err) {
			continue // try the next extension
		} else {
			return "", err
		}
	}

	return "", os.ErrNotExist
}

func (img *Image) appendFirmwareFiles(modName string, fws []string) error {
	for _, fw := range fws {
		path, err := findFwFile(fw)

		if os.IsNotExist(err) {
			debug("module %s depends on firmware %s but the firmware file does not exist", modName, fw)
			continue
		} else if err != nil {
			return err
		}

		if err := img.AppendFile(path); err != nil {
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
	initConfig.EnableZfs = conf.enableZfs
	initConfig.ZfsImportParams = conf.zfsImportParams

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

	return img.AppendContent(initConfigPath, 0o644, content)
}

func (img *Image) appendAliasesFile(aliases []alias) error {
	var buff bytes.Buffer
	for _, a := range aliases {
		buff.WriteString(a.pattern)
		buff.WriteString(" ")
		buff.WriteString(a.module)
		buff.WriteString("\n")
	}
	return img.AppendContent(imageModulesDir+"booster.alias", 0o644, buff.Bytes())
}
