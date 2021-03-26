package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

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
	stripBinaries           bool

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

	if err := img.appendInitBinary(conf.initBinary); err != nil {
		return err
	}

	if err := img.appendExtraFiles(conf.extraFiles); err != nil {
		return err
	}

	kmod, err := img.appendModules(conf)
	if err != nil {
		return err
	}

	var vconsole *VirtualConsole
	if conf.enableVirtualConsole {
		vconsole, err = img.enableVirtualConsole(conf.vconsolePath, conf.localePath)
		if err != nil {
			return err
		}
	}

	if err := img.appendInitConfig(conf, kmod.dependencies, kmod.postDependencies, vconsole); err != nil {
		return err
	}

	// appending initrd-release file per recommendation from https://systemd.io/INITRD_INTERFACE/
	if err := img.AppendContent([]byte{}, 0644, "/etc/initrd-release"); err != nil {
		return err
	}

	return img.Close()
}

func (img *Image) appendInitBinary(initBinary string) error {
	content, err := os.ReadFile(initBinary)
	if err != nil {
		return fmt.Errorf("%s: %v", initBinary, err)
	}
	return img.AppendContent(content, 0755, "/init")
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

func (img *Image) appendInitConfig(conf *generatorConfig, kmodDeps map[string][]string, kmodPostDeps map[string][]string, vconsole *VirtualConsole) error {
	var initConfig InitConfig // config for init stored to /etc/booster.init.yaml

	initConfig.MountTimeout = int(conf.timeout.Seconds())
	initConfig.Kernel = conf.kernelVersion
	initConfig.ModuleDependencies = kmodDeps
	initConfig.ModulePostDependencies = kmodPostDeps
	initConfig.VirtualConsole = vconsole

	if conf.networkConfigType == netDhcp {
		initConfig.Network = &InitNetworkConfig{}
		initConfig.Network.Dhcp = true
	} else if conf.networkConfigType == netStatic {
		initConfig.Network = &InitNetworkConfig{}
		initConfig.Network.Ip = conf.networkStaticConfig.ip
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

	return img.AppendContent(content, 0644, initConfigPath)
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
	return img.AppendContent(buff.Bytes(), 0644, imageModulesDir+"booster.alias")
}
