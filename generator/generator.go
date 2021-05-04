package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
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

	// UEFI stub config
	uefi            bool
	osRelease       string
	cmdLine         string
	extraInitRd     string
	splash          string
	uefiStub        string
	uefiCertificate string
	uefiKey         string
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

	dir, err := ioutil.TempDir("", "booster")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	finalFile := dir + "/image"
	img, err := NewImage(finalFile, conf.compression, conf.stripBinaries)
	if err != nil {
		return err
	}
	defer img.Close()

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
		if err := img.AppendContent(content, 0644, "/etc/mdadm.conf"); err != nil {
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
	if err := img.AppendContent([]byte{}, 0644, "/etc/initrd-release"); err != nil {
		return err
	}

	if err := img.Close(); err != nil {
		return err
	}

	if conf.uefi {
		osReleaseFile := findExistingFile(conf.osRelease, "/etc/os-release", "/usr/lib/os-release")
		if osReleaseFile == "" {
			return fmt.Errorf("unable to find os-release file, please specify uefi/osrelease config property")
		}

		cmdLineFile := findExistingFile(conf.cmdLine, "/etc/kernel/cmdline", "/usr/share/kernel/cmdline", "/proc/cmdline")
		if cmdLineFile == "" {
			return fmt.Errorf("unable to find cmdline file, please specify uefi/cmdline config property")
		}

		if conf.extraInitRd != "" {
			finalFile = dir + "/joined.images"

			temp, err := os.Create(finalFile)
			if err != nil {
				return err
			}
			defer os.Remove(temp.Name())

			for _, f := range strings.Split(conf.extraInitRd, ",") {
				img, err := os.Open(f)
				if err != nil {
					return err
				}
				defer img.Close()

				if _, err := io.Copy(temp, img); err != nil {
					return err
				}
			}

			img, err := os.Open(dir + "/image")
			if err != nil {
				return err
			}
			defer img.Close()

			if _, err := io.Copy(temp, img); err != nil {
				return err
			}

			_ = temp.Close()
		}

		params := []string{
			"--add-section", ".osrel=" + osReleaseFile, "--change-section-vma", ".osrel=0x20000",
			"--add-section", ".cmdline=" + cmdLineFile, "--change-section-vma", ".cmdline=0x30000",
			"--add-section", ".linux=" + kmod.hostModulesDir + "/vmlinuz", "--change-section-vma", ".linux=0x2000000",
			"--add-section", ".initrd=" + finalFile, "--change-section-vma", ".initrd=0x3000000",
		}

		if conf.splash != "" {
			params = append(params, "--add-section", ".splash="+conf.splash, "--change-section-vma", ".splash=0x40000")
		}

		uefiStub := findExistingFile(conf.uefiStub, "/usr/lib/systemd/boot/efi/linuxx64.efi.stub", "/usr/lib/systemd/boot/efi/linuxia32.efi.stub", "/usr/lib/gummiboot/linuxx64.efi.stub", "/usr/lib/gummiboot/linuxia32.efi.stub", "/lib/systemd/boot/efi/linuxx64.efi.stub", "/lib/systemd/boot/efi/linuxia32.efi.stub", "/lib/gummiboot/linuxx64.efi.stub", "/lib/gummiboot/linuxia32.efi.stub")
		if uefiStub == "" {
			return fmt.Errorf("unable to find uefi stub file, please specify uefi/stub config property")
		}
		params = append(params, uefiStub, dir+"/uefi")
		finalFile = dir + "/uefi"

		cmd := exec.Command("objcopy", params...)
		if conf.debug {
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
		}
		if err := cmd.Run(); err != nil {
			return err
		}

		// signing
		if conf.uefiCertificate != "" && conf.uefiKey != "" {
			cmd := exec.Command("sbsign", "--key", conf.uefiKey, "--cert", conf.uefiCertificate, "--output", dir+"/uefi.signed", dir+"/uefi")
			if conf.debug {
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
			}
			if err := cmd.Run(); err != nil {
				return err
			}
			finalFile = dir + "/uefi.signed"

			/*
				peFile, err := ioutil.ReadFile(conf.output)
				if err != nil {
					log.Fatal(err)
				}

				ctx := pecoff.PECOFFChecksum(peFile)
				Cert := util.ReadCertFromFile(conf.uefiCertificate)
				Key := util.ReadKeyFromFile(conf.uefiCertificate)

				sig := pecoff.CreateSignature(ctx, Cert, Key)

				b := pecoff.AppendToBinary(ctx, sig)
				if err = ioutil.WriteFile(conf.output, b, 0644); err != nil {
					log.Fatal(err)
				}
			*/
		}
	}

	return os.Rename(finalFile, conf.output)
}

func findExistingFile(files ...string) string {
	for _, f := range files {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	return ""
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
	return img.AppendContent(buff.Bytes(), 0644, imageModulesDir+"booster.alias")
}
