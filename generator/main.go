package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime/pprof"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	outputFile         = flag.String("output", "booster.img", "Output initrd file")
	forceOverwriteFile = flag.Bool("force", false, "Overwrite existing initrd file")
	initBinary         = flag.String("initBinary", "/usr/lib/booster/init", "Booster 'init' binary location")
	kernelVersion      = flag.String("kernelVersion", "", "Linux kernel version to generate initramfs for")
	configFile         = flag.String("config", "", "Configuration file path")
	debugEnabled       = flag.Bool("debug", false, "Enable debug output")
	universal          = flag.Bool("universal", false, "Add wide range of modules/tools to allow this image boot at different machines")
	pprofcpu           = flag.String("pprof.cpu", "", "Write cpu profile to file")
)

func debug(format string, v ...interface{}) {
	if *debugEnabled {
		fmt.Printf(format, v...)
	}
}

func main() {
	// TODO: add support for subcommands: build, info (image info like listing)
	flag.Parse()

	if err := generateInitRamfs(); err != nil {
		log.Fatal(err)
	}
}

func generateInitRamfs() error {
	if *pprofcpu != "" {
		f, err := os.Create(*pprofcpu)
		if err != nil {
			log.Fatal(err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}

	if _, err := os.Stat(*outputFile); (err == nil || !os.IsNotExist(err)) && !*forceOverwriteFile {
		return fmt.Errorf("File %v exists, please specify -force if you want to overwrite it", *outputFile)
	}

	if err := readConfig(); err != nil {
		return err
	}

	img, err := NewImage(*outputFile)
	if err != nil {
		return err
	}
	defer img.Cleanup()

	filesToMirror := []string{
		//"/etc/localtime",
	}
	for _, f := range filesToMirror {
		if err := img.AppendFile(f); err != nil {
			return err
		}
	}

	if err := appendInitBinary(img); err != nil {
		return err
	}

	if err := appendModules(img); err != nil {
		return err
	}

	if err := appendInitConfig(img); err != nil {
		return err
	}

	return img.Close()
}

func appendInitBinary(img *Image) error {
	content, err := ioutil.ReadFile(*initBinary)
	if err != nil {
		return err
	}
	return img.AppendContent(content, 0755, "/init")
}

var (
	generatorConfig GeneratorConfig // config from /etc/booster.yaml
	initConfig      InitConfig      // config for init stored to /etc/booster.init.yaml
)

func appendInitConfig(img *Image) error {
	// populate init config from /etc/booster.yaml
	initConfig.Network = generatorConfig.Network

	content, err := yaml.Marshal(initConfig)
	if err != nil {
		return err
	}

	return img.AppendContent(content, 0644, initConfigPath)
}

func readConfig() error {
	var data []byte
	var err error

	if *configFile == "" {
		// if user did not provide filename then check if the default config exists
		data, err = ioutil.ReadFile(generatorConfigPath)
		if os.IsNotExist(err) {
			// if no config present then use the default settings
			return nil
		}
	} else {
		data, err = ioutil.ReadFile(*configFile)
	}
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, &generatorConfig); err != nil {
		return err
	}

	// config sanity check
	if n := generatorConfig.Network; n != nil {
		if n.Dhcp && (n.Ip != "" || n.Gateway != "") {
			return fmt.Errorf("config: option network.(ip|gateway) cannot be used together with network.dhcp")
		}
	}

	return nil
}

func appendModules(img *Image) error {
	kmod, err := NewKmod(generatorConfig.Universal || *universal)
	if err != nil {
		return err
	}
	initConfig.Kernel = kmod.kernelVersion

	modules := []string{
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
		"hid_generic",
		"virtio_pci", "virtio_blk", "virtio_scsi", "virtio_crypto",
	}
	if err := kmod.activateModules(true, modules...); err != nil {
		return err
	}

	if len(generatorConfig.Modules) > 0 {
		mods := strings.Split(generatorConfig.Modules, ",")
		if err := kmod.activateModules(false, mods...); err != nil {
			return err
		}
	}

	// cbc module is a hard requirement for "encrypted_keys"
	// https://github.com/torvalds/linux/blob/master/security/keys/encrypted-keys/encrypted.c#L42
	kmod.addExtraDep("encrypted_keys", "cbc")

	if err := kmod.resolveDependencies(); err != nil {
		return err
	}
	if err := kmod.addModulesToImage(img); err != nil {
		return err
	}
	initConfig.ModuleDependencies = kmod.dependencies

	// collect aliases for required modules only
	aliases, err := kmod.filterAliasesForRequiredModules()
	if err != nil {
		return err
	}
	if err := appendAliasesFile(img, aliases, kmod.dir); err != nil {
		return err
	}

	for m := range kmod.hostModules {
		if !kmod.requiredModules[m] {
			debug("ignoring loaded module '%s'\n", m)
		}
	}

	//initConfig.ModulesForceLoad = kmod.forceLoadModules()

	return nil
}

func appendAliasesFile(img *Image, aliases []alias, dir string) error {
	var buff bytes.Buffer
	for _, a := range aliases {
		buff.WriteString(a.pattern)
		buff.WriteString(" ")
		buff.WriteString(a.module)
		buff.WriteString("\n")
	}
	if err := img.AppendContent(buff.Bytes(), 0644, dir+"/booster.alias"); err != nil {
		return err
	}
	return nil
}
