package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

// UserConfig is a format for /etc/booster.yaml config that is interface between user and booster generator
type UserConfig struct {
	Network *struct {
		Interfaces string `yaml:",omitempty"` // comma-separated list of interfaces to initialize at early-userspace

		Dhcp bool `yaml:",omitempty"`

		Ip         string `yaml:",omitempty"`            // e.g. 10.0.2.15/24
		Gateway    string `yaml:",omitempty"`            // e.g. 10.0.2.255
		DNSServers string `yaml:"dns_servers,omitempty"` // comma-separated list of ips, e.g. 10.0.1.1,8.8.8.8
	}
	Universal            bool   `yaml:",omitempty"`
	Modules              string `yaml:",omitempty"`                   // comma separated list of extra modules to add to initramfs
	ModulesForceLoad     string `yaml:"modules_force_load,omitempty"` // comma separated list of extra modules to load at the boot time
	Compression          string `yaml:",omitempty"`                   // output file compression
	MountTimeout         string `yaml:"mount_timeout,omitempty"`      // timeout for waiting for the rootfs mounted
	ExtraFiles           string `yaml:"extra_files,omitempty"`        // comma-separated list of files to add to image
	StripBinaries        bool   `yaml:"strip,omitempty"`              // if strip symbols from the binaries, shared libraries and kernel modules
	EnableVirtualConsole bool   `yaml:"vconsole,omitempty"`           // configure virtual console at boot time using config from https://www.freedesktop.org/software/systemd/man/vconsole.conf.html
}

// read user config from the specified file. If file parameter is empty string then "empty" configuration is considered
// (as if empty file is specified).
// once the user config is parsed, flags values are applied on top of it.
func readGeneratorConfig(file string) (*generatorConfig, error) {
	var u UserConfig

	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(data, &u); err != nil {
			return nil, err
		}
		// config sanity check
		if net := u.Network; net != nil {
			if net.Dhcp && (net.Ip != "" || net.Gateway != "") {
				return nil, fmt.Errorf("config: option network.(ip|gateway) cannot be used together with network.dhcp")
			}
		}
	}

	var conf generatorConfig

	// copy user config to generator
	if n := u.Network; n != nil {
		if n.Dhcp {
			conf.networkConfigType = netDhcp
		} else {
			conf.networkConfigType = netStatic
			conf.networkStaticConfig = &networkStaticConfig{
				n.Ip, n.Gateway, n.DNSServers,
			}
		}

		if u.Network.Interfaces != "" {
			// get MAC addresses for the specified interface names
			for _, i := range strings.Split(u.Network.Interfaces, ",") {
				// user can either provide the mac addr itself
				if hwAddr, err := net.ParseMAC(i); err == nil {
					conf.networkActiveInterfaces = append(conf.networkActiveInterfaces, hwAddr)
					continue
				}

				// or a network interface
				ifc, err := net.InterfaceByName(i)
				if err != nil {
					return nil, fmt.Errorf("invalid network interface: %s", i)
				}
				// TODO: or maybe instead of resolving it to MAC address here we should compute predictable interface names
				// in init? See the algorithm https://github.com/systemd/systemd/blob/main/src/udev/udev-builtin-net_id.c
				conf.networkActiveInterfaces = append(conf.networkActiveInterfaces, ifc.HardwareAddr)
			}
		}
	}
	conf.universal = u.Universal || *universal
	if u.Modules != "" {
		conf.modules = strings.Split(u.Modules, ",")
	}
	if u.ModulesForceLoad != "" {
		conf.modulesForceLoad = strings.Split(u.ModulesForceLoad, ",")
	}
	conf.compression = u.Compression
	if u.ExtraFiles != "" {
		conf.extraFiles = strings.Split(u.ExtraFiles, ",")
	}
	if u.MountTimeout != "" {
		timeout, err := time.ParseDuration(u.MountTimeout)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse mount timeout value: %v", err)
		}
		conf.timeout = timeout
	}

	// now check command line flags
	conf.output = *outputFile
	conf.forceOverwrite = *forceOverwriteFile
	conf.initBinary = *initBinary
	if *compression != "" {
		conf.compression = *compression
	}
	if conf.compression == "" {
		conf.compression = "zstd"
	}
	if *kernelVersion != "" {
		conf.kernelVersion = *kernelVersion
	} else {
		ver, err := readKernelVersion()
		if err != nil {
			return nil, err
		}
		conf.kernelVersion = ver
	}
	conf.modulesDir = path.Join("/usr/lib/modules", conf.kernelVersion)
	conf.debug = *debugEnabled
	conf.readDeviceAliases = readDeviceAliases
	conf.readHostModules = readHostModules
	conf.readModprobeOptions = readModprobeOptions
	conf.stripBinaries = u.StripBinaries || *strip
	conf.enableVirtualConsole = u.EnableVirtualConsole
	if conf.enableVirtualConsole {
		conf.vconsolePath = "/etc/vconsole.conf"
		conf.localePath = "/etc/locale.conf"
	}

	return &conf, nil
}

func readKernelVersion() (string, error) {
	// read kernel binary version as
	//     if (argc > 1){
	//        FILE* f = fopen(argv[1], "r");
	//        short offset = 0;
	//        char str[128];
	//        if(f){
	//            fseek(f, 0x20E, SEEK_SET);
	//            fread(&offset, 2, 1, f);
	//            fseek(f, offset + 0x200, SEEK_SET);
	//            fread(str, 128, 1, f);
	//            str[127] = '\0';
	//            printf("%s\n", str);
	//            fclose(f);
	//            return 0;
	//        }else {
	//            return 2;
	//        }
	//    } else {
	//        printf("use: kver [kernel image file]\n");
	//        return 1;
	//    }

	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}
	release := uts.Release
	length := bytes.IndexByte(release[:], 0)
	return string(uts.Release[:length]), nil
}
