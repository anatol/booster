package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

// validateAuthorizedKeys mirrors init/ssh.go:parseAuthorizedKeys so a missing
// or garbage authorized_keys file fails the build loudly instead of silently
// disabling the SSH server at boot — the same "fail at build, not as a
// locked-out boot" posture as the crypttab unreadable-warning (commit
// cebca35). Keep this in sync with the init-side parser.
func validateAuthorizedKeys(data []byte) error {
	rest := data
	n := 0
	for len(bytes.TrimSpace(rest)) > 0 {
		_, _, _, next, err := gossh.ParseAuthorizedKey(rest)
		if err != nil {
			return fmt.Errorf("no parseable SSH public key found: %v", err)
		}
		n++
		rest = next
	}
	if n == 0 {
		return fmt.Errorf("contains no SSH public keys")
	}
	return nil
}

// UserConfig is a format for /etc/booster.yaml config that is interface between user and booster generator
type UserConfig struct {
	Network *struct {
		Interfaces string `yaml:",omitempty"` // comma-separated list of interfaces to initialize at early-userspace

		Dhcp bool `yaml:",omitempty"`

		IP         string `yaml:",omitempty"`            // e.g. 10.0.2.15/24
		Gateway    string `yaml:",omitempty"`            // e.g. 10.0.2.255
		DNSServers string `yaml:"dns_servers,omitempty"` // comma-separated list of ips, e.g. 10.0.1.1,8.8.8.8

		// SSH-based remote LUKS unlock. Both SshHostKey and SshAuthorizedKeys
		// must point to readable files at build time; their contents are
		// embedded into the initramfs config. Setting SshAuthorizedKeys
		// enables the SSH server during early boot.
		SshHostKey        string `yaml:"ssh_host_key,omitempty"`        // path to OpenSSH- or PEM-encoded host private key
		SshAuthorizedKeys string `yaml:"ssh_authorized_keys,omitempty"` // path to authorized_keys file
		SshListen         string `yaml:"ssh_listen,omitempty"`          // listen address, default :22
	}
	Universal            bool   `yaml:",omitempty"`
	Modules              string `yaml:",omitempty"`                   // comma separated list of extra modules to add to initramfs
	ModulesForceLoad     string `yaml:"modules_force_load,omitempty"` // comma separated list of extra modules to load at the boot time
	AppendAllModAliases  bool   `yaml:"append_all_modaliases,omitempty"`
	Compression          string `yaml:",omitempty"`              // output file compression
	MountTimeout         string `yaml:"mount_timeout,omitempty"` // timeout for waiting for the rootfs mounted
	ExtraFiles           string `yaml:"extra_files,omitempty"`   // comma-separated list of files to add to image
	StripBinaries        bool   `yaml:"strip,omitempty"`         // if strip symbols from the binaries, shared libraries and kernel modules
	EnableVirtualConsole bool   `yaml:"vconsole,omitempty"`      // configure virtual console at boot time using config from https://www.freedesktop.org/software/systemd/man/vconsole.conf.html
	EnableLVM            bool   `yaml:"enable_lvm"`
	EnableMdraid         bool   `yaml:"enable_mdraid"`
	MdraidConfigPath     string `yaml:"mdraid_config_path"`
	EnableZfs            bool   `yaml:"enable_zfs"`
	ZfsImportParams      string `yaml:"zfs_import_params"`
	ZfsCachePath         string `yaml:"zfs_cache_path"`
	EnablePlymouth       bool   `yaml:"enable_plymouth"`
	CrypttabPath         string `yaml:"crypttab_path,omitempty"` // path to crypttab file, defaults to /etc/crypttab
	EnableFido2          bool   `yaml:"enable_fido2"`
	TokenTimeout         string `yaml:"token_timeout,omitempty"` // device-level keyboard-fallback timer (e.g. 30s); applies in both modes; global default, overridable by crypttab/cmdline
	PinDelay             string `yaml:"pin_delay,omitempty"`     // concurrent-mode only: hold an interactive PIN prompt (TPM2-PIN/FIDO2-PIN) this long (e.g. 3s) so a parallel non-interactive token can win first; default unset (off)
	PasswordEcho         string `yaml:"password_echo,omitempty"` // ordered comma-separated list of prompt echo modes; first = startup mode, Tab cycles the list; default asterisks,silent,plaintext

	// SerializeTokens opts out of booster's token concurrency: tokens are
	// tried one at a time in ID order. The per-type timeouts are scoped here
	// because they only take effect in serialize mode.
	SerializeTokens *struct {
		Enabled       bool   `yaml:",omitempty"`               // process LUKS tokens one at a time instead of concurrently
		ClevisTimeout string `yaml:"clevis_timeout,omitempty"` // per-token bound for clevis (e.g. 45s); default 45s
		Tpm2Timeout   string `yaml:"tpm2_timeout,omitempty"`   // per-token bound for non-PIN systemd-tpm2 (e.g. 15s); default 15s
		Fido2Timeout  string `yaml:"fido2_timeout,omitempty"`  // per-token bound for non-PIN systemd-fido2 (e.g. 30s); default 30s
	} `yaml:"serialize_tokens,omitempty"`
}

func parseCommaList(raw string) []string {
	var values []string
	for value := range strings.SplitSeq(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	return values
}

// validatePasswordEcho checks a password_echo value: an ordered,
// comma-separated list of unique prompt echo modes. The first entry is the
// startup mode and Tab cycles through the list in order (a single entry pins
// the prompt). Empty selects the default cycle asterisks,silent,plaintext.
// init/console_input.go parses the same syntax at boot time.
func validatePasswordEcho(val string) error {
	if val == "" {
		return nil
	}
	seen := make(map[string]bool)
	for mode := range strings.SplitSeq(val, ",") {
		mode = strings.TrimSpace(mode)
		switch mode {
		case "asterisks", "silent", "plaintext":
		default:
			return fmt.Errorf("config: invalid password_echo mode %q, expected a comma-separated list of: asterisks, silent, plaintext", mode)
		}
		if seen[mode] {
			return fmt.Errorf("config: password_echo lists mode %q twice", mode)
		}
		seen[mode] = true
	}
	return nil
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
		if n := u.Network; n != nil {
			if n.Dhcp && (n.IP != "" || n.Gateway != "") {
				return nil, fmt.Errorf("config: option network.(ip|gateway) cannot be used together with network.dhcp")
			}
			if n.SshHostKey != "" || n.SshAuthorizedKeys != "" {
				if n.SshHostKey == "" || n.SshAuthorizedKeys == "" {
					return nil, fmt.Errorf("config: network.ssh_host_key and network.ssh_authorized_keys must both be set")
				}
				if !n.Dhcp && n.IP == "" {
					return nil, fmt.Errorf("config: network.ssh_* requires network.dhcp or network.ip")
				}
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
				ip:         n.IP,
				gateway:    n.Gateway,
				dnsServers: strings.Join(parseCommaList(n.DNSServers), ","),
			}
		}

		// Resolve interface selectors to MAC addresses at build time so the
		// initramfs is independent from naming policy inside early userspace.
		for _, iface := range parseCommaList(u.Network.Interfaces) {
			if hwAddr, err := net.ParseMAC(iface); err == nil {
				conf.networkActiveInterfaces = append(conf.networkActiveInterfaces, hwAddr)
				continue
			}

			ifc, err := net.InterfaceByName(iface)
			if err != nil {
				return nil, fmt.Errorf("invalid network interface: %s", iface)
			}
			// TODO: or maybe instead of resolving it to MAC address here we should compute predictable interface names
			// in init? See the algorithm https://github.com/systemd/systemd/blob/main/src/udev/udev-builtin-net_id.c
			conf.networkActiveInterfaces = append(conf.networkActiveInterfaces, ifc.HardwareAddr)
		}

		if n.SshAuthorizedKeys != "" {
			// The host private key is embedded verbatim into the
			// (unencrypted) initramfs by design — it must be available
			// before any disk is unlocked. A group/other-accessible source
			// key is almost always operator error; OpenSSH itself refuses
			// loose private-key perms. Warn (don't fail) at build time.
			if fi, err := os.Stat(n.SshHostKey); err == nil && fi.Mode().Perm()&0o077 != 0 {
				warning("network.ssh_host_key: %s is accessible by group/other (mode %#o) — this SSH host private key gets embedded in the initramfs; tighten it to 0600", n.SshHostKey, fi.Mode().Perm())
			}
			hostKey, err := os.ReadFile(n.SshHostKey)
			if err != nil {
				return nil, fmt.Errorf("network.ssh_host_key: %v", err)
			}
			authKeys, err := os.ReadFile(n.SshAuthorizedKeys)
			if err != nil {
				return nil, fmt.Errorf("network.ssh_authorized_keys: %v", err)
			}
			if err := validateAuthorizedKeys(authKeys); err != nil {
				return nil, fmt.Errorf("network.ssh_authorized_keys: %s %v", n.SshAuthorizedKeys, err)
			}
			conf.sshHostKey = string(hostKey)
			conf.sshAuthorizedKeys = string(authKeys)
			conf.sshListen = n.SshListen
		}
	}
	conf.universal = u.Universal || opts.BuildCommand.Universal
	conf.modules = parseCommaList(u.Modules)
	conf.modulesForceLoad = parseCommaList(u.ModulesForceLoad)
	conf.compression = u.Compression
	conf.extraFiles = parseCommaList(u.ExtraFiles)
	if u.MountTimeout != "" {
		timeout, err := time.ParseDuration(u.MountTimeout)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse mount timeout value: %v", err)
		}
		conf.timeout = timeout
	}

	// now check command line flags
	conf.output = opts.BuildCommand.Args.Output
	conf.forceOverwrite = opts.BuildCommand.Force
	conf.initBinary = opts.BuildCommand.InitBinary
	if opts.BuildCommand.Compression != "" {
		conf.compression = opts.BuildCommand.Compression
	}
	if conf.compression == "" {
		conf.compression = "zstd"
	}
	if opts.BuildCommand.KernelVersion != "" {
		conf.kernelVersion = opts.BuildCommand.KernelVersion
	} else {
		ver, err := readKernelVersion()
		if err != nil {
			return nil, err
		}
		conf.kernelVersion = ver
	}
	if opts.BuildCommand.ModulesDirectory != "" {
		conf.modulesDir = opts.BuildCommand.ModulesDirectory
	} else {
		conf.modulesDir = filepath.Join(imageModulesDir, conf.kernelVersion)
	}
	conf.debug = opts.Verbose
	conf.readDeviceAliases = readDeviceAliases
	conf.readHostModules = readHostModules
	conf.readModprobeOptions = readModprobeOptions
	conf.appendAllModAliases = u.AppendAllModAliases
	conf.stripBinaries = u.StripBinaries || opts.BuildCommand.Strip
	conf.enableLVM = u.EnableLVM
	conf.enableMdraid = u.EnableMdraid
	conf.mdraidConfigPath = u.MdraidConfigPath
	conf.enableZfs = u.EnableZfs
	conf.zfsImportParams = u.ZfsImportParams
	conf.zfsCachePath = u.ZfsCachePath
	conf.enablePlymouth = u.EnablePlymouth
	conf.enableVirtualConsole = u.EnableVirtualConsole
	if conf.enableVirtualConsole {
		conf.vconsolePath = "/etc/vconsole.conf"
		conf.localePath = "/etc/locale.conf"
	}
	conf.crypttabFile = opts.BuildCommand.CrypttabFile
	if conf.crypttabFile == "" {
		conf.crypttabFile = u.CrypttabPath
	}
	conf.enableFido2 = u.EnableFido2
	if err := validatePasswordEcho(u.PasswordEcho); err != nil {
		return nil, err
	}
	conf.passwordEcho = u.PasswordEcho
	var clevisT, tpm2T, fido2T string
	if st := u.SerializeTokens; st != nil {
		conf.serializeTokens = st.Enabled
		clevisT, tpm2T, fido2T = st.ClevisTimeout, st.Tpm2Timeout, st.Fido2Timeout
	}
	for _, f := range []struct {
		name string
		val  string
		dst  *int
	}{
		{"token_timeout", u.TokenTimeout, &conf.tokenTimeout},
		{"pin_delay", u.PinDelay, &conf.pinDelay},
		{"serialize_tokens.clevis_timeout", clevisT, &conf.clevisTimeout},
		{"serialize_tokens.tpm2_timeout", tpm2T, &conf.tpm2Timeout},
		{"serialize_tokens.fido2_timeout", fido2T, &conf.fido2Timeout},
	} {
		if f.val == "" {
			continue
		}
		d, err := time.ParseDuration(f.val)
		if err != nil {
			return nil, fmt.Errorf("config: unable to parse %s value %q: %v", f.name, f.val, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("config: %s must be positive, got %q", f.name, f.val)
		}
		// Stored as whole seconds (0 means "unset" downstream), so a positive
		// sub-second value would silently truncate to 0 and disable the option.
		if d < time.Second {
			return nil, fmt.Errorf("config: %s must be at least 1s, got %q", f.name, f.val)
		}
		*f.dst = int(d.Seconds())
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
