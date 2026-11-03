package main

import "net"

type InitNetworkConfig struct {
	Interfaces []net.HardwareAddr `yaml:",omitempty"` // list of active interfaces to use

	Dhcp bool `yaml:",omitempty"`

	IP         string `yaml:",omitempty"`            // e.g. 10.0.2.15/24
	Gateway    string `yaml:",omitempty"`            // e.g. 10.0.2.255
	DNSServers string `yaml:"dns_servers,omitempty"` // comma-separated list of ips, e.g. 10.0.1.1,8.8.8.8

	// SshHostKey is the OpenSSH- or PEM-encoded SSH server private key
	// (gossh.ParsePrivateKey accepts both). SshAuthorizedKeys is the
	// contents of an authorized_keys file. SSH remote unlock is enabled
	// when both are non-empty.
	SshHostKey        string `yaml:"ssh_host_key,omitempty"`
	SshAuthorizedKeys string `yaml:"ssh_authorized_keys,omitempty"`
	SshListen         string `yaml:"ssh_listen,omitempty"`
}

// InitBluetoothConfig lists the paired keyboards init reconnects before any
// disk is unlocked, grouped by the controller they are bonded to. Keys and
// SDP records are hex strings in the byte order BlueZ stores them in.
type InitBluetoothConfig struct {
	Adapters []BluetoothAdapter `yaml:",omitempty"`
}

type BluetoothAdapter struct {
	Address string            `yaml:",omitempty"` // controller's public address, e.g. 00:1A:7D:DA:71:13
	Devices []BluetoothDevice `yaml:",omitempty"`
}

type BluetoothDevice struct {
	Address string `yaml:",omitempty"` // identity address of the keyboard
	Name    string `yaml:",omitempty"`
	Vendor  uint16 `yaml:",omitempty"` // BlueZ's [DeviceID]; zero when it has none
	Product uint16 `yaml:",omitempty"`
	Version uint16 `yaml:",omitempty"`

	// Exactly one of the two is set: the transport the keyboard is bonded over.
	Classic *BluetoothClassic `yaml:",omitempty"`
	LE      *BluetoothLE      `yaml:"le,omitempty"`
}

// BluetoothClassic is a keyboard bonded over BR/EDR, driven by the kernel's HIDP.
type BluetoothClassic struct {
	LinkKey     string   `yaml:"link_key"`
	LinkKeyType uint8    `yaml:"link_key_type"`
	PINLength   uint8    `yaml:"pin_length,omitempty"`
	SDPRecords  []string `yaml:"sdp_records,omitempty"` // BlueZ's cached SDP records; none means init asks the keyboard
}

// BluetoothLE is a keyboard bonded over LE, driven by booster's HID-over-GATT client.
type BluetoothLE struct {
	AddressType          string `yaml:"address_type"`                     // public or static
	LongTermKey          string `yaml:"long_term_key"`                    // the key this host encrypts with as central
	Authenticated        uint8  `yaml:"authenticated,omitempty"`          // BlueZ's Authenticated=, which is the mgmt LTK type
	EncSize              uint8  `yaml:"enc_size"`                         // encryption key size in bytes
	EDiv                 uint16 `yaml:"ediv,omitempty"`                   // legacy pairing only, zero for LE Secure Connections
	Rand                 uint64 `yaml:"rand,omitempty"`                   // legacy pairing only, zero for LE Secure Connections
	IdentityResolvingKey string `yaml:"identity_resolving_key,omitempty"` // resolves the keyboard's private addresses
}

type VirtualConsole struct {
	KeymapFile      string `yaml:",omitempty"`
	Utf             bool   `yaml:",omitempty"`
	FontFile        string `yaml:",omitempty"`
	FontMapFile     string `yaml:",omitempty"`
	FontUnicodeFile string `yaml:",omitempty"`
}

type InitConfig struct {
	Network                *InitNetworkConfig  `yaml:",omitempty"`
	ModuleDependencies     map[string][]string `yaml:",omitempty"`
	ModulePostDependencies map[string][]string `yaml:",omitempty"`
	ModulesForceLoad       []string            `yaml:",omitempty"`
	ModprobeOptions        map[string]string   `yaml:",omitempty"`
	BuiltinModules         set                 `yaml:",omitempty"`
	Kernel                 string              `yaml:",omitempty"` // kernel version this image was built for
	MountTimeout           int                 `yaml:",omitempty"` // mount timeout in seconds
	VirtualConsole         *VirtualConsole     `yaml:",omitempty"`
	EnableLVM              bool                `yaml:",omitempty"`
	EnableMdraid           bool                `yaml:",omitempty"`
	EnableZfs              bool                `yaml:",omitempty"`
	ZfsImportParams        string              `yaml:",omitempty"` // TODO: remove it
	EnablePlymouth         bool                `yaml:",omitempty"`
	SerializeTokens        bool                `yaml:",omitempty"`                         // dispatch LUKS tokens serially instead of concurrently; default false
	TokenTimeout           int                 `yaml:",omitempty"`                         // device-level keyboard-fallback timer in seconds; 0 = unset (crypttab/cmdline or derived default applies)
	PinDelay               int                 `yaml:",omitempty"`                         // concurrent-mode PIN-prompt pre-delay in seconds so a parallel non-interactive token can win first; 0 = off
	ClevisTimeout          int                 `yaml:",omitempty"`                         // serialize-mode per-token bound for clevis tokens in seconds; 0 = default 45
	Tpm2Timeout            int                 `yaml:",omitempty"`                         // serialize-mode per-token bound for non-PIN systemd-tpm2 tokens in seconds; 0 = default 15
	Fido2Timeout           int                 `yaml:",omitempty"`                         // serialize-mode per-token bound for non-PIN systemd-fido2 tokens in seconds; 0 = default 30
	PasswordEcho           string              `yaml:"password_echo,omitempty"`            // ordered comma-separated echo-mode cycle; first entry = startup mode; validated by the generator
	EmergencyShellPassword string              `yaml:"emergency_shell_password,omitempty"` // argon2id PHC; gates the emergency shell

	Bluetooth *InitBluetoothConfig `yaml:",omitempty"` // paired keyboards to reconnect before any disk is unlocked
}

const initConfigPath = "/etc/booster.init.yaml"
