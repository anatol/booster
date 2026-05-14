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
	SerializeTokens        bool                `yaml:",omitempty"` // dispatch LUKS tokens serially instead of concurrently; default false
	TokenTimeout           int                 `yaml:",omitempty"` // device-level keyboard-fallback timer in seconds; 0 = unset (crypttab/cmdline or derived default applies)
	PinDelay               int                 `yaml:",omitempty"` // concurrent-mode PIN-prompt pre-delay in seconds so a parallel non-interactive token can win first; 0 = off
	ClevisTimeout          int                 `yaml:",omitempty"` // serialize-mode per-token bound for clevis tokens in seconds; 0 = default 45
	Tpm2Timeout            int                 `yaml:",omitempty"` // serialize-mode per-token bound for non-PIN systemd-tpm2 tokens in seconds; 0 = default 15
	Fido2Timeout           int                 `yaml:",omitempty"` // serialize-mode per-token bound for non-PIN systemd-fido2 tokens in seconds; 0 = default 30
}

const initConfigPath = "/etc/booster.init.yaml"
