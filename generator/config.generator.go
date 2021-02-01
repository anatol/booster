package main

import "time"

type GeneratorConfig struct {
	Network *struct {
		Dhcp bool `yaml:",omitempty"`

		Ip         string `yaml:",omitempty"`            // e.g. 10.0.2.15/24
		Gateway    string `yaml:",omitempty"`            // e.g. 10.0.2.255
		DNSServers string `yaml:"dns_servers,omitempty"` // comma-separated list of ips, e.g. 10.0.1.1,8.8.8.8
	}
	Universal    bool   `yaml:",omitempty"`
	Modules      string `yaml:",omitempty"`              // comma separated list of extra modules to add to initramfs
	Compression  string `yaml:",omitempty"`              // output file compression
	MountTimeout string `yaml:"mount_timeout,omitempty"` // timeout for waiting for the rootfs mounted
	ExtraFiles   string `yaml:"extra_files,omitempty"`   // comma-separated list of files to add to image
}

const generatorConfigPath = "/etc/booster.yaml"
const defaultTimeout = 3 * time.Minute
