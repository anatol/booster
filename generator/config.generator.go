package main

import "time"

type GeneratorConfig struct {
	Network *struct {
		Dhcp bool `yaml:",omitempty"`

		Ip      string `yaml:",omitempty"` // e.g. 10.0.2.15/24
		Gateway string `yaml:",omitempty"` // e.g. 10.0.2.255
	}
	Universal    bool   `yaml:",omitempty"`
	Modules      string `yaml:",omitempty"`              // comma separated list of extra modules to add to initramfs
	Compression  string `yaml:",omitempty"`              // output file compression
	MountTimeout string `yaml:"mount_timeout,omitempty"` // timeout for waiting for the rootfs mounted
}

const generatorConfigPath = "/etc/booster.yaml"
const defaultTimeout = 3 * time.Minute
