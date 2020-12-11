package main

type GeneratorConfig struct {
	Network *struct {
		Dhcp bool `yaml:",omitempty"`

		Ip      string `yaml:",omitempty"` // e.g. 10.0.2.15/24
		Gateway string `yaml:",omitempty"` // e.g. 10.0.2.255
	}
	Universal bool   `yaml:",omitempty"`
	Modules   string `yaml:",omitempty"` // comma separated list of extra modules to add to initramfs
}

const generatorConfigPath = "/etc/booster.yaml"
