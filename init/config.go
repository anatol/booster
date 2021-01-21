package main

type InitConfig struct {
	Network *struct {
		Dhcp bool `yaml:",omitempty"`

		Ip      string `yaml:",omitempty"` // e.g. 10.0.2.15/24
		Gateway string `yaml:",omitempty"` // e.g. 10.0.2.255
	}

	ModuleDependencies map[string][]string `yaml:",omitempty"`
	ModulesForceLoad   []string            `yaml:",omitempty"`
	Kernel             string              `yaml:",omitempty"` // kernel version this image was built for
	MountTimeout       int                 `yaml:",omitempty"` // mount timeout in seconds
}

const initConfigPath = "/etc/booster.init.yaml"
