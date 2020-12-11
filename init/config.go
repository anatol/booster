package main

type InitConfig struct {
	Network *struct {
		Dhcp bool `yaml:",omitempty"`

		Ip      string `yaml:",omitempty"` // e.g. 10.0.2.15/24
		Gateway string `yaml:",omitempty"` // e.g. 10.0.2.255
	}

	ModuleDependencies map[string][]string `yaml:",omitempty"`
	ModulesForceLoad   []string            `yaml:",omitempty"`
}

const initConfigPath = "/etc/booster.init.yaml"
