module init

go 1.16

require (
	github.com/anatol/clevis.go v0.0.0-20210303074313-5911702bb1fb
	github.com/anatol/devmapper.go v0.0.0-20210322024145-ba6a046aeb3d
	github.com/anatol/luks.go v0.0.0-20210314231502-552c7e4aa186
	github.com/insomniacslk/dhcp v0.0.0-20210315110227-c51060810aaa
	github.com/lestrrat-go/jwx v1.1.5 // indirect
	github.com/s-urbaniak/uevent v1.0.0
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	github.com/yookoala/realpath v1.0.0
	golang.org/x/crypto v0.0.0-20210317152858-513c2a44f670
	golang.org/x/net v0.0.0-20210316092652-d523dce5a7f4 // indirect
	golang.org/x/sys v0.0.0-20210317091845-390168757d9c
	golang.org/x/term v0.0.0-20210317153231-de623e64d2a6 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

// workaround for https://github.com/anatol/booster/issues/22
replace github.com/s-urbaniak/uevent => github.com/stapelberg/uevent v1.0.1-0.20200422145418-40d619f351bf
