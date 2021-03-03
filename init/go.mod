module init

go 1.16

require (
	github.com/anatol/clevis.go v0.0.0-20210303074313-5911702bb1fb
	github.com/anatol/luks.go v0.0.0-20210303190043-bd05d044c4a2
	github.com/insomniacslk/dhcp v0.0.0-20210120172423-cc9239ac6294
	github.com/s-urbaniak/uevent v1.0.0
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	github.com/yookoala/realpath v1.0.0
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
	golang.org/x/sys v0.0.0-20210303074136-134d130e1a04
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

// workaround for https://github.com/anatol/booster/issues/22
replace github.com/s-urbaniak/uevent => github.com/stapelberg/uevent v1.0.1-0.20200422145418-40d619f351bf
