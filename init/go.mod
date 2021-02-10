module init

go 1.15

require (
	github.com/anatol/clevis.go v0.0.0-20210206190044-7ab6db3fd9c2
	github.com/anatol/luks.go v0.0.0-20210208171804-d44366ded8ec
	github.com/insomniacslk/dhcp v0.0.0-20210120172423-cc9239ac6294
	github.com/s-urbaniak/uevent v1.0.0
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	github.com/yookoala/realpath v1.0.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/net v0.0.0-20210119194325-5f4716e94777 // indirect
	golang.org/x/sys v0.0.0-20210124154548-22da62e12c0c
	golang.org/x/term v0.0.0-20201210144234-2321bbc49cbf // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

// workaround for https://github.com/anatol/booster/issues/22
replace github.com/s-urbaniak/uevent => github.com/stapelberg/uevent v1.0.1-0.20200422145418-40d619f351bf
