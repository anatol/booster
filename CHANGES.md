Booster - fast and secure initramfs generator

Release 0.6 (2020-07-20)
  * Add support for full-disk encryption using Yubikey. See https://github.com/anatol/clevis.go/blob/main/clevis-encrypt-yubikey for clevis plugin.
  * Fix poweroff issues with i915 (#86)
  * Add support for root partitions stored at MMC devices (#90)
  * Add support for runit (#92). Runit is an init used at some ditros (e.g. Void Linux)
