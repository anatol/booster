Booster - fast and secure initramfs generator

Release 0.7 (2021 Oct 07)
  * Fixed a race condition with mounting RAID5 volumes. (#97)
  * Added support for custom encryption blocks. With cryptsetup 2.4.0 LUKS partitions use large encryption blocks of size 4096 bytes.
  * Add support of sha512 and blake2b/blake2s hashes to pbkdf2 KDF.
  * Add support of FIDO2 and TPM2 tokens enrolled with systemd-cryptenroll. (#96)
  * Booster now waits till `modules_force_load` modules are fully loaded before switching to userspace. (#103)
  * Add compatibility support for proprietary drivers. It makes possible to load `amdgpu` at boot time. (#45 #104)
  * nvme and usb could be used as root devices now. (#94 #95)
  * HID drivers `kernel/drivers/hid` are checked by default now. This improves keyboard drivers detection and fixes numerous keyboard issues at the boot time. (#80)
  * By default network modules removed from the image if network is disabled in config. This reduces size of the generated image.
  * Improves [Discoverable Partitions Specification](https://systemd.io/DISCOVERABLE_PARTITIONS/) compliance.
    Booster makes sure that only root from active ESP disk is mounted; booster is able to detect LUKS partitions and mount them; booster takes GPT flags into account. (#98)
  * It is possible to specify a LUKS partitions as `root=` directly. In this case the LUKS partition is unlocked and mounted as `/dev/mapper/root`.

Release 0.6 (2021 Jul 20)
  * Add support for full-disk encryption using Yubikey. See https://github.com/anatol/clevis.go/blob/main/clevis-encrypt-yubikey for clevis plugin.
  * Fix poweroff issues with i915 (#86)
  * Add support for root partitions stored at MMC devices (#90)
  * Add support for runit (#92). Runit is an init used at some ditros (e.g. Void Linux)
