Booster - fast and secure initramfs generator

Release 0.9 (2022 Aug 24)
  * Load 'efivarfs' before mounting the filesystem (#149)
  * generator: add drivers/ata to the list of default modules (#149)
  * Recover panic in udev goroutine (#22 #31 #153)
  * Always use path/filepath pkg for operating systems paths
  * Adding a more advanced parser to allow handling more complex cmdline parameters (#73)
  * Add zfs support (#33)
  * Print NIC hardware address (#155)
  * Replace github.com/s-urbaniak/uevent.go with github.com/pilebones/go-udev/netlink (#155)
  * Add support to allow unlocking a luks volume by keyfile (#37)

Release 0.8 (2022 May 6)
  * Add `booster.log` boot parameter that replaces and extends the functionality of `booster.debug`. `booster.debug` is marked as deprecated.
  * `booster.disable_concurrent_module_loading` boot parameter has been removed. This parameter has been used as a safety net if concurrent module loading does not work properly. Concurrent module loading has been thoroughly tested and found no major issues. Drop the unneeded parameter.
  * Fix “too many open files” booster generator error (#76)
  * Process udev and block scanning concurrently to increase the level of parallelism and reduce boot time.
  * Refactor `booster` CLI. Add `booster build`, `booster ls`, `booster cat`, `booster unpack` subcommand to build/inspect initramfs images. This functionality is roughly equivalent to `lsinitcpio` (#11)
  * Add sdhci_acpi to the list of modules required for eMMC (#90)
  * Handle `init=` kernel parameter (#115)
  * Handle devices with 4K sectors (#119)
  * Fix GPU drivers loading (#120)
  * Handle FAT16/FAT32 partitions correctly
  * Add support for partitions used for hibernation
  * Add uas to the list of default modules (#121)
  * Handle multiple luks mappings in the kernel command line (#124)
  * Handle firmware files compressed with xz (#127)
  * Handle non-/usr filesystem hierarchy (such as used by Alpine Linux)
  * Add /usr/lib64 to the list of elf directories to handle Fedora Linux (#137)
  * Handle HWPATH=xxx device reference in boot parameters (#112)
  * Handle WWID=XXX device reference in boot parameters (#111)
  * (Experimental) Implement remote unlock functionality using Tang protocol. (#24)
  * Unconditionally enable local echo for emergency shell (#144)
  * Don't error-out if `/etc/locale.conf` doesn't exist
  * Lookup executable under `$PATH`

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
