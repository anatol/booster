booster(1) -- fast and secure initramfs generator
=================================================

## DESCRIPTION
**Booster** is a tool to create initramfs images needed at the early stage of Linux boot process. Booster is made with speed and full disk encryption use-case in mind.

Booster advantages:

 * Fast image build time and fast boot time.
 * Out-of-box support for LUKS-based full disk encryption setup.
 * Clevis style data binding. The encrypted filesystem can be bound to TPM2 chip or to a network service. This helps to unlock the drive automatically but only if the TPM2/network service presents.
 * Easy to configure.
 * Automatic host configuration discovery. This helps to create minimalistic images specific for the current host.

## CONFIG FILE
**booster** generator config file is located at `/etc/booster.yaml`. Here is a sample config file:

    network:
      interfaces: enp0s31f2,2e:1d:61:30:a3:63
      dhcp: on
      # either dhcp above or static configuration below can be used
      ip: 10.0.2.15/24
      gateway: 10.0.2.255
      dns_servers: 192.168.1.1,8.8.8.8
    universal: false
    modules: nvidia,kernel/sound/usb/
    compression: zstd
    mount_timeout: 5m6s
    strip: true
    extra_files: vim,/usr/share/vim/vim82/,fsck,fsck.ext4
    vconsole: true

  * `network` node, if presents, initializes network at the boot time. It is needed if mounting a root fs requires access to the network (e.g. in case of Tang binding).
    The network can be either configured dynamically with DHCPv4 or statically within this config. In the former case `dhcp` is set to `on`.
    In the latter case the config allows to specify `ip` - the machine IP address and its network mask, `gateway` - default gateway, `dns_servers` - comma-separated list of DNS servers.
    The `network` node also accepts `interfaces` property - a comma-separated list of network interfaces (specified either with name or MAC address) to enable at the boot time.
    Network names like `enp0s31f6` get resolved to MAC addresses at generation time and then passed to init.
    If `interfaces` node is not specified then all the interfaces activated at boot.

  * `universal` is a boolean flag that tells booster to generate a universal image. By default booster generates a host-specific image that includes kernel modules used at the current host. For example if the host does not have a TPM2 chip then tpm modules are ignored. Universal image includes many kernel modules and tools that might be needed at a broad range of hardware configurations.

  * `modules` is a comma-separates list of extra modules to add to the generated image. One can use a module name or a path relative to the modules dir (/usr/lib/modules/$KERNEL_VERSION). If the path ends with slash symbol (/) then it considered a directory and all modules from this directory needs to be added recursively. booster also takes modules dependencies into account, all dependencies of the specified modules will be added to the image as well.

  * `compression` is a flag that specifies compression for the output initramfs file. Currently supported algorithms are "zstd", "gzip", "xz", "lz4", "none". If no option specified then "zstd" is used as a default compression.

  * `mount_timeout` timeout for waiting for root filesystem to appear. The field format is a decimal number and then unit number. Valid units are "s", "m", "h". If no value specified then default timeout (3 minutes) is used. To disable the timeout completely specify "0s".

  * `strip` is a boolean flag that enables ELF files stripping before adding it to the image. Binaries, shared libraries and kernel modules are examples of ELF files that get processed with strip.

  * `extra_files` is a comma-separated list of extra files to add to the image. If an item starts with slash ("/") then it considered an absolute path. Otherwise it is a path relative to /usr/bin. If the item is a directory then its content is added recursively. There are a few special cases:
       * adding `busybox` to the image enables emergency shell in case of a panic during the boot process.
       * adding `fsck` enables boot time filesystem check. It also requires filesystem specific binary called `fsck.$rootfstype` to be added to the image. Filesystems are corrected automatically and if it fails then boot stops and it is responsibily of the user to fix the root filesystem.

  * `vconsole` is a flag that enables early-user console configuration. If it set to `true` then booster reads configuration from `/etc/vconsole.conf` and `/etc/locale.conf` and adds required keymap and fonts to the generated image.
    following config properties are taken into account: `KEYMAP`, `KEYMAP_TOGGLE`, `FONT`, `FONT_MAP`, `FONT_UNIMAP`. See also [man vconsole.conf](https://man.archlinux.org/man/vconsole.conf.5.en).

## COMMAND-LINE FLAGS
  `booster` command accepts following flags:

  * `-config` config file to use. Default value is `/etc/booster.yaml`.
  * `-universal` generate a universal image
  * `-kernelVersion` use modules for the given kernel version. If the flag is not specified then the current kernel is used (as reported by "uname -r").
  * `-output` output file, by default booster.img used
  * `-compression` output file compression. Currently supported compression algorithms are "zstd" (default), "gzip" and "none".
  * `-strip` strip ELF files (binaries, shared libraries and kernel modules) before adding it to the image
  * `-force` overwrite output file if it exists

## BOOT TIME KERNEL PARAMETERS
Some parts of booster boot functionality can be modified with kernel boot parameters. These parameters are usually set through bootloader config. Booster boot uses following kernel parameters:

 * `root=($PATH|UUID=$UUID|LABEL=$LABEL)` root device. It can be specified as a path to the block device (e.g. root=/dev/sda) or with filesystem UUID (e.g. root=UUID=fd59d06d-ffa8-473b-94f0-6584cb2b6665, pay atenntion that it does not contain any quotes) or with filesystem label (e.g. root=LABEL=rootlabel, pay attention that label does not contain any quotes or whitespaces).
 * `rootfstype=$TYPE` (e.g. rootfstype=ext4). By default booster tries to detect the root filesystem type. But if the autodetection does not work then this kernel parameter is useful. Also please file a ticket so we can improve the code that detects filetypes.
 * `rootflags=$OPTIONS` mount options for the root filesystem, e.g. rootflags=user_xattr,nobarrier.
 * `rd.luks.uuid=$UUID` UUID of the LUKS partition where the root partition is enclosed. booster will try to unlock this LUKS device.
 * `rd.luks.name=$UUID=$NAME` similar to rd.luks.uuid parameter but also specifies the name used for the LUKS device opening.
 * `rd.luks.options=opt1,opt2` a comma-separated lists of LUKS flags. Supported options are `discard`, `same-cpu-crypt`, `submit-from-crypt-cpus`, `no-read-workqueue`, `no-write-workqueue`.
    Note that booster also supports LUKS v2 persistent flags stored with the partition metadata. Any command-line options are added on top of the persistent flags.
 * `booster.debug=1` enable booster debug output. It is printed to console at the boot time. This feature might be useful to debug booster issues.
 * `quiet` option is opposite of `booster.debug` and reduces verbosity of the tool. It hides boot-time booster warnings. This option is ignored if `booster.debug` is set.

## DEBUGGING
If you have a problem with booster boot tool you can enable debug mode to get more
information about what is going on. Just add `booster.debug=1` kernel parameter and booster
provide additional logs.

## EXAMPLES
Create an initramfs file specific for the current kernel/host. The output file is booster.img:

    $ booster

The same as above but output image to /tmp/foobar.img:

    $ booster /tmp/foobar.img

Create an universal image with many modules (such as SATA/TPM/NVME/... drivers) included:

    $ booster -universal

Create an initramfs for kernel version 5.4.91-1-lts and copy it to /boot/booster-lts.img:

    $ booster -kernelVersion 5.4.91-1-lts -output /boot/booster-lts.img

Here is a `systemd-boot` configuration stored at /boot/loader/entries/booster.conf. In this example e122d09e-87a9-4b35-83f7-2592ef40cefa is a UUID for the LUKS partition and 08684949-bcbb-47bb-1c17-089aaa59e17e is a UUID for the encrypted filesystem (e.g. ext4). Please refer for your bootloader documentation for more info about its configuration.

    title Linux with Booster
    linux /vmlinuz-linux
    initrd /booster-linux.img
    options rd.luks.uuid=e122d09e-87a9-4b35-83f7-2592ef40cefa root=UUID=08684949-bcbb-47bb-1c17-089aaa59e17e rw

## COPYRIGHT
Booster is Copyright (C) 2020 Anatol Pomazau <http://github.com/anatol>

## SEE ALSO
Project homepage <https://github.com/anatol/booster>
