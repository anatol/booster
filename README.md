# Booster - fast and secure initramfs generator

![Booster initramfs generator](docs/booster.png)

Initramfs is a specially crafted small root filesystem that mounted at the early stages of Linux OS boot process.
This initramfs among other things is responsible for unlocking encrypted partitions and mounting it as a root filesystem.

Booster is a tool to create such early boot images. Booster is made with speed and full disk encryption use-case in mind.

Booster advantages:
 * Fast image build time and fast boot time.
 * Out-of-box support for full disk encryption setup.
 * [Clevis](https://github.com/latchset/clevis/) style data binding. The encrypted filesystem can be bound
   to TPM2 chip or to a network service. This helps to unlock the drive automatically but only if the TPM2/network service
   presents.
 * Easy to configure.
 * Automatic host configuration discovery. This helps to create minimalistic images specific for the current host.

There are other initramfs generators similar to booster: [mkinitcpio](https://git.archlinux.org/mkinitcpio.git/) and [dracut](https://dracut.wiki.kernel.org/index.php/Main_Page).

### Install
#### Arch Linux
Install [booster-git](https://aur.archlinux.org/packages/booster-git/) package from AUR.

At the installation time this package will create a number of booster images in your `/boot/` directory:
```shell
$ ls -lh /boot/booster-*.img
-rwxr-xr-x 1 root root 3.9M Dec 10 20:51 /boot/booster-linux.img
```

Or optionally the image can be generated manually as `booster -o mybooster.img`. Note that by default booster generates
host specific images with minimum binaries needed for the current host. Providing `-universal` flag to `booster` tool
will add more modules and tools and the result image will be bigger.

Once the image is generated it is time to configure the bootloader.

#### systemd-boot
Here is a sample entry for `systemd-boot` UEFI bootloader:

```
$ cat /boot/loader/entries/booster.conf
title Linux with Booster
linux /vmlinuz-linux
initrd /intel-ucode.img
initrd /booster-linux.img
options rd.luks.uuid=e122d09e-87a9-4b35-83f7-2592ef40cefa root=UUID=08684949-bcbb-47bb-1c17-089aaa59e17e rw
```

where `e122d09e-87a9-4b35-83f7-2592ef40cefa` is a UUID for the LUKS partition and `08684949-bcbb-47bb-1c17-089aaa59e17e` is
a UUID for the encrypted filesystem (e.g. ext4). Please refer for your bootloader documentation for more info about its
configuration.

### Configure
Booster generator has a number of configurable options.

#### Config file
First there is a configuration file located at `/etc/booster.yaml`. It has following fields:

```yaml
network:
  dhcp: on
  ip: 10.0.2.15/24
  gateway: 10.0.2.255
universal: false
modules: nvidia,kernel/sound/usb/
compression: zstd
mount_timeout: 5m6s
```

`network` node, if presents, initializes network at the boot time. It is needed if mounting a root fs requires access to the network (e.g. in case of Tang binding).
The address can be configured with a static ip (node `ip`) or with DHCPv4 (`dhcp: on`).

`universal` is a boolean flag that tells booster to generate a universal image.
By default `booster` generates a host-specific image that includes kernel modules used at the *current host*.
For example if the host does not have a TPM2 chip then tpm modules are ignored.
*Universal* image includes many kernel modules and tools that might be needed at a broad range of hardware configurations.

`modules` is a comma-separates list of extra modules to add to the generated image. One can use a module name or a path relative
to the modules dir (`/usr/lib/modules/$KERNEL_VERSION`). If the path ends with slash symbol (`/`) then it considered a directory
and all modules from this directory needs to be added recursively. `booster` also takes modules dependencies into account, all dependencies
of the specified modules will be added to the image as well.

`compression` is a flag that specifies compression for the output initramfs file. Currently supported algorithms are "zstd", "gzip", "none".
If no option specified then "zstd" is used as a default compression.

`mount_timeout` timeout for waiting for root filesystem to appear. The field format is a decimal number and then unit number.
Valid units are "s", "m", "h". If no value specified then default timeout (3 minutes) is used.
To disable the timeout completely specify "0s".

#### Command-line arguments
`booster` accepts a list of arguments:
 * `-universal` generate a universal image
 * `-kernelVersion` use modules for the given kernel version. If the flag is not specified then the current kernel is used (as reported by `uname -r`).
 * `-output` output file, by default `booster.img` used
 * `-compression` output file compression. Currently supported compression algorithms are "zstd" (default) and "gzip".
 * `-force` overwrite output file if it exists

#### Kernel boot parameter
Some parts of booster boot functionality can be modified with kernel boot parameters. These parameters are usually set through bootloader config.
Booster boot uses following kernel parameters:
 * `root=($PATH|UUID=$UUID|LABEL=$LABEL)` root device. It can be specified as a path to the block device (e.g. `root=/dev/sda`) or with filesystem UUID (e.g. `root=UUID=fd59d06d-ffa8-473b-94f0-6584cb2b6665`, pay atenntion that it does *not* contain any quotes) or with filesystem label (e.g. `root=LABEL=rootlabel`, pay attention that label does not contain any quotes or whitespaces).
 * `rootfstype=$TYPE` (e.g. `rootfstype=ext4`). By default booster tries to detect the root filesystem type. But if the autodetection does not work then this kernel parameter is useful.
   Also please file a ticket so we can improve the code that detects filetypes.
 * `rootflags=$OPTIONS` mount options for the root filesystem, e.g. `rootflags=user_xattr,nobarrier`.
 * `rd.luks.uuid=$UUID` UUID of the LUKS partition where the root partition is enclosed. booster will try to unlock this LUKS device.
 * `rd.luks.name=$UUID=$NAME` similar to `rd.luks.uuid` parameter but also specifies the name used for the LUKS device opening.
 * `booster.debug=1` enable booster debug output. It is printed to console at the boot time. This feature might be useful to debug booster issues.

### Build
The project consists of 3 components:
 * `init` binary that runs as a part of your machine boot process. It is going to be the very first user process run at your machine.
 * `generator` tool that creates ramfs image with all components needed to boot the computer
 * `integration_tests` tests that involve all components and use QEMU to boot from a generated image

These components use standard Golang tooling. To build any part do `go build`, to run tests do `go test`.

### Run tests
 ```bash
cd {init,generator,integration_tests}
go test -v
 ```

### Debugging
If you have a problem with booster boot tool you can enable debug mode to get more
information about what is going on. Just add `booster.debug=1` kernel parameter and booster
provide additional logs.

### Credits
Work on this project has been started as a part of Twitter's hack week. Huge thanks to my employer for its support
of open-source development. Special thanks to [Ian Brown](https://twitter.com/igb).

Booster architecture has been inspired by Michael Stapelberg's project called [distri](https://distr1.org/).
Initial version of booster borrowed a lot of ideas from the distri's initramfs generator.

### Licence
See [license](LICENSE)
