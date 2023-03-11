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
 * [Systemd-cryptenroll](http://0pointer.net/blog/unlocking-luks2-volumes-with-tpm2-fido2-pkcs11-security-hardware-on-systemd-248.html)
   type of binding. Booster is able to detect and unlock systemd-fido2 and systemd-tpm2 style partitions.
 * Supports [autodiscoverable root partition](https://systemd.io/DISCOVERABLE_PARTITIONS/)
 * Easy to configure.
 * Automatic host configuration discovery. This helps to create minimalistic images specific for the current host.

There are other initramfs generators similar to booster: [mkinitcpio](https://git.archlinux.org/mkinitcpio.git/) and [dracut](https://dracut.wiki.kernel.org/index.php/Main_Page).

### Install
#### Arch Linux
Install [booster](https://archlinux.org/packages/extra/x86_64/booster/) package from the official repository.

At the installation time this package will create a number of booster images in your `/boot/` directory:
```shell
$ ls -lh /boot/booster-*.img
-rwxr-xr-x 1 root root 3.9M Dec 10 20:51 /boot/booster-linux.img
```

#### Void Linux
Install booster with `xbps-install -S booster`.

Run `xbps-reconfigure -f linux` to create the initramfs for a previously installed kernel.

#### Alpine Linux
Install booster using `apk add booster`.

Refer to `/usr/share/doc/booster/README.alpine` for bootloader configuration instructions (which depend on the desired setup).

#### Manual
Or optionally the image can be generated manually as `booster build mybooster.img`. Note that by default booster generates
host specific images with minimum binaries needed for the current host. Providing `--universal` flag to `booster` tool
will add more modules and tools and the result image will be bigger.

Once the image is generated it is time to configure the bootloader.

### Usage
For usage instructions please see booster manpage using `man booster` or the same document [available online](docs/manpage.md).

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

### Credits
Work on this project has been started as a part of Twitter's hack week. Huge thanks to my employer for its support
of open-source development. Special thanks to [Ian Brown](https://twitter.com/igb).

Booster architecture has been inspired by Michael Stapelberg's project called [distri](https://distr1.org/).
Initial version of booster borrowed a lot of ideas from the distri's initramfs generator.

### Licence
See [license](LICENSE)
