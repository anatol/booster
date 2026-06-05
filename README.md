# Booster - fast, secure, modern initramfs for Linux

![Booster initramfs generator](docs/booster.png)

Booster makes early boot feel lighter, faster, and more dependable.
It builds compact initramfs images that move your Linux system from firmware to the real root filesystem with minimal fuss and strong encrypted-boot support.

Instead of packing a large generic early userspace, Booster discovers what your machine actually needs and builds a focused image around it.
The result is a lean boot image with the drivers, unlock tools, filesystem support, and recovery paths your host needs, without carrying a kitchen sink into every reboot.

## Why Booster?

Booster is built around a simple promise: early boot should be quick, clear, secure, and pleasant to operate.

Highlights:

* **Boot faster with smaller images** - generate lean images quickly and keep early boot focused on the work your system actually needs.
* **Make encrypted Linux feel effortless** - unlock LUKS roots using passphrases, keyfiles, detached headers, TPM2, FIDO2 security keys, Clevis-style bindings, or remote SSH unlock.
* **Use modern security hardware confidently** - support `systemd-cryptenroll` TPM2 and FIDO2 tokens, including native FIDO2 support through Booster's plugin path.
* **Enjoy calm, coordinated prompts** - hardware-token, PIN, and passphrase flows work together; successful unlock paths cancel prompts that are no longer needed.
* **Get a smoother FIDO2 boot** - Booster can pre-check connected FIDO2 keys before asking for a PIN, skip the wrong key silently, and fall back cleanly when a token is missing.
* **Unlock systems from wherever you manage them** - use SSH during early boot for headless, rack-mounted, or hard-to-reach encrypted machines.
* **Avoid bloated early userspace** - host-specific discovery includes what your machine needs by default.
* **Build flexible rescue images** - universal mode adds broader hardware coverage for portable installs, recovery media, and changing hardware.
* **Cover real storage layouts** - handle ext4, Btrfs, ZFS, LVM, mdraid, GPT autodiscovery, hibernation resume devices, and multiple LUKS mappings.
* **Inspect and debug with confidence** - list, read, and unpack images with built-in commands before you trust them to boot.

Booster is a strong fit for encrypted laptops, developer workstations, servers with remote recovery needs, minimal Linux systems, and boot setups that should stay understandable years after you configured them.

## Feature Tour

### Encryption That Feels Built In

Booster treats full-disk encryption as a first-class workflow, not an add-on.
It can unlock LUKS devices from kernel parameters, `/etc/crypttab`, GPT autodiscovery, direct `root=` references to LUKS containers, keyfiles, detached headers, and hardware-backed tokens.

Supported unlock styles include:

* Plain passphrase unlock with careful prompt handling.
* Shared passphrase caching for related encrypted volumes.
* Keyfiles embedded in the initramfs or stored on a separate device.
* Detached LUKS headers embedded in the image, read from a raw block device, or loaded from a separate filesystem.
* `systemd-cryptenroll` TPM2 and FIDO2 tokens.
* Clevis-style bindings for TPM2, Tang, and other supported policies.
* SSH-based remote passphrase unlock for systems you cannot physically reach.

### Hardware Tokens Without Rough Edges

Booster's token orchestration is designed to make encrypted boot feel polished.
Non-interactive tokens can race in the background, PIN-based tokens are prompted in a deterministic order, and the regular passphrase prompt appears as a fallback instead of blocking the whole boot forever.

Recent FIDO2 improvements make the experience smoother:

* Native FIDO2 support can be enabled with `enable_fido2: true`.
* A `crypttab` entry with `fido2-device=` can cause Booster to bundle the FIDO2 plugin automatically.
* Booster can check whether a connected FIDO2 key actually has the credential before asking for its PIN.
* Missing-token hints are delayed so fast TPM2, Clevis, or other token unlocks can complete without unnecessary noise.
* Empty PIN submission skips a token and continues to the next unlock path.

### Small Images That Match Your Machine

By default, Booster builds a host-specific image.
It looks at the current system, includes the modules and tools needed to boot it, and leaves out unnecessary pieces.
That keeps the image easier to audit, faster to generate, and faster to execute during boot.

When you need a broader image, `--universal` includes a wider set of modules for rescue scenarios, portable media, or systems where hardware may change.

### Storage Layouts Users Actually Run

Booster supports practical real-world boot layouts, including:

* GPT autodiscoverable root partitions.
* Root on LUKS, LVM, mdraid, Btrfs, ZFS, NVMe, USB, MMC, and eMMC.
* Btrfs subvolumes and multi-device Btrfs setups.
* Hibernation resume devices.
* Device references by `UUID=`, `LABEL=`, `PARTUUID=`, `PARTLABEL=`, `HWPATH=`, `WWID=`, or `/dev/...`.
* Multiple encrypted mappings from the kernel command line or `/etc/crypttab`.

### Better Early-Boot Visibility

When something goes wrong, Booster gives you useful ways to see what happened.
Use `booster.log=debug,console` for detailed boot logs, add `busybox` for an emergency shell, or enable network support to retrieve logs from an unbootable machine.

Booster also includes image-inspection commands so you can verify what was built before rebooting:

```shell
booster ls /boot/booster-linux.img
booster cat /boot/booster-linux.img /init
booster unpack /boot/booster-linux.img /tmp/booster-image
```

## Install

### Arch Linux

Install the official package:

```shell
pacman -S booster
```

The package creates Booster images in `/boot/`:

```shell
$ ls -lh /boot/booster-*.img
-rwxr-xr-x 1 root root 3.9M Dec 10 20:51 /boot/booster-linux.img
```

### Void Linux

Install Booster with:

```shell
xbps-install -S booster
```

Then regenerate the initramfs for an already installed kernel:

```shell
xbps-reconfigure -f linux
```

### Alpine Linux

Install Booster with:

```shell
apk add booster
```

Then read `/usr/share/doc/booster/README.alpine` for setup-specific bootloader instructions.

### Manual build

You can also build an image directly:

```shell
booster build /boot/booster-linux.img
```

For a more portable image with a wider hardware set:

```shell
booster build --universal /boot/booster-linux.img
```

After creating the image, point your bootloader at it.
For full configuration details, see the [Booster manpage](docs/manpage.md).

## Quick Start

Create a host-specific image:

```shell
booster build booster.img
```

Create an image for a specific kernel:

```shell
booster build --kernel-version 6.8.9-arch1-1 /boot/booster-linux.img
```

Inspect the generated image:

```shell
booster ls /boot/booster-linux.img
```

Regenerate packaged images after changing `/etc/booster.yaml`:

```shell
/usr/lib/booster/regenerate_images
```

Generate a Unified Kernel Image when your distribution provides `systemd-ukify`:

```shell
/usr/lib/booster/regenerate_uki build /boot/EFI/Linux
```

## Example Configuration

Booster is intentionally small to configure.
A simple encrypted laptop often needs no large config file at all.
Add only the features your boot path needs:

```yaml
compression: zstd
vconsole: true
enable_fido2: true
enable_lvm: true
enable_mdraid: true
```

For remote unlock over SSH:

```yaml
network:
  dhcp: on
  ssh_host_key: /etc/booster/ssh_host_ed25519_key
  ssh_authorized_keys: /etc/booster/authorized_keys
  ssh_listen: :22
```

For smoother token ordering when several hardware unlock methods are enrolled:

```yaml
serialize_tokens:
  enabled: true
  clevis_timeout: 45s
  tpm2_timeout: 15s
  fido2_timeout: 30s
```

For Plymouth splash support:

```yaml
enable_plymouth: true
modules_force_load: amdgpu
```

Use `quiet splash` in your kernel command line, and avoid `booster.log=console` when you want the graphical splash.

## Documentation

The full user documentation is in the [Booster manpage](docs/manpage.md).
It covers:

* `/etc/booster.yaml` options.
* Kernel command-line parameters.
* LUKS, FIDO2, TPM2, Clevis, keyfile, and detached-header setup.
* `/etc/crypttab` integration.
* Remote unlock over SSH.
* GPT root autodiscovery.
* Unified Kernel Image generation.
* Debugging and recovery.

## Similar Projects

Booster lives in the same problem space as [mkinitcpio](https://git.archlinux.org/mkinitcpio.git/) and [dracut](https://dracut.wiki.kernel.org/index.php/Main_Page).
Its focus is a fast, compact, Go-based initramfs generator with strong encrypted-boot ergonomics and automatic host discovery.

## Build From Source

The project has three main parts:

* `init` - the early userspace program that runs during boot.
* `generator` - the tool that builds the initramfs image.
* `tests` - QEMU-based integration tests for generated images.

Build with standard Go tooling:

```shell
go build ./...
```

Run unit tests:

```shell
go test ./generator ./init
```

Run the full test suite:

```shell
go test ./...
```

The `./tests` package contains QEMU integration tests and requires the host to have the needed boot and virtualization tooling installed.

## Credits

Work on this project started during Twitter's hack week.
Huge thanks to Twitter for supporting open-source development, and special thanks to [Ian Brown](https://twitter.com/igb).

Booster's architecture was inspired by Michael Stapelberg's [distri](https://distr1.org/), and the initial version borrowed many ideas from distri's initramfs generator.

## License

See [LICENSE](LICENSE).
