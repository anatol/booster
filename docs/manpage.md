booster(1) -- fast and secure initramfs generator
=================================================

## DESCRIPTION
**Booster** is a tool to create initramfs images needed at the early stage of Linux boot process. Booster is made with speed and full disk encryption use-case in mind.

Booster advantages:

 * Fast image build time and fast boot time.
 * Out-of-box support for LUKS-based full disk encryption setup.
 * Clevis style data binding. The encrypted filesystem can be bound to a TPM2 chip or to a network service. This helps to unlock the drive automatically but only if the TPM2/network service is present.
 * Automatically detects and unlocks systemd-cryptenroll (fido2 and tpm2) types of partition encryption.
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
      ssh_host_key: /etc/booster/ssh_host_ed25519_key
      ssh_authorized_keys: /etc/booster/authorized_keys
      ssh_listen: :22
    universal: false
    modules: -*,hid_apple,kernel/sound/usb/,kernel/fs/btrfs/btrfs.ko,kernel/lib/crc4.ko.xz
    compression: zstd
    mount_timeout: 5m6s
    strip: true
    extra_files: vim,/usr/share/vim/vim82/,fsck,fsck.ext4
    vconsole: true
    enable_lvm: true
    enable_mdraid: true
    token_timeout: 30s
    pin_delay: 5s
    serialize_tokens:
      enabled: true
      clevis_timeout: 45s

 * `network` node, if present, initializes the network at the boot time. It is needed if mounting a root fs requires access to the network (e.g. in case of Tang binding).
    The network can be either configured dynamically with DHCPv4 or statically within this config. In the former case `dhcp` is set to `on`.
    In the latter case the config allows to specify `ip` - the machine IP address and its network mask, `gateway` - default gateway, `dns_servers` - comma-separated list of DNS servers.
    The `network` node also accepts `interfaces` property - a comma-separated list of network interfaces (specified either with name or MAC address) to enable at the boot time.
    Network names like `enp0s31f6` get resolved to MAC addresses at generation time and then passed to init.
    If `interfaces` node is not specified then all the interfaces are activated at boot.
    The `network` node also accepts `ssh_host_key`, `ssh_authorized_keys`, and `ssh_listen` to enable remote LUKS unlock over SSH. `ssh_host_key` is a path to an OpenSSH- or PEM-encoded SSH host private key, `ssh_authorized_keys` is a path to an authorized_keys file, and `ssh_listen` is the listen address (default `:22`). Both `ssh_host_key` and `ssh_authorized_keys` must be set together, and SSH requires `dhcp: true` or a static `ip`. See REMOTE UNLOCK below.

 * `universal` is a boolean flag that tells booster to generate a universal image. By default booster generates a host-specific image that includes kernel modules used at the current host. For example if the host does not have a TPM2 chip then tpm modules are ignored. Universal image includes many kernel modules and tools that might be needed at a broad range of hardware configurations.

 * `modules` is a comma-separated list of extra modules to add to or remove from the generated image.
    One can use a module name or a path relative to the modules dir (/usr/lib/modules/$KERNEL_VERSION).
    The compression algorithm suffix (e.g. ".xz", ".gz) can be omitted from the module filename.
    If the element starts with a minus sign (`-`) then it means "do not add it to the image", otherwise modules are added.
    If the path ends with a slash symbol (/) then it is considered a directory and all modules from this directory need to be added recursively.
    A special symbol `*` (star) means all modules. It can be used for example to add all modules or remove all predefined modules from the image.
    Booster also takes module dependencies into account, all dependencies of the specified modules will be added to the image as well.

 * `modules_force_load` list of module names that are forcibly loaded during the boot process before switching into user-space. Any module in this list automatically added to the image so there is no need to duplicate it at `modules` property.

 * `append_all_modaliases` is a boolean flag that instructs booster to add all hosts's module aliases to the booster image. This flag is useful for debugging boot timeout issues when some important modules are missed from the image. Setting the flag to `true` will help to print module names for aliases that were requested by kernel but missed in the image.

 * `compression` is a flag that specifies compression for the output initramfs file. Currently supported algorithms are "zstd", "gzip", "xz", "lz4", "none". If no option is specified, "zstd" is used as the default compression.

 * `mount_timeout` timeout for waiting for the root filesystem to appear. The field format is a decimal number and then unit number. Valid units are "s", "m", "h". If no value is specified, the default timeout (3 minutes) is used. To disable the timeout completely specify "0s".

 * `strip` is a boolean flag that enables stripping of ELF files before adding them to the image. Binaries, shared libraries and kernel modules are examples of ELF files that get processed with the strip UNIX tool.

   This option is not compatible with signed modules. If you see `booster: finit(crc32,generic): key was rejected by service` boot error please set the `strip` config option to `false`.

 * `extra_files` is a comma-separated list of extra files to add to the image. If an item starts with slash ("/") then it is considered an absolute path. Otherwise it is a path relative to /usr/bin. If the item is a directory then its content is added recursively. There are a few special cases:
    * adding `busybox` to the image enables an emergency shell in case of a panic during the boot process.
    * adding `fsck` enables boot time filesystem check. It also requires filesystem specific binary called `fsck.$rootfstype` to be added to the image. Filesystems are corrected automatically and if it fails then boot stops and it is the responsibility of the user to fix the root filesystem.

 * `vconsole` is a flag that enables early-user console configuration. If it is set to `true` then booster reads configuration from `/etc/vconsole.conf` and `/etc/locale.conf` and adds required keymap and fonts to the generated image.
    The following config properties are taken into account: `KEYMAP`, `KEYMAP_TOGGLE`, `FONT`, `FONT_MAP`, `FONT_UNIMAP`. See also [man vconsole.conf](https://man.archlinux.org/man/vconsole.conf.5.en).

 * `enable_lvm` is a flag that enables LVM volume assembly at the boot time. This flag also makes sure all the required modules/binaries are added to the image.

 * `enable_mdraid` is a flag that enables MdRaid assembly at the boot time. This flag also makes sure all the required modules/binaries are added to the image.

 * `enable_zfs` is a flag that enables ZFS filesystem as root filesystem. This flag also makes sure all the required modules/binaries are added to the image. Note that if ZFS is enabled then `zfs=` boot option must be used instead of `root=` boot option.

 * `crypttab_path` path to the crypttab file to read at image build time. Defaults to `/etc/crypttab` if not set. Can be overridden by the `--crypttab` flag. If set, any read error is reported as a failure.

 * `enable_plymouth` is a flag that enables Plymouth boot splash support. When enabled, booster bundles the Plymouth daemon, plugins, theme, and fonts into the initramfs. GPU driver must be included in `modules_force_load`. The `quiet splash` kernel parameters are also required. Note that `booster.log=console` conflicts with Plymouth's graphical display; when console logging is active, Plymouth reverts to the details plugin (text-based fallback).

 * `enable_fido2` is a boolean flag that enables FIDO2 hardware token support.

 * `serialize_tokens` makes booster try a device's LUKS tokens one at a time in ascending token-ID order instead of racing them concurrently (default off). A non-interactive token (TPM2 PCR-only, touchless FIDO2, clevis) enrolled before a PIN token then unlocks the device before the PIN prompt is reached. Each non-interactive token is bounded by a per-type timeout so a stuck one cannot hang the boot; on expiry booster moves to the next. PIN tokens are not bounded (empty-Enter already skips them). Keys:

    * `serialize_tokens.enabled` — boolean, default `false`.
    * `serialize_tokens.clevis_timeout` / `serialize_tokens.tpm2_timeout` / `serialize_tokens.fido2_timeout` — per-token bounds for clevis, non-PIN `systemd-tpm2`, and non-PIN `systemd-fido2`. Go duration. Defaults `45s` / `15s` / `30s`. No effect unless `serialize_tokens.enabled` is set.

 * `token_timeout` (top-level, applies in both modes) bounds how long booster waits for tokens before it *also* starts the keyboard passphrase prompt. The tokens keep racing after the prompt appears; whichever path wins first dismisses the other (see **LUKS unlock concurrency and prompt order** in NOTES). It is the booster-config equivalent of the crypttab/`rd.luks.options` `token-timeout=` (see `rd.luks.options` under **BOOT TIME KERNEL PARAMETERS**). Go duration. Precedence, highest first:

    1. an explicit per-device `token-timeout=` — on the kernel cmdline (`rd.luks.options`) or in crypttab; the cmdline value wins when both set it for the same device.
    2. this `token_timeout`.
    3. in serialize mode, the sum of the device's per-token timeouts (so the keyboard prompt never preempts a token that has not had its turn).
    4. the `30s` default.

    In serialize mode prefer leaving `token_timeout` unset so tier 3 applies: a fixed value shorter than the token chain can start the keyboard prompt before a token has had its turn.

 * `pin_delay` is the concurrent-mode counterpart to `serialize_tokens`: it holds the first interactive PIN prompt (TPM2-PIN, FIDO2-PIN) this long so a parallel non-interactive token can unlock first and the prompt is never drawn — cancelled before render if a token wins, shown as normal if the delay expires (no unlock path is lost; the delay only postpones the prompt). Go duration; unset (the default) means no delay. No effect in serialize mode, or when no parallel non-PIN token is enrolled (a PIN-only device prompts immediately). Set it longer than the racing token's real unlock time — TPM2/FIDO2 hardware bring-up, or for clevis the network/DHCP round-trip — but well below `token_timeout`; otherwise the prompt is still drawn. A few seconds suits a fast PCR-only TPM2 unseal; clevis-over-network or a universal image with slow module loading needs more.

Once you are done modifying your config file and want to regenerate booster images under `/boot` please use `/usr/lib/booster/regenerate_images`.
It is a convenience script that performs the same type of image regeneration as if you installed `booster` with your package manager.

## COMMAND-LINE FLAGS

### Application Options

* `-v`, `--verbose` Enable verbose output

### SUBCOMMANDS

### build
Build initrd image. Usage: `booster [OPTIONS] build [build-OPTIONS] output`

* `-f`, `--force` Overwrite existing initrd file.
* `--init-binary` <default: _/usr/lib/booster/init_> Booster 'init' binary location.
* `--compression` <default: _zstd_> Output file compression. Possible values: _zstd_, _gzip_, _xz_, _lz4_, _none_.
* `--kernel-version` Linux kernel version to generate initramfs for.
* `--config` <default: _/etc/booster.yaml_> Configuration file path.
* `--universal` Add wide range of modules/tools to allow this image boot at different machines.
* `--strip` Strip ELF files (binaries, shared libraries and kernel modules) before adding it to the image.
* `--crypttab` <default: _/etc/crypttab_> Path to the crypttab file to read at image build time. Overrides `crypttab_path` from the config file. If neither is set, booster reads `/etc/crypttab` and silently skips it if the file is absent or unreadable. If specified explicitly, any read error is reported as a failure.

### cat
Show content of the file inside the image. Usage: `booster [OPTIONS] cat image file-in-image`

### ls
List content of the image. Usage: `booster [OPTIONS] ls image`

### unpack
Unpack image. Usage: `booster [OPTIONS] unpack image output-dir`

## BOOT TIME KERNEL PARAMETERS
Some parts of booster boot functionality can be modified with kernel boot parameters. These parameters are usually set through bootloader config. Booster boot uses following kernel parameters:

 * `root=$deviceref` device reference to root device. See "Device Reference" in NOTES for how to specify it, and "ROOT PARTITION DISCOVERY" for how booster handles unencrypted, LUKS, and autodiscovered roots.
 * `rootfstype=$TYPE` (e.g. rootfstype=ext4). By default booster tries to detect the root filesystem type. But if the autodetection does not work then this kernel parameter is useful. Also please file a ticket so we can improve the code that detects filetypes.
 * `rootflags=$OPTIONS` mount options for the root filesystem, e.g. rootflags=user_xattr,nobarrier. In partition autodiscovery mode GPT attribute 60 ("read-only") is taken into account.
 * `rd.luks.uuid=$UUID` UUID of the LUKS partition where the root partition is enclosed. booster will try to unlock this LUKS device.
 * `rd.luks.name=$UUID=$NAME` similar to rd.luks.uuid parameter but also specifies the name used for the LUKS device opening.
 * `rd.luks.key=$UUID=$PATH` absolute path to a keyfile in the initrd/initramfs which can be used to unlock the device identified by UUID, if this file does not exist or fails to unlock it will fall back to a password request.
 * `rd.luks.header=$UUID=$PATH` detached LUKS header for the device identified by `$UUID`. `$PATH` can take three forms:
    * **Initramfs file** — an absolute path (e.g. `/etc/luks/root.hdr`) to a header file bundled into the initramfs at build time via `extra_files`.
    * **Raw block device** — a device path (e.g. `/dev/sdb`) where the LUKS header begins at byte offset 0. Booster waits for the device to appear and passes it directly to cryptsetup without mounting.
    * **File on a separate device** — `$path:$deviceref` where `$deviceref` is `UUID=...`, `LABEL=...`, `PARTUUID=...`, or `PARTLABEL=...`. Booster mounts the device read-only, reads the header file, then unmounts before unlocking.
 * `rd.luks.options=opt1,opt2` a comma-separated list of LUKS flags. Supported options are `discard`, `same-cpu-crypt`, `submit-from-crypt-cpus`, `no-read-workqueue`, `no-write-workqueue`. `token-timeout=<duration>` sets how long to wait for hardware tokens (FIDO2, TPM2) before also prompting for a keyboard passphrase. Accepts a decimal number followed by a unit (`s`, `m`, `h`), or a bare integer treated as seconds. Default is 30 s.
    Note that booster also supports LUKS v2 persistent flags stored with the partition metadata. Any command-line options are added on top of the persistent flags.
 * `rd.modules_force_load` a comma-separated list of extra kernel modules which should be force loaded.
 * `resume=$deviceref` device reference to suspend-to-disk device.
 * `zfs=$pool/$dataset` specifies what ZFS dataset needs to be used for root partition. This option is only used if ZFS config option is enabled. If ZFS filesystem is enabled then `root=` boot param is ignored.
 * `booster.log` configures booster init logging. It accepts a comma separated list of following values:

   One of the level values (from more verbose to less verbose) - `debug`, `info`, `warning`, `error` or `null`.
   The last level of `null` disables any logging, so *⚠️use it only if know what you are doing⚠️*.
   If the level is not specified then `info` used by default.

   `console` - print booster init logs to console.

   The debug log is also printed to the kernel kmsg buffer and available for reading either with `dmesg` or with `journalctl -b`.
   If debug level is enabled then kmsg throttling gets disabled automatically.
 * `booster.debug` an obsolete option that is equivalent to `booster.log=debug,console`.
 * `quiet` Set booster init verbosity to minimum. This option is ignored if `booster.debug` or `booster.log` is set.
 * `init=$PATH` path to user-space init binary. If not specified then default value `/sbin/init` is used.

## ROOT PARTITION DISCOVERY

Booster identifies the root filesystem from the kernel cmdline and, if it
is encrypted, unlocks the LUKS container before mounting. Most setups land
on one of the configurations below.

### Unencrypted root

    root=UUID=<filesystem-uuid>

`PARTUUID=`, `LABEL=`, or a `/dev/...` path also work.

### Encrypted (LUKS) root

There are four ways to set it up. Pick whichever fits your bootloader
and existing tooling.

**Named via cmdline.**

    rd.luks.name=<luks-partition-uuid>=<name> root=/dev/mapper/<name>

See `rd.luks.name`, `rd.luks.uuid`, and friends under BOOT TIME KERNEL
PARAMETERS for the full set.

**Named via /etc/crypttab.** Add an entry marked `x-initrd.attach`; the
first column becomes the mapper name. Pair with `root=/dev/mapper/<name>`
on the cmdline. See CRYPTTAB below for syntax and bundling rules.

**Auto-named.** With no `rd.luks.*` on the cmdline and no crypttab entry
covering this volume, point `root=` at the LUKS container itself:

    root=UUID=<luks-partition-uuid>

Booster unlocks it as `/dev/mapper/root` and mounts that. `PARTUUID=`,
`LABEL=`, or a `/dev/...` path resolving to the container also work.

**Zero kernel parameters.** Tag the partition with the per-architecture
root GUID and booster discovers it with no `root=` argument at all. See
GPT autodiscovery below.

### GPT autodiscovery (no cmdline at all)

Set the root partition's GPT type to "Linux root" for your CPU architecture
using any GPT editor (gdisk, sgdisk, fdisk, cfdisk, parted, ...). On x86-64
with gdisk, for instance, the type code is `8304`. Other tools and
architectures use different shortcuts; consult your editor's type list.
The full per-architecture GUID list is in the [Discoverable Partitions Specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/).

The same GUID covers both plain-filesystem and LUKS-encrypted roots —
booster handles either. Booster scans only the disk that holds the
active EFI System Partition; root-tagged partitions on other disks are
ignored. Tag exactly one partition on that disk.

### When boot stalls

If `root=/dev/mapper/<name>` is set but no source above produces that
mapper, booster prints

    root=/dev/mapper/<name> but no LUKS unlock spec was found for "<name>"

before stalling at the mount-timeout. Add any of the unlock recipes above
and rebuild.

## CRYPTTAB

Booster supports unlocking LUKS volumes declared in `/etc/crypttab` (see
[crypttab(5)](https://man7.org/linux/man-pages/man5/crypttab.5.html)).
Only entries marked with the `x-initrd.attach` option are bundled into
the initramfs at image build time. The generator must be able to read
the file — run as root, or pass `--crypttab <path>` to a user-readable
copy.

When both a `rd.luks.*` cmdline parameter and a crypttab entry cover the
same device, the cmdline takes precedence for the device reference and
mapper name, and for any security option (keyfile, header, tries,
token-timeout, …) it sets explicitly; the crypttab entry supplies only
the options the cmdline left unset. Crypttab entries for devices not
covered by `rd.luks.*` are appended as new mappings.

Booster-specific behaviour for selected options:

 * **keyfile** `/path:UUID=xxx` (or `LABEL=`, `PARTUUID=`, `PARTLABEL=`) — keyfile on a separate device. Booster mounts the device read-only at boot, reads the key, then unmounts. The file is not bundled into the initramfs.
 * **`header=`** — if the path is a plain absolute path the generator bundles the file into the initramfs automatically. The `/path:deviceref` form mounts the device at boot; `/dev/...` uses the raw block device directly.
 * **`fido2-device=`** — when this option appears in a crypttab entry, the generator automatically bundles `fido2plugin.so`; no `enable_fido2: true` in the config file is required. Both `fido2-device=` and `tpm2-device=` are otherwise accepted for compatibility; booster discovers enrolled tokens from the LUKS2 header, not from the crypttab option value.
 * **`keyfile-timeout=`** / **`token-timeout=`** — accept a bare integer (seconds) or any duration string accepted by Go's `time.ParseDuration` (e.g. `30s`, `2m`).

## REMOTE UNLOCK

Booster can unlock LUKS volumes from a remote SSH client during early boot.
The SSH server starts once networking is up (DHCP lease acquired or static
`ip` configured) and prompts the connecting client for a LUKS passphrase.
The submitted passphrase is broadcast to every LUKS device currently
waiting at a keyboard prompt; a successful unlock seeds the in-boot
passphrase cache so sibling volumes with the same key unlock without
further prompts. Equivalent to Debian's `dropbear-initramfs` setup but
native to booster — uses Go's `golang.org/x/crypto/ssh` rather than
bundling dropbear.

Generate a host key once (kept on the host, embedded into the image at
build time):

    $ ssh-keygen -t ed25519 -f /etc/booster/ssh_host_ed25519_key -N ''

Build an `authorized_keys` file with one or more public keys, one per
line:

    ssh-ed25519 AAAAC3Nz...user1@laptop
    ssh-ed25519 AAAAC3Nz...user2@phone

Wire both files into `/etc/booster.yaml`:

    network:
      dhcp: on
      ssh_host_key: /etc/booster/ssh_host_ed25519_key
      ssh_authorized_keys: /etc/booster/authorized_keys
      ssh_listen: :22

Both `ssh_host_key` and `ssh_authorized_keys` are read at image build
time and embedded into the initramfs; one without the other is a config
error. SSH also requires `network.dhcp: true` or a static `network.ip`.

From a client, connect as `root` and paste the passphrase at the prompt:

    $ ssh -p 22 root@<host>

Security notes:

 * Pubkey-only authentication; password auth is not supported.
   Per-session attempts are capped at 10 wrong submissions before
   disconnect; the SSH handshake itself must complete within 15
   seconds (slow-loris guard).
 * The host private key and the enrolled `authorized_keys` are read
   at image build time and embedded into the initramfs. Anyone with
   read access to `/boot` (or the image file) can extract both. Treat
   them as compromised whenever `/boot` is exposed; rebuild the image
   to rotate the host key.
 * The host key fingerprint is stable across reboots (no auto-regen),
   so `known_hosts` does not churn.
 * The SSH port plus a stolen copy of any private key listed in
   `authorized_keys` is enough for an attacker to keep guessing LUKS
   passphrases against the live server. We disconnect a session after
   10 wrong submissions, but nothing stops the attacker from
   reconnecting and trying 10 more. The cap slows brute force, it
   does not stop it — anyone who can reach the SSH port is in a
   position roughly equivalent to direct LUKS keyslot exposure.
 * `ssh_listen: :22` listens on every network interface that comes
   up at boot, on both IPv4 and IPv6 — including link-local IPv6
   addresses (`fe80::...`) that auto-configure without DHCP. Pin
   `ssh_listen` to an exact address (for example `10.0.0.5:22`) so
   only the interface you actually intend to expose is reachable,
   and firewall the port at the network boundary.
 * The session is restricted to the passphrase prompt — no shell, no
   command execution, no port forwarding, no PAM, no PTY allocation.

## NOTES

### Device Reference
Device reference is a way to specify a device or partition in kernel parameters. It is labeled as `$deviceref` above.
Device reference has one of the following values:

 * `/dev/XXX` path to specific device file, it can be either a path to real device/partition like `/dev/sda1`, `/dev/nvme0n1` or path to dm-mapper virtual device like
   `/dev/mapper/root` or `/dev/vg_mesos/lv_mesos_containers`.
 * `UUID=$UUID` or `/dev/disk/by-uuid/$UUID` references device by its filesystem/LUKS UUID. See notes about UUID formatting rules below.
 * `LABEL=$LABEL` or `/dev/disk/by-label/$LABEL` references device by its filesystem/LUKS label.
 * `PARTUUID=$UUID` or `/dev/disk/by-partuuid/$UUID` references device by GPT partition UUID.
 * `PARTUUID=$UUID/PARTNROFF=$OFFSET` references device by $OFFSET from a GPT partition specified by $UUID e.g. `PARTUUID=fd59d06d-ffa8-473b-94f0-6584cb2b6665/PARTNROFF=2`.
 * `PARTLABEL=$LABEL` or `/dev/disk/by-partlabel/$LABEL` references device by GPT partition label.
 * `HWPATH=$PATH` or `/dev/disk/by-path/$PATH` references device by deterministic hardware path e.g. `pci-0000:02:00.0-nvme-1-part2`.
 * `WWID=$ID` or `/dev/disk/by-id/$ID` references device by its wwid e.g. `nvme-KXG6AZNV256G_TOSHIBA_40SA13GZF6B1-part3`

### UUID parameters
Boot parameters such as `root=UUID=$UUID` and `rd.luks.uuid=$UUID` allow you to specify the block device by its UUID.
The UUID format is `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` where `x` is a hexadecimal symbol either in lower or upper case.
UUID parameter can optionally be enclosed with quote symbol `"` though it is not recommended. Following examples show correct parameters format:
`root=UUID=ac8299a8-91ce-4bf6-a524-55a62844b787`, `root=UUID="ac8299a8-91ce-4bf6-a524-55a62844b787"` (not recommended),
`rd.luks.uuid=ac8299a8-91ce-4bf6-a524-55a62844b787`, `rd.luks.uuid="ac8299a8-91ce-4bf6-a524-55a62844b787"` (not recommended).

### Password entry
Editing keys beyond the standard:
 * **Ctrl+W** — erase the previous word.
 * **Ctrl+U** — erase the entire entry.
 * **Tab** — toggle visibility of the typed characters (asterisks ↔ literal).

### LUKS unlock concurrency and prompt order
Booster runs LUKS unlock paths concurrently per volume — multiple enrolled tokens dispatch in parallel where possible, and the keyboard passphrase prompt runs alongside them as a fallback. This subsection summarises the deterministic ordering and the cancel-on-win behaviour that ties them together.

**PIN-token serialization.** Tokens that need a PIN (TPM2-PIN, FIDO2-PIN) prompt serially, in ascending LUKS2 token-ID order — booster never races two PIN prompts for the same keyboard. Tokens that do not need a PIN (TPM2 PCR-only, FIDO2 touchless) dispatch in parallel and can win the race without user interaction. To preview the PIN prompt order for a volume, run `cryptsetup luksDump <device>` and read the token IDs.

**FIDO2 credential pre-flight.** When a LUKS volume has multiple FIDO2 tokens enrolled (for example a primary key and a backup), booster identifies the matching device before prompting for its PIN. It runs a CTAP2 assertion with `up=false` against each FIDO2-capable hidraw, asking the authenticator whether it holds this volume's credential — devices that do not are skipped silently and the dispatcher advances to the next FIDO2 token (or the next unlock method) without prompting for the wrong key's PIN. Tokens enrolled with `fido2-uv-required=true` skip the pre-flight (per CTAP 2.1 §7.4) and proceed directly to the full assertion.

**Cancel-on-win.** Any prompt — keyboard passphrase, FIDO2-PIN, or TPM2-PIN — is dismissed automatically when a parallel unlock path wins (a touchless token completes, a sibling volume's keyfile reads successfully, etc.). This applies on both the kernel console and the Plymouth splash. On Plymouth the on-screen prompt clears immediately on the server side once Plymouth MR !393 is picked up; older Plymouth builds release the prompt server-side but leave its UI drawn until the splash is otherwise cleared.

**PIN attempt caps.** Each PIN-bearing token accepts up to 3 attempts; submit an empty PIN (just press Enter) to skip the token and dispatch the next one.

### Modules selection
It is a note to summarize the algorithm that computes what modules are going to end up in the generated booster image.
Initial module list for booster is `defaultModulesList` - a set of predefined hard-coded modules defined at `generator.go`.
These are selected modules that most likely cover most system boot needs - disk, filesystem, keyboard, tpm, ethernet, usb drivers.

If the `universal` config option is set to false (default value) then so-called host mode is used.
I.e. image is generated with the drivers needed for current host hardware only.
To achieve it booster fetches all currently loaded modules from `/sys/module/` and computes intersection with the `defaultModulesList`.

Then booster looks at `modules` config option, a comma-separated list of elements. It iterates over all the elements left-to-right.
The host mode filtering rule does not apply to this list of manually specified modules.

If the element starts with minus sign `-` then it removes given modules from the image, otherwise modules are added to the image.

If the element is a module name then this module is added/removed. Note that by convention a kernel module name can be computed from its filename by replacing all dashes to underscore, e.g.
For the module `hid-apple.ko.gz` name will be `hid_apple`.

If the element is a path to the module file relative to `/usr/lib/modules/$KERNEL_VERSION` then the module is added/removed. Note that the compression algorithm suffix can be omitted from the module filename.

If the element ends with the slash symbol `/` then this element is considered a directory relative to `/usr/lib/modules/$KERNEL_VERSION`.
Booster goes over this directory recursively and adds/removes the modules to the image. Minus sign can be used with the directories.

Star symbol `*` is a shortcut for "all modules", it can be used to add all modules or remove all modules from the image.

Next booster moves to the `modules_force_load` option that consists of module names to load at the boot time.
All these modules are also added to the image.

At the final step booster computes dependency graphs between modules and all required dependencies.
For example if a user manually added `ext4` and kernel build system says `ext` module requires `mbcache` and `jbd2` then both
`mbcache` and `jbd2` automatically added to the image.

## Unified Kernel Image
A [Unified Kernel Image](https://uapi-group.org/specifications/specs/unified_kernel_image/) (UKI) is a PE binary that bundles the boot components (kernel, initrd, kernel command line, and a UEFI boot stub) as a single executable.
This allows booting directly through the firmware (UEFI) and authenticating all of the boot components at once for Secure Boot.

The recommended, cross-distribution way to build UKIs with Booster is through systemd's [kernel-install(8)](https://man7.org/linux/man-pages/man8/kernel-install.8.html). Booster ships a kernel-install plugin that generates the initrd; systemd's `ukify` plugin then assembles and optionally signs the UKI. Configure `/etc/kernel/install.conf`:

    layout=uki
    initrd_generator=booster
    uki_generator=ukify

The kernel command line is read from `/etc/kernel/cmdline` and embedded into the UKI:

    # /etc/kernel/cmdline
    rd.luks.uuid=<luks-uuid> root=UUID=<fs-uuid> rw

Microcode and Secure Boot signing are configured in `/etc/kernel/uki.conf`, which `ukify` consumes (see [ukify(1)](https://man7.org/linux/man-pages/man1/ukify.1.html)):

    [UKI]
    Microcode=/boot/intel-ucode.img
    SecureBootPrivateKey=/etc/kernel/secureboot/db.key
    SecureBootCertificate=/etc/kernel/secureboot/db.crt

Booster does not bundle CPU microcode into its initramfs, so point `Microcode=` at your distribution's early-microcode image (e.g. `/boot/intel-ucode.img` or `/boot/amd-ucode.img`); `ukify` adds it as the UKI's `.ucode` section. Set the kernel command line in `/etc/kernel/cmdline`, not in `uki.conf`.

`ukify` can also sign TPM2 PCR policies (`PCRPrivateKey=`/`PCRBanks=`) for measured-boot binding.

Distributions that already drive kernel installation through `kernel-install` (e.g. Fedora) build the UKI automatically. On Arch-based distributions, which use pacman hooks rather than `kernel-install`, a hook such as the AUR `pacman-hook-kernel-install` runs it on kernel updates; booster's own pacman hook can stay enabled (it then builds an unused plain initrd next to the UKI) or be disabled to avoid the redundant build.

Embedding the command line matters for security. A UKI with no embedded command line accepts one from the boot loader at runtime, which is not part of the signed and measured image: an attacker could append e.g. `init=/bin/sh` and obtain a root shell on the decrypted filesystem after a TPM2 auto-unlock, because the measured boot chain — and therefore the TPM policy — is unchanged. When the command line is embedded it is measured into PCR 11, and under Secure Boot systemd-stub ignores any externally supplied command line.

The legacy Arch-only helper `/usr/lib/booster/regenerate_uki` is deprecated: it does not embed the kernel command line and is therefore vulnerable to the injection described above. Prefer `kernel-install`.

To boot the UKI by default you may also need to adjust your boot loader configuration.

## DEBUGGING
If you have a problem with booster boot tool you can enable debug mode to get more
information about what is going on. Just add `booster.log=debug,console` kernel parameter and booster
provides additional logs.

### Use TFTP to download logs for unbootable device
In case of a boot failure, when the devices are missing, logs can still be retrieved from busybox using the network.
First, set up a tftp server (port 69) on another machine/VM. For example on Archlinux, `pacman -S atftp; systemctl start atftpd`.
Then, edit `/etc/booster.yaml` and add [network support](#config-file) and busybox (`extra_files: busybox`).
Regenerate the initramfs and reboot. Once inside busybox, get the logs and send them to the tftp server:

    $ dmesg >boot.log
    $ lsmod >mods.log
    $ tftp -pl boot.log <server ip>
    $ tftp -pl mods.log <server ip>

The logs will be in `/srv/atftp` on the server.

### Boot timeout
If you got `booster: Timeout waiting for root filesystem` error please add `append_all_modaliases` config flag and rebuild the image. With this flag you'll get a list of modules that were requested by the kernel but absent in the booster image. Some of these modules might be required to boot your system.

## EXAMPLES
Create an initramfs file specific for the current kernel/host. The output file is booster.img:

    $ booster build booster.img

Create an universal image with many modules (such as SATA/TPM/NVME/... drivers) included:

    $ booster build --universal booster.img

Create an initramfs for kernel version 5.4.91-1-lts and copy it to /boot/booster-lts.img:

    $ booster build --kernel-version 5.4.91-1-lts /boot/booster-lts.img

Here is a `systemd-boot` configuration stored at /boot/loader/entries/booster.conf. In this example e122d09e-87a9-4b35-83f7-2592ef40cefa is a UUID for the LUKS partition and 08684949-bcbb-47bb-1c17-089aaa59e17e is a UUID for the encrypted filesystem (e.g. ext4). Please refer to your bootloader documentation for more info about its configuration.

    title Linux with Booster
    linux /vmlinuz-linux
    initrd /booster-linux.img
    options rd.luks.uuid=e122d09e-87a9-4b35-83f7-2592ef40cefa root=UUID=08684949-bcbb-47bb-1c17-089aaa59e17e rw

For hardware-token unlock with a FIDO2 device, enroll the LUKS slot once with `systemd-cryptenroll`:

    $ systemd-cryptenroll --fido2-device=auto /dev/sda2

Then add a `/etc/crypttab` entry. Booster takes the mapper name from the first column; the generator auto-bundles `fido2plugin.so` whenever it sees `fido2-device=`. `token-timeout=` sets how long booster waits for the FIDO2 touch before also opening the keyboard passphrase prompt (default 30s; `0` waits forever):

    cryptroot  UUID=e122d09e-87a9-4b35-83f7-2592ef40cefa  none  fido2-device=auto,token-timeout=60s,x-initrd.attach

The bootloader entry points `root=` at the future mapper node:

    title Linux with Booster
    linux /vmlinuz-linux
    initrd /booster-linux.img
    options root=/dev/mapper/cryptroot rw

Boot with no `root=` on the kernel cmdline at all using GPT autodiscovery. Tag the root partition with the per-architecture GUID — on x86-64 that's `4f68bce3-e8cd-4db1-96e7-fbcaf984b709`:

    $ sgdisk --typecode=2:4f68bce3-e8cd-4db1-96e7-fbcaf984b709 /dev/sda

For a LUKS-encrypted root, add a `/etc/crypttab` entry naming the mapper (otherwise booster synthesises `/dev/mapper/root`):

    cryptroot  UUID=e122d09e-87a9-4b35-83f7-2592ef40cefa  none  x-initrd.attach

The bootloader entry then carries only the mount-style flags:

    title Linux with Booster
    linux /vmlinuz-linux
    initrd /booster-linux.img
    options rw

Users of the Btrfs filesystem with a system installed on a subvolume should add rootflags corresponding to their entry in /etc/fstab. In this example 69bc4dd2-7f6c-4821-aa6b-d80d9c97d470 is a UUID for Btrfs partition, with the system installed on subvolume called root and /etc/fstab looks like this:

    UUID=69bc4dd2-7f6c-4821-aa6b-d80d9c97d470	/         	btrfs     	rw,relatime,autodefrag,compress=zstd:2,space_cache,subvol=root	0 0

So /boot/loader/entries/booster.conf should look like this:

    title Linux with Booster
    linux /vmlinuz-linux
    initrd /booster-linux.img
    options root=UUID=69bc4dd2-7f6c-4821-aa6b-d80d9c97d470 rw rootflags=relatime,autodefrag,compress=zstd:2,space_cache,subvol=root

Booster has no built-in Btrfs subvolume default. If `subvol=` (or `subvolid=`) is omitted, the kernel mounts the filesystem's configured default subvolume — set with `btrfs subvolume set-default <id> <path>` — falling back to the top-level subvolume (ID 5) when no default has been configured. Distro conventions like `@` (Arch), `root` (some Debian-derived installers), or `@/.snapshots/N/snapshot` (openSUSE) must be set explicitly in your bootloader entry; both `subvol=NAME` and `subvolid=ID` are accepted.

Build a Unified Kernel Image via kernel-install (with `/etc/kernel/install.conf` configured for the UKI layout as described under UNIFIED KERNEL IMAGE):

    # kernel-install add "$(uname -r)" /usr/lib/modules/"$(uname -r)"/vmlinuz

## COPYRIGHT
Booster is Copyright (C) 2020 Anatol Pomazau <http://github.com/anatol>

## SEE ALSO
Project homepage <https://github.com/anatol/booster>
