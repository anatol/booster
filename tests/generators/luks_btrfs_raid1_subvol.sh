#!/usr/bin/env bash
# tools: parted partprobe mkfs.btrfs btrfs cryptsetup
# Creates a single GPT disk with two LUKS2 partitions, each wrapping one member
# of a btrfs RAID1 volume, with the root tree living in a subvolume named "@".
#
#   Partition 1: LUKS2, UUID=$LUKS_UUID1 (passphrase $LUKS_PASSWORD1) → btrfs RAID1 member
#   Partition 2: LUKS2, UUID=$LUKS_UUID2 (passphrase $LUKS_PASSWORD2) → btrfs RAID1 member
#   btrfs filesystem UUID: $FS_UUID, /sbin/init lives in subvolume @
#
# Used by TestLuksBtrfsRaid1MapperRootSubvol to reproduce the reported layout
# from the "failed to mount btrfs array" issue verbatim: distinct passphrases,
# mappings from rd.luks.name=, root=/dev/mapper/<name> and rootflags=subvol=@.
# init is placed ONLY inside @, so a boot that ignores the subvol mount option
# lands on a root without /sbin/init and fails loudly rather than silently
# passing.
#
# Required env vars:
#   OUTPUT         path for the disk image
#   LUKS_UUID1     UUID of the first  LUKS2 container
#   LUKS_UUID2     UUID of the second LUKS2 container
#   FS_UUID        UUID of the btrfs filesystem spanning both containers
#   LUKS_PASSWORD1 passphrase for the first  LUKS container
#   LUKS_PASSWORD2 passphrase for the second LUKS container

set -o errexit

lodev=
dir=
MAPPER1="luks-btrfs-subvol1-${LUKS_UUID1}"
MAPPER2="luks-btrfs-subvol2-${LUKS_UUID2}"

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  [ -n "${dir}" ] && { sudo umount "${dir}" 2>/dev/null; rm -rf "${dir}"; }
  sudo cryptsetup close "${MAPPER1}" 2>/dev/null || true
  sudo cryptsetup close "${MAPPER2}" 2>/dev/null || true
  [ -n "${lodev}" ] && sudo losetup -d "${lodev}"
}

truncate --size 450M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}" | grep -m1 '^/dev/')

sudo parted -s "${lodev}" mklabel gpt \
  mkpart member1 2MiB 224MiB \
  mkpart member2 224MiB 446MiB

sudo partprobe "${lodev}"
sleep 0.5

sudo cryptsetup luksFormat --uuid "${LUKS_UUID1}" --type luks2 "${lodev}p1" <<< "${LUKS_PASSWORD1}"
sudo cryptsetup luksFormat --uuid "${LUKS_UUID2}" --type luks2 "${lodev}p2" <<< "${LUKS_PASSWORD2}"

sudo cryptsetup open "${lodev}p1" "${MAPPER1}" <<< "${LUKS_PASSWORD1}"
sudo cryptsetup open "${lodev}p2" "${MAPPER2}" <<< "${LUKS_PASSWORD2}"

sudo mkfs.btrfs -f --uuid "${FS_UUID}" -d raid1 -m raid1 \
  "/dev/mapper/${MAPPER1}" "/dev/mapper/${MAPPER2}"

dir=$(mktemp -d)
sudo mount "/dev/mapper/${MAPPER1}" "${dir}"
sudo btrfs subvolume create "${dir}/@"
sudo mkdir "${dir}/@/sbin"
sudo cp assets/init "${dir}/@/sbin/init"
