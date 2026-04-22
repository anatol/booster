#!/usr/bin/env bash
# Creates a single GPT disk with two LUKS2 partitions, each wrapping one member
# of a btrfs RAID1 volume.  Both partitions share the same passphrase.
#
#   Partition 1: LUKS2, UUID=$LUKS_UUID1 → btrfs RAID1 member
#   Partition 2: LUKS2, UUID=$LUKS_UUID2 → btrfs RAID1 member
#   btrfs filesystem UUID: $FS_UUID
#
# Used by TestLuksBtrfsRaid1 to verify that both LUKS members unlock with a
# single passphrase prompt and btrfs assembles correctly.
#
# Required env vars:
#   OUTPUT        path for the disk image
#   LUKS_UUID1    UUID of the first  LUKS2 container
#   LUKS_UUID2    UUID of the second LUKS2 container
#   FS_UUID       UUID of the btrfs filesystem spanning both containers
#   LUKS_PASSWORD passphrase used for both LUKS containers

set -o errexit

lodev=
dir=
MAPPER1="luks-btrfs1-${LUKS_UUID1}"
MAPPER2="luks-btrfs2-${LUKS_UUID2}"

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

sudo cryptsetup luksFormat --uuid "${LUKS_UUID1}" --type luks2 "${lodev}p1" <<< "${LUKS_PASSWORD}"
sudo cryptsetup luksFormat --uuid "${LUKS_UUID2}" --type luks2 "${lodev}p2" <<< "${LUKS_PASSWORD}"

sudo cryptsetup open "${lodev}p1" "${MAPPER1}" <<< "${LUKS_PASSWORD}"
sudo cryptsetup open "${lodev}p2" "${MAPPER2}" <<< "${LUKS_PASSWORD}"

sudo mkfs.btrfs -f --uuid "${FS_UUID}" -d raid1 -m raid1 \
  "/dev/mapper/${MAPPER1}" "/dev/mapper/${MAPPER2}"

dir=$(mktemp -d)
sudo mount "/dev/mapper/${MAPPER1}" "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"
