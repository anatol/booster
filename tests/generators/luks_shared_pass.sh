#!/usr/bin/env bash
# Creates a single GPT disk with two LUKS2 partitions sharing the same passphrase.
#
#   Partition 1 (extra): LUKS2, UUID=$LUKS_UUID1 — no inner filesystem
#   Partition 2 (root):  LUKS2, UUID=$LUKS_UUID2 → ext4, UUID=$FS_UUID
#
# Used by TestPassphraseCache to verify that when two concurrent LUKS unlocks
# share the same passphrase the user is prompted exactly once (issue #306).
#
# Required env vars:
#   OUTPUT        path for the disk image
#   LUKS_UUID1    UUID of the first (extra) LUKS2 container
#   LUKS_UUID2    UUID of the second (root)  LUKS2 container
#   FS_UUID       UUID of the ext4 filesystem inside the root container
#   LUKS_PASSWORD passphrase used for both LUKS containers

set -o errexit

lodev=
dir=
MAPPER="luks-root-${LUKS_UUID2}"

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  [ -n "${dir}" ] && { sudo umount "${dir}" 2>/dev/null; rm -rf "${dir}"; }
  sudo cryptsetup close "${MAPPER}" 2>/dev/null || true
  [ -n "${lodev}" ] && sudo losetup -d "${lodev}"
}

truncate --size 60M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}" | grep -m1 '^/dev/')

sudo parted -s "${lodev}" mklabel gpt \
  mkpart extra 2MiB 28MiB \
  mkpart root  28MiB 58MiB

sudo partprobe "${lodev}"
sleep 0.5

sudo cryptsetup luksFormat --uuid "${LUKS_UUID1}" --type luks2 "${lodev}p1" <<< "${LUKS_PASSWORD}"
sudo cryptsetup luksFormat --uuid "${LUKS_UUID2}" --type luks2 "${lodev}p2" <<< "${LUKS_PASSWORD}"

sudo cryptsetup open "${lodev}p2" "${MAPPER}" <<< "${LUKS_PASSWORD}"
sudo mkfs.ext4 -U "${FS_UUID}" "/dev/mapper/${MAPPER}"
dir=$(mktemp -d)
sudo mount "/dev/mapper/${MAPPER}" "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"
