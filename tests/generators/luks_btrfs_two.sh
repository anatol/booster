#!/usr/bin/env bash
# Creates two LUKS2-encrypted disk images whose decrypted contents form a
# single btrfs RAID1 filesystem.  Used to test multi-device btrfs with
# encrypted drives (shared and distinct passphrases).
#
# Required env vars:
#   OUTPUT           path for the first LUKS image
#   OUTPUT2          path for the second LUKS image
#   LUKS_UUID1       UUID for the first LUKS container
#   LUKS_UUID2       UUID for the second LUKS container
#   LUKS_PASSWORD1   passphrase for the first LUKS container
#   LUKS_PASSWORD2   passphrase for the second LUKS container
#   FS_UUID          btrfs filesystem UUID (shared across both member devices)

set -o errexit

DEV1_NAME="luks-${LUKS_UUID1}"
DEV2_NAME="luks-${LUKS_UUID2}"
lodev1=
lodev2=
rootdir=

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  [ -n "${rootdir}" ] && { sudo umount "${rootdir}"; rm -rf "${rootdir}"; }
  sudo cryptsetup close "${DEV1_NAME}" 2>/dev/null || true
  sudo cryptsetup close "${DEV2_NAME}" 2>/dev/null || true
  [ -n "${lodev1}" ] && sudo losetup -d "${lodev1}"
  [ -n "${lodev2}" ] && sudo losetup -d "${lodev2}"
}

truncate --size 300M "${OUTPUT}"
truncate --size 300M "${OUTPUT2}"

lodev1=$(sudo losetup -f --show "${OUTPUT}")
lodev2=$(sudo losetup -f --show "${OUTPUT2}")

echo -n "${LUKS_PASSWORD1}" | sudo cryptsetup luksFormat --uuid "${LUKS_UUID1}" --type luks2 --key-file=- "${lodev1}"
echo -n "${LUKS_PASSWORD2}" | sudo cryptsetup luksFormat --uuid "${LUKS_UUID2}" --type luks2 --key-file=- "${lodev2}"

echo -n "${LUKS_PASSWORD1}" | sudo cryptsetup open --key-file=- "${lodev1}" "${DEV1_NAME}"
echo -n "${LUKS_PASSWORD2}" | sudo cryptsetup open --key-file=- "${lodev2}" "${DEV2_NAME}"

sudo mkfs.btrfs --uuid "${FS_UUID}" -d raid1 -m raid1 \
  "/dev/mapper/${DEV1_NAME}" "/dev/mapper/${DEV2_NAME}"

rootdir=$(mktemp -d)
sudo mount "/dev/mapper/${DEV1_NAME}" "${rootdir}"
sudo chown "${USER}" "${rootdir}"
mkdir "${rootdir}/sbin"
cp assets/init "${rootdir}/sbin/init"
