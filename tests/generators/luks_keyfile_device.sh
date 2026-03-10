#!/usr/bin/env bash
# Creates two disk images:
#   $OUTPUT        — LUKS2 root disk, unlocked by keyfile only (no password slot)
#   $KEYDEV_OUTPUT — small ext4 "key device" containing the keyfile at /keyfile
#
# Required env vars:
#   OUTPUT          path for the LUKS root image
#   KEYDEV_OUTPUT   path for the key device image
#   LUKS_UUID       UUID for the LUKS container
#   FS_UUID         UUID for the ext4 filesystem inside LUKS
#   KEYDEV_UUID     UUID for the ext4 key device filesystem

set -o errexit

LUKS_DEV_NAME="luks-${LUKS_UUID}"
KEYFILE=$(mktemp)

rootlodev=
keylodev=
rootdir=
keydir=

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  [ -n "${rootdir}" ]   && { sudo umount "${rootdir}"; rm -rf "${rootdir}"; }
  [ -n "${keydir}" ]    && { sudo umount "${keydir}";  rm -rf "${keydir}"; }
  sudo cryptsetup close "${LUKS_DEV_NAME}" 2>/dev/null || true
  [ -n "${rootlodev}" ] && sudo losetup -d "${rootlodev}"
  [ -n "${keylodev}" ]  && sudo losetup -d "${keylodev}"
  rm -f "${KEYFILE}"
}

# Generate a random binary keyfile
dd if=/dev/urandom of="${KEYFILE}" bs=512 count=8 status=none

# --- key device: small ext4 image containing the keyfile ---
truncate --size 10M "${KEYDEV_OUTPUT}"
mkfs.ext4 -U "${KEYDEV_UUID}" "${KEYDEV_OUTPUT}"
keylodev=$(sudo losetup -f --show "${KEYDEV_OUTPUT}")
keydir=$(mktemp -d)
sudo mount "${keylodev}" "${keydir}"
sudo chown "${USER}" "${keydir}"
cp "${KEYFILE}" "${keydir}/keyfile"
sudo umount "${keydir}"
rm -rf "${keydir}"; keydir=
sudo losetup -d "${keylodev}"; keylodev=

# --- LUKS root disk: keyfile-only (no password slot) ---
truncate --size 40M "${OUTPUT}"
rootlodev=$(sudo losetup -f --show "${OUTPUT}")
sudo cryptsetup luksFormat --uuid "${LUKS_UUID}" --type luks2 \
  --key-file "${KEYFILE}" "${rootlodev}"
sudo cryptsetup open --key-file "${KEYFILE}" "${rootlodev}" "${LUKS_DEV_NAME}"
sudo mkfs.ext4 -U "${FS_UUID}" "/dev/mapper/${LUKS_DEV_NAME}"
rootdir=$(mktemp -d)
sudo mount "/dev/mapper/${LUKS_DEV_NAME}" "${rootdir}"
sudo chown "${USER}" "${rootdir}"
mkdir "${rootdir}/sbin"
cp assets/init "${rootdir}/sbin/init"
