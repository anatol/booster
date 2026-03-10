#!/usr/bin/env bash
# Creates a LUKS2 image whose enrolled keyfile has a 512-byte random preamble
# (bytes 0-511) followed by 4096 bytes of actual key material (bytes 512-4607).
# At boot, crypttab must supply keyfile-offset=512,keyfile-size=4096 to skip
# the preamble and read only the real key.
#
# Required env vars:
#   OUTPUT           path for the LUKS image
#   KEYFILE_OUTPUT   path where the combined keyfile (preamble + key) is written
#   LUKS_UUID        UUID for the LUKS container
#   FS_UUID          UUID for the ext4 filesystem inside LUKS

set -o errexit

LUKS_DEV_NAME="luks-${LUKS_UUID}"
TMPKF=$(mktemp)
lodev=
rootdir=

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  [ -n "${rootdir}" ] && { sudo umount "${rootdir}"; rm -rf "${rootdir}"; }
  sudo cryptsetup close "${LUKS_DEV_NAME}" 2>/dev/null || true
  [ -n "${lodev}" ]   && sudo losetup -d "${lodev}"
  rm -f "${TMPKF}"
}

# 512 bytes of random preamble + 4096 bytes of actual key = 4608 bytes total
dd if=/dev/urandom of="${TMPKF}" bs=512 count=9 status=none
cp "${TMPKF}" "${KEYFILE_OUTPUT}"

truncate --size 40M "${OUTPUT}"
lodev=$(sudo losetup -f --show "${OUTPUT}")
sudo cryptsetup luksFormat --uuid "${LUKS_UUID}" --type luks2 \
  --key-file "${TMPKF}" --keyfile-offset 512 --keyfile-size 4096 "${lodev}"
sudo cryptsetup open \
  --key-file "${TMPKF}" --keyfile-offset 512 --keyfile-size 4096 \
  "${lodev}" "${LUKS_DEV_NAME}"
sudo mkfs.ext4 -U "${FS_UUID}" "/dev/mapper/${LUKS_DEV_NAME}"
rootdir=$(mktemp -d)
sudo mount "/dev/mapper/${LUKS_DEV_NAME}" "${rootdir}"
sudo chown "${USER}" "${rootdir}"
mkdir "${rootdir}/sbin"
cp assets/init "${rootdir}/sbin/init"
