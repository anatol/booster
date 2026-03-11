#!/usr/bin/env bash
# Creates a LUKS2 image with a detached header.
# The LUKS metadata lives in HEADER_OUTPUT; the encrypted payload lives in OUTPUT.
# At boot, crypttab must supply header=<path> (or rd.luks.header=) pointing to
# the bundled header file.
#
# Required env vars:
#   OUTPUT        path for the encrypted data image
#   HEADER_OUTPUT path where the detached header file is written
#   LUKS_UUID     UUID for the LUKS container
#   FS_UUID       UUID for the ext4 filesystem inside LUKS

set -o errexit

LUKS_DEV_NAME="luks-${LUKS_UUID}"
lodev=
rootdir=

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  [ -n "${rootdir}" ] && { sudo umount "${rootdir}"; rm -rf "${rootdir}"; }
  sudo cryptsetup close "${LUKS_DEV_NAME}" 2>/dev/null || true
  [ -n "${lodev}" ] && sudo losetup -d "${lodev}"
}

truncate --size 40M "${OUTPUT}"
truncate --size 2M  "${HEADER_OUTPUT}"

lodev=$(sudo losetup -f --show "${OUTPUT}")

# Format with detached header: metadata goes to HEADER_OUTPUT, payload to lodev
sudo cryptsetup luksFormat \
  --type luks2 \
  --uuid "${LUKS_UUID}" \
  --header "${HEADER_OUTPUT}" \
  "${lodev}" <<< "1234"

sudo cryptsetup open \
  --header "${HEADER_OUTPUT}" \
  "${lodev}" "${LUKS_DEV_NAME}" <<< "1234"

sudo mkfs.ext4 -U "${FS_UUID}" "/dev/mapper/${LUKS_DEV_NAME}"
rootdir=$(mktemp -d)
sudo mount "/dev/mapper/${LUKS_DEV_NAME}" "${rootdir}"
sudo chown "${USER}" "${rootdir}"
mkdir "${rootdir}/sbin"
cp assets/init "${rootdir}/sbin/init"
