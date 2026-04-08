#!/usr/bin/env bash
#
# Creates a LUKS2 image with FIDO2 enrolled via systemd-cryptenroll.
#
# cryptsetup luksFormat and systemd-cryptenroll both support regular files
# directly, so we avoid loop devices (and the udev/blkid lock conflicts they
# trigger) until the final mount step.

set -euo pipefail
trap 'quit' EXIT

quit() {
  trap - EXIT
  [ -n "${cred_dir:-}" ] && rm -rf "${cred_dir}"
  sudo umount "${dir}" 2>/dev/null || true
  rm -rf "${dir}" 2>/dev/null || true
  sudo cryptsetup close "${LUKS_DEV_NAME}" 2>/dev/null || true
  [ -n "${lodev:-}" ] && sudo losetup -d "${lodev}" 2>/dev/null || true
}

LUKS_DEV_NAME=luks-booster-systemd
cred_dir=
dir=
lodev=

# Format directly on the image file — no loop device or kernel involvement,
# so no udev races.
truncate --size 40M "${OUTPUT}"
cryptsetup luksFormat --uuid "${LUKS_UUID}" --type luks2 "${OUTPUT}" <<< "${LUKS_PASSWORD}"

# Enroll FIDO2 directly on the file (systemd-cryptenroll supports regular
# files for LUKS2).  Run as the current user so it can access the FIDO2
# device via seat-based udev permissions.
#
# Store credentials in XDG_RUNTIME_DIR (tmpfs on systemd systems — PIN stays
# in RAM, never touches disk).  systemd-cryptenroll requires regular files;
# names must match exactly what it looks for.
cred_dir=$(mktemp -d -p "${XDG_RUNTIME_DIR:-/tmp}")
printf '%s' "${LUKS_PASSWORD}" > "${cred_dir}/cryptenroll.passphrase"
printf '%s' "${FIDO2_PIN}" > "${cred_dir}/cryptenroll.fido2-pin"
CREDENTIALS_DIRECTORY="${cred_dir}" systemd-cryptenroll --fido2-device=auto --fido2-with-client-pin=yes "${OUTPUT}"
rm -rf "${cred_dir}"; cred_dir=

# Now attach as a loop device only for the mount step.  By this point the
# LUKS2 header is fully written; udev will probe and see it quickly.
lodev=$(sudo losetup -f --show "${OUTPUT}")
udevadm settle --timeout=10 || true

sudo cryptsetup open --disable-external-tokens --disable-locks --type luks2 "${lodev}" "${LUKS_DEV_NAME}" <<< "${LUKS_PASSWORD}"
sudo mkfs.ext4 -U "${FS_UUID}" -L atestlabel12 "/dev/mapper/${LUKS_DEV_NAME}"
dir=$(mktemp -d)
sudo mount "/dev/mapper/${LUKS_DEV_NAME}" "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"
