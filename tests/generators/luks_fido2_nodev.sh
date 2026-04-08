#!/usr/bin/env bash
#
# Creates a LUKS2 image with a fake systemd-fido2 token injected directly
# into the LUKS2 metadata.  The credential and salt are random bytes that
# will never match any real FIDO2 device.  This is used to test that booster
# correctly waits token-timeout seconds for a FIDO2 device and then falls
# back to the keyboard passphrase prompt.

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount "${dir}" 2>/dev/null || true
  rm -r "${dir}" 2>/dev/null || true
  sudo cryptsetup close "${LUKS_DEV_NAME}" 2>/dev/null || true
  sudo losetup -d "${lodev}" 2>/dev/null || true
}

LUKS_DEV_NAME=luks-booster-fido2nodev

truncate --size 40M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}")
sudo cryptsetup luksFormat --uuid "${LUKS_UUID}" --type luks2 "${lodev}" <<< "${LUKS_PASSWORD}"

# Inject a fake systemd-fido2 token.  Random credential/salt ensure it will
# never successfully authenticate against any real device.  Booster will
# find the token, wait token-timeout for a matching hidraw device, then fall
# back to the keyboard prompt.
FAKE_CREDENTIAL=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 -w0)
FAKE_SALT=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 -w0)
printf '{"type":"systemd-fido2","keyslots":["0"],"fido2-credential":"%s","fido2-salt":"%s","fido2-rp":"io.systemd.cryptsetup","fido2-clientPin-required":false,"fido2-up-required":true,"fido2-uv-required":false}' \
    "${FAKE_CREDENTIAL}" "${FAKE_SALT}" \
    | sudo cryptsetup token import --json-file=- "${lodev}"

sudo cryptsetup open --disable-external-tokens --type luks2 "${lodev}" "${LUKS_DEV_NAME}" <<< "${LUKS_PASSWORD}"
sudo mkfs.ext4 -U "${FS_UUID}" -L atestlabel12 "/dev/mapper/${LUKS_DEV_NAME}"
dir=$(mktemp -d)
sudo mount "/dev/mapper/${LUKS_DEV_NAME}" "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"
