#!/usr/bin/env bash

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  swtpm_ioctl --tcp :2322 -s
  rm -rf assets/tpm2.generate
  rm assets/cryptenroll.passphrase
  sudo umount "${dir}"
  rm -r "${dir}"
  sudo cryptsetup close "${LUKS_DEV_NAME}"
  sudo losetup -d "${lodev}"
}

LUKS_DEV_NAME=luks-booster-systemd

mkdir assets/tpm2.generate
cp assets/tpm2/tpm2-00.permall.pristine assets/tpm2.generate/tpm2-00.permall
swtpm socket --tpmstate dir=assets/tpm2.generate --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &

truncate --size 40M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}")
sudo cryptsetup luksFormat --uuid "${LUKS_UUID}" --type luks2 "${lodev}" <<< "${LUKS_PASSWORD}"

printf '%s' "${LUKS_PASSWORD}" > assets/cryptenroll.passphrase
# it looks like edk2 extends PCR 0-7 so let's use some other PCR outside of this range
if [ "${CRYPTENROLL_TPM2_PIN}" != "" ]; then
  printf '%s' "${CRYPTENROLL_TPM2_PIN}" > assets/cryptenroll.tpm2-pin
  sudo CREDENTIALS_DIRECTORY="$(pwd)/assets" systemd-cryptenroll --tpm2-device=swtpm: --tpm2-pcrs=10+13 --tpm2-with-pin=true "${lodev}"
else
  sudo CREDENTIALS_DIRECTORY="$(pwd)/assets" systemd-cryptenroll --tpm2-device=swtpm: --tpm2-pcrs=10+13 "${lodev}"
fi

sudo cryptsetup open --disable-external-tokens --type luks2 "${lodev}" "${LUKS_DEV_NAME}" <<< "${LUKS_PASSWORD}"
sudo mkfs.ext4 -U "${FS_UUID}" -L atestlabel12 "/dev/mapper/${LUKS_DEV_NAME}"
dir=$(mktemp -d)
sudo mount "/dev/mapper/${LUKS_DEV_NAME}" "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"

if [ "${CRYPTENROLL_TPM2_PIN}" != "" ]; then
  sudo cryptsetup -v luksKillSlot "${lodev}" 0
fi
