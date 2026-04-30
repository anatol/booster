#!/usr/bin/env bash

trap 'quit' EXIT ERR

success=0
swtpm_pid=

quit() {
  set +o errexit
  swtpm_ioctl --tcp :2322 -s 2>/dev/null
  wait "${swtpm_pid}" 2>/dev/null  # ensure state is fully written to disk before copying
  # On success, save the swtpm state back as pristine. With systemd v252+ the
  # SRK is provisioned into the TPM during enrollment; tests need this state so
  # booster can load the sealed key from handle 0x81000001.
  if [ "${success}" = "1" ] && [ -f "assets/tpm2.generate/tpm2-00.permall" ]; then
    sudo cp "assets/tpm2.generate/tpm2-00.permall" "assets/tpm2/tpm2-00.permall.pristine"
    sudo chown "${USER}": "assets/tpm2/tpm2-00.permall.pristine"
  fi
  rm -rf assets/tpm2.generate
  rm -f assets/cryptenroll.passphrase assets/cryptenroll.tpm2-pin assets/cryptenroll.new-tpm2-pin
  sudo umount "${dir}"
  rm -r "${dir}"
  sudo cryptsetup close "${LUKS_DEV_NAME}"
  sudo losetup -d "${lodev}"
}

LUKS_DEV_NAME=luks-booster-systemd

rm -rf assets/tpm2.generate
mkdir assets/tpm2.generate
cp assets/tpm2/tpm2-00.permall.pristine assets/tpm2.generate/tpm2-00.permall
swtpm socket --tpmstate dir=assets/tpm2.generate --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
swtpm_pid=$!

# Wait for swtpm to be ready before running cryptenroll, otherwise it may fall
# back to the real hardware TPM (/dev/tpm0) if present on the host.
for i in $(seq 1 50); do
  swtpm_ioctl --tcp :2322 --ping 2>/dev/null && break
  sleep 0.1
done

truncate --size 40M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}")
sudo cryptsetup luksFormat --uuid "${LUKS_UUID}" --type luks2 "${lodev}" <<< "${LUKS_PASSWORD}"

printf '%s' "${LUKS_PASSWORD}" > assets/cryptenroll.passphrase
# it looks like edk2 extends PCR 0-7 so let's use some other PCR outside of this range.
# Pass SWTPM env vars explicitly so systemd-cryptenroll uses our TCP swtpm rather
# than any real hardware TPM that may be present on the host.
# CRYPTENROLL_TPM2_PCRS controls PCR binding. Defaults to 10+13; set to empty
# string to enroll without PCR binding (tests the no-PCR policy path).
PCRS_FLAG="--tpm2-pcrs=${CRYPTENROLL_TPM2_PCRS:-10+13}"

if [ "${CRYPTENROLL_TPM2_PIN}" != "" ]; then
  # cryptenroll.new-tpm2-pin is the credential name for setting a new PIN during enrollment
  printf '%s' "${CRYPTENROLL_TPM2_PIN}" > assets/cryptenroll.new-tpm2-pin
  # Use sudo env so CREDENTIALS_DIRECTORY survives sudo's env_reset.
  # Pass the full TCTI string directly so cryptenroll cannot fall back to /dev/tpm0.
  sudo env CREDENTIALS_DIRECTORY="$(pwd)/assets" \
    systemd-cryptenroll --tpm2-device="swtpm:host=localhost,port=2321" \
    "${PCRS_FLAG}" --tpm2-with-pin=true "${lodev}"
else
  sudo env CREDENTIALS_DIRECTORY="$(pwd)/assets" \
    systemd-cryptenroll --tpm2-device="swtpm:host=localhost,port=2321" \
    "${PCRS_FLAG}" "${lodev}"
fi

sudo cryptsetup open --disable-external-tokens --type luks2 "${lodev}" "${LUKS_DEV_NAME}" <<< "${LUKS_PASSWORD}"
sudo mkfs.ext4 -U "${FS_UUID}" -L atestlabel12 "/dev/mapper/${LUKS_DEV_NAME}"
dir=$(mktemp -d)
sudo mount "/dev/mapper/${LUKS_DEV_NAME}" "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"

if [ "${CRYPTENROLL_TPM2_PIN}" != "" ] && [ "${KEEP_PASSPHRASE_SLOT}" != "1" ]; then
  sudo cryptsetup -v luksKillSlot "${lodev}" 0
fi

success=1
