#!/usr/bin/env bash

if ! [ -d /var/lib/swtpm-localca ]; then
  sudo mkdir /var/lib/swtpm-localca
fi
sudo chown "${USER}" /var/lib/swtpm-localca

mkdir assets/tpm2
swtpm_setup --tpm-state assets/tpm2 --tpm2 --ecc --create-ek-cert --create-platform-cert --lock-nvram
# swtpm_setup may leave the state directory and files owned by root; fix so the
# test framework (running as the normal user) can read and copy the pristine.
sudo chown -R "${USER}": assets/tpm2

# Provision a persistent SRK at handle 0x81000001 if tpm2-tools are available.
# systemd-cryptenroll v252+ calls tpm2_get_or_create_srk during enrollment, so
# it will provision the SRK automatically on the first enrollment run and the
# systemd_tpm2.sh quit trap will save the result back to this pristine.
# Pre-provisioning here is optional but makes the pristine self-contained for
# the systemd_tpm2_legacy_pin.sh generator (which uses tpm2-tools directly).
if command -v tpm2_createprimary &>/dev/null && command -v tpm2_evictcontrol &>/dev/null; then
  swtpm socket --tpmstate dir=assets/tpm2 --tpm2 \
    --server type=tcp,port=12321 --ctrl type=tcp,port=12322 \
    --flags not-need-init,startup-clear &
  swtpm_pid=$!

  for i in $(seq 1 50); do
    swtpm_ioctl --tcp :12322 --ping 2>/dev/null && break
    sleep 0.1
  done

  srk_ctx=$(mktemp --suffix=.ctx)
  TPM2TOOLS_TCTI="swtpm:host=localhost,port=12321" \
    tpm2_createprimary -C o -g sha256 -G ecc \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" \
    -c "${srk_ctx}"
  TPM2TOOLS_TCTI="swtpm:host=localhost,port=12321" \
    tpm2_evictcontrol -C o -c "${srk_ctx}" 0x81000001
  rm -f "${srk_ctx}"

  swtpm_ioctl --tcp :12322 -s
  wait "${swtpm_pid}"
fi

mv assets/tpm2/tpm2-00.permall assets/tpm2/tpm2-00.permall.pristine
