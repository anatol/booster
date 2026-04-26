#!/usr/bin/env bash
#
# Generates a LUKS2 image with a systemd-tpm2 token in v252–254 format:
# tpm2_srk present (persistent SRK at 0x81000001) but no tpm2_salt,
# with PIN auth using authValue = SHA256_trimmed(pin).
#
# This tests booster's backward-compat path for users who enrolled with
# systemd v252–254 before the salted PBKDF2 PIN auth was introduced in v255.
#
# Requires: swtpm, tpm2-tools (tpm2_create, tpm2_createprimary, tpm2_evictcontrol)

set -euo pipefail
trap 'quit' EXIT

success=0
swtpm_pid=
dir=
lodev=
tmpdir=$(mktemp -d)
T="${tmpdir}/t"

quit() {
  set +o errexit
  swtpm_ioctl --tcp :2322 -s 2>/dev/null
  wait "${swtpm_pid}" 2>/dev/null
  # On success save the swtpm state (including the provisioned SRK) back to
  # pristine so test runs can unseal against the same SRK.
  if [ "${success}" = "1" ] && [ -f "assets/tpm2.generate/tpm2-00.permall" ]; then
    sudo cp "assets/tpm2.generate/tpm2-00.permall" "assets/tpm2/tpm2-00.permall.pristine"
    sudo chown "${USER}": "assets/tpm2/tpm2-00.permall.pristine"
  fi
  rm -rf assets/tpm2.generate "${tmpdir}"
  [ -n "${dir}" ] && { sudo umount "${dir}" 2>/dev/null; rm -r "${dir}"; }
  sudo cryptsetup close luks-booster-tpm2-legacy >/dev/null 2>&1 || true
  [ -n "${lodev}" ] && sudo losetup -d "${lodev}" >/dev/null 2>&1 || true
}

TCTI="swtpm:host=localhost,port=2321"

rm -rf assets/tpm2.generate
mkdir assets/tpm2.generate
cp assets/tpm2/tpm2-00.permall.pristine assets/tpm2.generate/tpm2-00.permall
swtpm socket --tpmstate dir=assets/tpm2.generate --tpm2 \
  --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear &
swtpm_pid=$!

for i in $(seq 1 50); do
  swtpm_ioctl --tcp :2322 --ping 2>/dev/null && break
  sleep 0.1
done

# Ensure the SRK is provisioned at 0x81000001.  If the pristine was generated
# without tpm2-tools the SRK may be absent; provision it now.
if ! TPM2TOOLS_TCTI="${TCTI}" tpm2_readpublic -c 0x81000001 &>/dev/null; then
  TPM2TOOLS_TCTI="${TCTI}" \
    tpm2_createprimary -C o -g sha256 -G ecc \
    -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt" \
    -c "${T}.srk.ctx"
  TPM2TOOLS_TCTI="${TCTI}" tpm2_evictcontrol -C o -c "${T}.srk.ctx" 0x81000001
  rm -f "${T}.srk.ctx"
fi

# PCR policy for PCRs 10+13 with password extension (PCRs are 0 in fresh swtpm).
# tpm2_policypassword -L saves the final policy digest after both PCR and
# password commands; no separate policygetdigest tool needed in tpm2-tools 5.x.
TPM2TOOLS_TCTI="${TCTI}" tpm2_startauthsession --policy-session -S "${T}.sess"
TPM2TOOLS_TCTI="${TCTI}" tpm2_policypcr      -S "${T}.sess" -l sha256:10,13
TPM2TOOLS_TCTI="${TCTI}" tpm2_policypassword -S "${T}.sess" -L "${T}.policy"
POLICY_HASH=$(python3 -c "print(open('${T}.policy','rb').read().hex())")
TPM2TOOLS_TCTI="${TCTI}" tpm2_flushcontext -l

# authValue = SHA256_trimmed(pin) — the pre-v255 convention, no PBKDF2.
PIN_AUTH_HEX=$(python3 -c "
import hashlib
h = bytearray(hashlib.sha256('${CRYPTENROLL_TPM2_PIN}'.encode()).digest())
while h and h[-1] == 0:
    h = h[:-1]
print(bytes(h).hex())
")

# Generate the random key that will be sealed; the LUKS slot passphrase is
# base64(raw_key) to match booster's recoverSystemdTPM2Password return value.
openssl rand 32 > "${T}.rawkey"
LUKS_TPM_PASSPHRASE=$(base64 -w0 "${T}.rawkey")

# Seal raw_key against the SRK with the PCR+password policy and PIN authValue.
TPM2TOOLS_TCTI="${TCTI}" \
  tpm2_create -C 0x81000001 \
  -i "${T}.rawkey" \
  -L "${T}.policy" \
  -p "hex:${PIN_AUTH_HEX}" \
  -u "${T}.pub" -r "${T}.priv"

# systemd-tpm2 blob: TPM2B_PRIVATE || TPM2B_PUBLIC (each size-prefixed big-endian,
# exactly as tpm2_create writes them — matches parseSystemdTPM2Blob's wire format).
cat "${T}.priv" "${T}.pub" > "${T}.blob"

# Build the token JSON.  tpm2_srk is present (IESYS_RESOURCE_SERIALIZE format,
# 10-byte header encoding handle 0x81000001) but tpm2_salt is intentionally
# absent — this is the v252–254 format that predates the salted PIN in v255.
python3 > "${T}.token.json" << PYEOF
import json, base64, struct

blob_b64 = base64.b64encode(open("${T}.blob", "rb").read()).decode()

# Minimal IESYS_RESOURCE_SERIALIZE: magic(4) + version(2) + handle(4).
# extractSRKHandle parses this and returns Handle(0x81000001).
srk_b64 = base64.b64encode(struct.pack(">IHI", 0x69657379, 1, 0x81000001)).decode()

print(json.dumps({
    "type": "systemd-tpm2",
    "keyslots": ["1"],
    "tpm2-blob": blob_b64,
    "tpm2-pcrs": [10, 13],
    "tpm2-pcr-bank": "sha256",
    "tpm2-primary-alg": "ecc",
    "tpm2-policy-hash": "${POLICY_HASH}",
    "tpm2-pin": True,
    "tpm2_srk": srk_b64,
    # tpm2_salt absent: simulates systemd v252-254 (SHA256 PIN, no PBKDF2)
}))
PYEOF

# Write passphrases to temp files so cryptsetup never reads stdin.
# Avoids conflicts with sudo's PAM/FIDO2 authentication when running non-interactively.
printf '%s' "${LUKS_PASSWORD}"       > "${T}.lukspass"
printf '%s' "${LUKS_TPM_PASSPHRASE}" > "${T}.tpmpass"

# Create the LUKS2 image.
truncate --size 40M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}" | grep -Em1 '^/dev/loop[0-9]+$')
sudo cryptsetup luksFormat --batch-mode --uuid "${LUKS_UUID}" --type luks2 \
  --key-file "${T}.lukspass" "${lodev}"

# Add TPM key slot (slot 1) authenticated by the temporary passphrase slot.
sudo cryptsetup luksAddKey --batch-mode --key-slot 1 \
  --key-file "${T}.lukspass" "${lodev}" "${T}.tpmpass"

# Import the token (associates it with slot 1).
sudo cryptsetup token import "${lodev}" < "${T}.token.json"

# Populate the filesystem.
sudo cryptsetup open --disable-external-tokens --type luks2 \
  --key-file "${T}.lukspass" "${lodev}" luks-booster-tpm2-legacy
sudo mkfs.ext4 -U "${FS_UUID}" -L atestlabel12 "/dev/mapper/luks-booster-tpm2-legacy"
dir=$(mktemp -d)
sudo mount "/dev/mapper/luks-booster-tpm2-legacy" "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"

# Remove passphrase slot so only the TPM-PIN slot remains.
sudo cryptsetup luksKillSlot --batch-mode --key-file "${T}.tpmpass" "${lodev}" 0

success=1
