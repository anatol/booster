#!/usr/bin/env bash

# Generates a LUKS2 image whose volume key is enrolled to a *signed* (authorized)
# TPM2 PCR policy: systemd-cryptenroll --tpm2-public-key binds the key to a
# public key rather than to literal PCR values, and a detached signature
# (systemd-measure sign) authorizes the PCR 11 boot-phase state at unlock.
#
# This is the only test that exercises booster's signed-policy path end-to-end
# against REAL systemd artifacts: a real systemd-cryptenroll signed token (whose
# tpm2_pubkey is base64-of-PEM — the exact byte format that broke a green unit
# suite) and a real systemd-measure signature. The swtpm unit tests in
# init/tpm_signed_test.go build their own token and sign their own policy, so
# they are self-consistent and cannot catch interop drift; this can.
#
# How the PCR 11 match works WITHOUT a UKI: edk2 in the QEMU guest only extends
# PCR 0-7 (see systemd_tpm2.sh), so PCR 11 is still 0 when booster runs. Booster
# then extends just the "enter-initrd" phase word (the barrier it applies in
# place of systemd-pcrphase), so at unseal PCR 11 = SHA256(0^32 ||
# SHA256("enter-initrd")) and the policy is the canonical TPM2 PolicyPCR digest
# over that value. (A real UKI boot would also have the stub measure the
# kernel/initrd sections into PCR 11 first — that layer is validated only on
# real hardware.)
#
# We sign that canonical digest directly rather than with systemd-measure:
# `systemd-measure sign --current` emits a NON-canonical PolicyPCR digest in this
# bare-swtpm scenario (one no TPM PolicyPCR session reproduces), so it cannot be
# the oracle here. The digest computed below was verified byte-identical to both
# `tpm2_policypcr` (the reference implementation) and booster's own live-TPM
# computation. The token itself is still a real systemd-cryptenroll
# --tpm2-public-key enrollment, so booster's token parsing (the base64(PEM)
# tpm2_pubkey path) is exercised end-to-end; and the test is self-checking — if
# this digest were wrong, booster (computing via the real TPM at unseal) would
# not match and the boot would fall through to the passphrase.

trap 'quit' EXIT ERR

success=0
swtpm_pid=

quit() {
  set +o errexit
  swtpm_ioctl --tcp :2322 -s 2>/dev/null
  wait "${swtpm_pid}" 2>/dev/null  # ensure state is fully written before copying
  # On success keep the swtpm state pristine for the next run: systemd v252+
  # provisions the SRK during enrollment and booster loads the sealed key from
  # persistent handle 0x81000001, so that state must survive into the guest.
  if [ "${success}" = "1" ] && [ -f "assets/tpm2.generate/tpm2-00.permall" ]; then
    sudo cp "assets/tpm2.generate/tpm2-00.permall" "assets/tpm2/tpm2-00.permall.pristine"
    sudo chown "${USER}": "assets/tpm2/tpm2-00.permall.pristine"
  fi
  rm -rf assets/tpm2.generate
  rm -f assets/cryptenroll.passphrase
  if [ "${success}" != "1" ]; then
    # Remove the partial image and signature so a failed run never poisons the
    # asset cache (the framework keys only on the .img and would skip a rebuild).
    rm -f "${OUTPUT}" "${SIG_OUTPUT}" assets/systemd-tpm2-signed.pcr-public.pem
  fi
  rm -f assets/systemd-tpm2-signed.pcr-private.pem
  sudo umount "${dir}"
  rm -r "${dir}"
  sudo cryptsetup close "${LUKS_DEV_NAME}"
  sudo losetup -d "${lodev}"
}

LUKS_DEV_NAME=luks-booster-systemd-signed
# Where the detached signature is written. The Go test embeds this file into the
# initramfs via extra_files and points booster at it with
# rd.luks.options=tpm2-signature=<this path> (a non-UKI boot has no
# /.extra/tpm2-pcr-signature.json for booster to auto-discover).
SIG_OUTPUT=${SIG_OUTPUT:-assets/systemd-tpm2-signed.pcrsig.json}
PRIV_KEY=assets/systemd-tpm2-signed.pcr-private.pem
PUB_KEY=assets/systemd-tpm2-signed.pcr-public.pem

rm -rf assets/tpm2.generate
mkdir assets/tpm2.generate
cp assets/tpm2/tpm2-00.permall.pristine assets/tpm2.generate/tpm2-00.permall
swtpm socket --tpmstate dir=assets/tpm2.generate --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
swtpm_pid=$!

# Wait for swtpm to be ready before cryptenroll, otherwise it may fall back to a
# real hardware TPM (/dev/tpm0) if one is present on the host.
for i in $(seq 1 50); do
  swtpm_ioctl --tcp :2322 --ping 2>/dev/null && break
  sleep 0.1
done

# RSA signing key for the authorized policy (RSA-only: booster verifies with
# TPM2_VerifySignature over an RSASSA/SHA256 signature).
openssl genrsa -out "${PRIV_KEY}" 2048
openssl rsa -in "${PRIV_KEY}" -pubout -out "${PUB_KEY}"

truncate --size 40M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}")
sudo cryptsetup luksFormat --uuid "${LUKS_UUID}" --type luks2 "${lodev}" <<< "${LUKS_PASSWORD}"

printf '%s' "${LUKS_PASSWORD}" > assets/cryptenroll.passphrase

# Enroll a signed (authorized) policy bound to PCR 11. The key is bound to the
# public key, not to a literal PCR value, so enrollment needs no particular
# PCR 11 state. Pass the full TCTI so cryptenroll cannot fall back to /dev/tpm0.
sudo env CREDENTIALS_DIRECTORY="$(pwd)/assets" \
  systemd-cryptenroll --tpm2-device="swtpm:host=localhost,port=2321" \
  --tpm2-public-key="${PUB_KEY}" --tpm2-public-key-pcrs=11 "${lodev}"

# Build the detached signature over the canonical PolicyPCR digest for PCR 11 at
# the enter-initrd phase value (see header for why not systemd-measure). The
# signature is RSASSA/SHA256 over the policy digest, in systemd's JSON schema.
polbin=$(mktemp)
read -r POL_HEX PKFP < <(python3 - "${PUB_KEY}" "${polbin}" <<'PY'
import sys, hashlib, struct, subprocess
pub, polbin = sys.argv[1], sys.argv[2]
# PCR 11 after booster's enter-initrd barrier, from a zero base in the guest.
pcr11 = hashlib.sha256(b"\x00" * 32 + hashlib.sha256(b"enter-initrd").digest()).digest()
# Canonical TPM2 PolicyPCR digest: H(0^32 || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || H(pcr values)).
# Selection = sha256 (0x000B), sizeofSelect 3, bit 11 set -> [00 08 00].
sel = struct.pack(">I", 1) + struct.pack(">H", 0x000B) + bytes([3, 0x00, 0x08, 0x00])
pol = hashlib.sha256(b"\x00" * 32 + struct.pack(">I", 0x0000017F) + sel + hashlib.sha256(pcr11).digest()).digest()
open(polbin, "wb").write(pol)
# pkfp = systemd's key fingerprint: SHA256 of the PKCS#1 DER public key.
der = subprocess.check_output(["openssl", "rsa", "-pubin", "-in", pub, "-RSAPublicKey_out", "-outform", "DER"], stderr=subprocess.DEVNULL)
print(pol.hex(), hashlib.sha256(der).hexdigest())
PY
)
# RSASSA/SHA256 over the policy digest (openssl dgst signs DigestInfo(SHA256, SHA256(pol))).
SIG_B64=$(openssl dgst -sha256 -sign "${PRIV_KEY}" "${polbin}" | base64 -w0)
rm -f "${polbin}"
printf '{"sha256":[{"pcrs":[11],"pkfp":"%s","pol":"%s","sig":"%s"}]}\n' \
  "${PKFP}" "${POL_HEX}" "${SIG_B64}" > "${SIG_OUTPUT}"

sudo cryptsetup open --disable-external-tokens --type luks2 "${lodev}" "${LUKS_DEV_NAME}" <<< "${LUKS_PASSWORD}"
sudo mkfs.ext4 -U "${FS_UUID}" -L atestlabel12 "/dev/mapper/${LUKS_DEV_NAME}"
dir=$(mktemp -d)
sudo mount "/dev/mapper/${LUKS_DEV_NAME}" "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"

success=1
