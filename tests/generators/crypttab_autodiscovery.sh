#!/usr/bin/env bash
# tools: gdisk partprobe cryptsetup
# Generate a disk whose root partition is LUKS-formatted AND tagged with
# the amd64 DPS root partition type GUID (4f68bce3-e8cd-4db1-96e7-fbcaf984b709).
# Boot harness pairs this disk with a crypttab entry naming the LUKS volume
# "cryptroot" and a kernel cmdline that omits root= / rd.luks.uuid=, so the
# only way booster can resolve root is autodiscovery + crypttab.

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount "${dir}" 2>/dev/null
  rm -rf "${dir}"
  sudo cryptsetup close "${LUKS_DEV_NAME}" 2>/dev/null
  sudo losetup -d "${lodev}" 2>/dev/null
}

LUKS_DEV_NAME="luks-${LUKS_UUID}"
DPS_AMD64_ROOT="4f68bce3-e8cd-4db1-96e7-fbcaf984b709"

truncate --size 100M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}" | grep -m1 '^/dev/')

# Create GPT with a single partition spanning the disk, tagged as the
# DPS amd64 root type. gdisk's `n` then `t` sets the type code; we pass
# the GUID directly so this stays arch-explicit rather than relying on
# gdisk's friendly type aliases.
sudo gdisk "${lodev}" <<EOF
o
y
n


+95M
${DPS_AMD64_ROOT}
w
y
EOF

# Wait briefly for the kernel to surface the new partition node.
sudo partprobe "${lodev}"
sleep 1

sudo cryptsetup luksFormat --uuid "${LUKS_UUID}" --type luks2 "${lodev}p1" <<< "${LUKS_PASSWORD}"
sudo cryptsetup open --type luks2 "${lodev}p1" "${LUKS_DEV_NAME}" <<< "${LUKS_PASSWORD}"
sudo mkfs.ext4 -U "${FS_UUID}" -L crypttabautod "/dev/mapper/${LUKS_DEV_NAME}"

dir=$(mktemp -d)
sudo mount "/dev/mapper/${LUKS_DEV_NAME}" "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"
