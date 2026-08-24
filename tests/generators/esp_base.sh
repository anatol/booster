#!/usr/bin/env bash
# tools: sgdisk mmd mcopy mkfs.fat cryptsetup

# Builds the half of the ESP autodiscovery image that no test varies: the GPT, an
# empty FAT ESP carrying the bootloader, and a root filesystem holding /sbin/init.
# esp.sh writes the rest at test time without privileges.
#
# Only the LUKS variant needs root, and only because populating an encrypted
# volume means opening it through device-mapper.  The plain variant is built
# entirely in userspace.

trap 'quit' EXIT

LUKS_PASSWORD=66789
LUKS_DEV_NAME=booster_auto_root_$$

quit() {
  set +o errexit
  [ -n "${root_mount:-}" ] && sudo umount "${root_mount}" 2>/dev/null
  [ -n "${opened:-}" ] && sudo cryptsetup close "${LUKS_DEV_NAME}" 2>/dev/null
  [ -n "${lodev:-}" ] && sudo losetup -d "${lodev}" 2>/dev/null
  rm -f "${esp_img:-}" "${root_img:-}"
}

# Partition table.  sgdisk edits the file directly, so no loop device is needed
# to lay one out.  Sector numbers are fixed here because esp.sh has to know the
# ESP's byte offset to write into it later.
esp_start=2048
esp_sectors=$((200 * 1024 * 1024 / 512))
root_start=$((esp_start + esp_sectors))

truncate --size 500M "${OUTPUT}"
sgdisk -o \
  -n "1:${esp_start}:+200M" -t 1:ef00 \
  -n "2:${root_start}:0" -t 2:8304 \
  "${OUTPUT}" > /dev/null

# ESP: mkfs.fat and mtools both work on a plain file.
esp_img=$(mktemp)
truncate --size 200M "${esp_img}"
mkfs.fat -F32 "${esp_img}" > /dev/null
mmd -i "${esp_img}" ::/EFI ::/EFI/BOOT ::/loader ::/loader/entries
mcopy -i "${esp_img}" /usr/lib/systemd/boot/efi/systemd-bootx64.efi ::/EFI/BOOT/BOOTX64.EFI
printf "default booster\ntimeout 0\n" | mcopy -i "${esp_img}" - ::/loader/loader.conf
dd if="${esp_img}" of="${OUTPUT}" bs=512 seek="${esp_start}" conv=notrunc status=none

root_sectors=$(($(sgdisk -i 2 "${OUTPUT}" | grep -oP 'Partition size: \K[0-9]+') ))
root_img=$(mktemp)
truncate --size $((root_sectors * 512)) "${root_img}"

if [ -n "${ENABLE_LUKS+1}" ]; then
  # luksFormat only writes a header, so it needs no privileges.  Opening the
  # result to put a filesystem in it does.
  cryptsetup luksFormat --batch-mode "${root_img}" <<< "${LUKS_PASSWORD}"
  lodev=$(sudo losetup -f --show "${root_img}" | grep -m1 '^/dev/')
  sudo cryptsetup open "${lodev}" "${LUKS_DEV_NAME}" <<< "${LUKS_PASSWORD}"
  opened=1
  sudo mkfs.ext4 -q "/dev/mapper/${LUKS_DEV_NAME}"
  root_mount=$(mktemp -d)
  sudo mount "/dev/mapper/${LUKS_DEV_NAME}" "${root_mount}"
  sudo mkdir -p "${root_mount}/sbin"
  sudo cp assets/init "${root_mount}/sbin/init"
  sudo umount "${root_mount}"
  root_mount=""
  sudo cryptsetup close "${LUKS_DEV_NAME}"
  opened=""
  sudo losetup -d "${lodev}"
  lodev=""
else
  # mkfs.ext4 -d populates from a staging directory without mounting anything.
  stage=$(mktemp -d)
  mkdir -p "${stage}/sbin"
  cp assets/init "${stage}/sbin/init"
  mkfs.ext4 -q -d "${stage}" "${root_img}"
  rm -rf "${stage}"
fi

dd if="${root_img}" of="${OUTPUT}" bs=512 seek="${root_start}" conv=notrunc status=none
