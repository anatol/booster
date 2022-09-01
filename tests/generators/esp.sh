#!/usr/bin/env bash

# generates an image with 2 partitions, one for ESP (EFI bootloader) and one for root
trap 'quit' EXIT ERR

LUKS_PASSWORD=66789
LUKS_DEV_NAME=booster_auto_root

quit() {
  set +o errexit
  sudo umount "${boot_mount}"
  sudo umount "${root_mount}"
  sudo cryptsetup close "${LUKS_DEV_NAME}"
  sudo losetup -d "${lodev}"
}

truncate --size 500M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}")
sudo gdisk "${lodev}" <<< "o
y
n


+200M
ef00
n



8304
w
y
"

if [ -n "${GPT_ATTR+1}" ]; then
  sudo gdisk "${lodev}" <<< "x
a
2
${GPT_ATTR}

w
y
"
fi

sudo mkfs.fat -F32 "${lodev}p1"
boot_mount=$(mktemp -d)
sudo mount "${lodev}p1" "${boot_mount}"
sudo mkdir -p "${boot_mount}"/{loader/entries,EFI/BOOT}

printf "default booster\ntimeout 0\n" | sudo tee "${boot_mount}/loader/loader.conf"
printf "title Booster\nlinux /vmlinuz-linux\ninitrd /booster-linux.img\noptions %s\n" "${KERNEL_OPTIONS}" | sudo tee "${boot_mount}/loader/entries/booster.conf"
sudo cp "${KERNEL_IMAGE}" "${boot_mount}/vmlinuz-linux"
sudo cp "${INITRAMFS_IMAGE}" "${boot_mount}/booster-linux.img"
sudo cp /usr/lib/systemd/boot/efi/systemd-bootx64.efi "${boot_mount}/EFI/BOOT/BOOTX64.EFI"

root_dev="${lodev}p2"
if [ -n "${ENABLE_LUKS+1}" ]; then
  sudo cryptsetup luksFormat "${root_dev}" <<< "$LUKS_PASSWORD"
  sudo cryptsetup open "${root_dev}" "${LUKS_DEV_NAME}" <<< "$LUKS_PASSWORD"
  root_dev="/dev/mapper/$LUKS_DEV_NAME"
fi

sudo mkfs.ext4 "${root_dev}"
root_mount=$(mktemp -d)
sudo mount "${root_dev}" "${root_mount}"
sudo mkdir -p "${root_mount}/sbin"
sudo cp assets/init "${root_mount}/sbin/init"
