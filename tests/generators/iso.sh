#!/usr/bin/env bash

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  rm -rf "${rootfs}"
}

rootfs=$(mktemp -d)

mkdir -p "${rootfs}"/boot/{loader/entries,EFI/BOOT}

printf "default booster\ntimeout 0\n" | sudo tee "${rootfs}/boot/loader/loader.conf"
printf "title Booster\nlinux /vmlinuz-linux\ninitrd /booster-linux.img\noptions %s\n" "${KERNEL_OPTIONS}" | sudo tee "${rootfs}/boot/loader/entries/booster.conf"
cp "${KERNEL_IMAGE}" "${rootfs}/boot/vmlinuz-linux"
cp "${INITRAMFS_IMAGE}" "${rootfs}/boot/booster-linux.img"
cp /usr/lib/systemd/boot/efi/systemd-bootx64.efi "${rootfs}/boot/EFI/BOOT/BOOTX64.EFI"

mkdir -p "${rootfs}/sbin"
cp assets/init "${rootfs}/sbin/init"

grub-mkrescue -o "${OUTPUT}" "${rootfs}"
