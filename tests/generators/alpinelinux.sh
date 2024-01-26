#!/usr/bin/env bash

trap 'quit' EXIT
trap 'err' ERR

quit() {
  set +o errexit
  sudo umount "${mount}"
  rm -rf "${mount}"
  sudo losetup -d "${lodev}"
}

err() {
  set +o errexit
  quit
  rm -rf assets/alpinelinux
}

truncate --size 200M "${OUTPUT}"
mkfs.ext4 "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}")
mount=$(mktemp -d)
sudo mount "${lodev}" "${mount}"

sudo mkdir -p "${mount}/etc/apk/"
echo "http://dl-cdn.alpinelinux.org/alpine/edge/main" | sudo tee -a "${mount}/etc/apk/repositories"
echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" | sudo tee -a "${mount}/etc/apk/repositories"
sudo apk --root "${mount}" --initdb --update-cache --allow-untrusted add alpine-base linux-virt agetty

sudo chroot "${mount}" /bin/sh -eu << EOT
cd /etc/init.d
/bin/ln -s agetty agetty.ttyS0
/sbin/rc-update add agetty.ttyS0 default
EOT

mkdir -p assets/alpinelinux
modulesdir="${mount}/lib/modules"
# Makes the fairly reasonable assumption that the "|" character will never appear in a kernel version
kernelver=$(find "${modulesdir}" -maxdepth 1 -type d ! -name "modules" -print0 | xargs -0 stat -c "%Y|%n" | sort -r | cut -d "|" -f 2 | xargs basename)
printf '%s' "${kernelver}" > assets/alpinelinux/vmlinuz-version
sudo cp -r "${modulesdir}/${kernelver}" assets/alpinelinux/modules
sudo mv "${mount}/boot/config-${kernelver}" assets/alpinelinux/config
sudo mv "${mount}/boot/vmlinuz-virt" assets/alpinelinux/vmlinuz
sudo chown -R "$USER" assets/alpinelinux
