#!/usr/bin/env bash

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount "${mount}"
  rm -rf "${mount}"
  sudo losetup -d "${lodev}"
}

truncate --size 5G "${OUTPUT}"
mkfs.ext4 "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}")
mount=$(mktemp -d)
sudo mount "${lodev}" "${mount}"

mkdir -p assets/voidlinux

wget https://raw.githubusercontent.com/void-linux/void-packages/master/common/repo-keys/60%3Aae%3A0c%3Ad6%3Af0%3A95%3A17%3A80%3Abc%3A93%3A46%3A7a%3A89%3Aaf%3Aa3%3A2d.plist
sudo mkdir -p "${mount}/var/db/xbps/keys/"
sudo mv 60:ae:0c:d6:f0:95:17:80:bc:93:46:7a:89:af:a3:2d.plist "${mount}/var/db/xbps/keys/"

sudo xbps-install -y -R https://alpha.de.repo.voidlinux.org/current -c /var/cache/xbps -r "${mount}" -Su base-system linux

modulesdir="${mount}/usr/lib/modules"
# Makes the fairly reasonable assumption that the "|" character will never appear in a kernel version
kernelver=$(find "${modulesdir}" -maxdepth 1 -type d ! -name "modules" -print 0 | xargs -0 stat -c "%Y|%n" | sort -r | cut -d "|" -f 2 | xargs basename)
printf '%s' "${kernelver}" > assets/voidlinux/vmlinuz-version
sudo cp -r "${modulesdir}/${kernelver} assets/voidlinux/modules"
sudo mv "${mount}/boot/config-${kernelver}" assets/voidlinux/config
sudo mv "${mount}/boot/vmlinuz-${kernelver}" assets/voidlinux/vmlinuz
sudo chown -R "${USER}" assets/voidlinux
