#!/usr/bin/env bash

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount "${dir}"
  rm -r "${dir}"
  sudo losetup -d "${lodev}"
}

truncate --size 100M "${OUTPUT}"
lodev=$(sudo losetup --sector-size 4096 -f -P --show "${OUTPUT}")
sudo fdisk "${lodev}" <<< "g
n



x
u
d4699213-6e73-41d5-ad81-3daf5dfcecfb
r
w
"

sudo mkfs.ext4 "${lodev}p1"
dir=$(mktemp -d)
sudo mount "${lodev}p1" "${dir}"

sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"
