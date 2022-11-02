#!/usr/bin/env bash

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount "${dir}"
  rm -r "${dir}"
}

truncate --size 650M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}")
# create 2 partitions equal size
sudo fdisk "${lodev}" <<< "g
n


+300M
t

29
n


+300M
t

29
w
"

sudo mkfs.btrfs --uuid=$FS_UUID -d raid0 "${lodev}p1" "${lodev}p2"
dir=$(mktemp -d)
sudo mount "${lodev}p1" "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"
