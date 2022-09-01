#!/usr/bin/env bash

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount "${dir}"
  rm -r "${dir}"
  sudo losetup -d "${lodev}"
}

truncate --size 100M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}")
# create 4 partitions of size 10, 15, 11, 63 megabytes
sudo gdisk "${lodev}" <<< "o
y
n


+10M

c
раздел1
x
c
78073a8b-bdf6-48cc-918e-edb926b25f64
m
n


+15M

c
2
раздел2
x
c
2
78112a1f-3c75-483d-b120-48492e48af35
m
n


+11M
4f68bce3-e8cd-4db1-96e7-fbcaf984b709
c
3
раздел3
x
c
3
1b8e9701-59a6-49f4-8c31-b97c99cd52cf
m
n




c
4
раздел4
x
c
4
7ab42460-1deb-4e22-80f1-47dc0e2a7153
m
w
y
"

sudo mkfs.ext4 -U "${FS_UUID}" -L "${FS_LABEL}" "${lodev}p3"
dir=$(mktemp -d)
sudo mount "${lodev}p3" "${dir}"

sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"
