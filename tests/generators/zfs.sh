#!/usr/bin/env bash
# tools: zpool zfs gdisk

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount "${dir}"
  rm -r "${dir}"
  sudo zpool destroy testpool
  sudo losetup -d "${lodev}"
}

truncate --size 100M "${OUTPUT}"
lodev=$(sudo losetup -f -P --show "${OUTPUT}" | grep -m1 '^/dev/')
sudo gdisk "${lodev}" <<< "o
y
n




c
zfspart
x
c
308eb65b-292a-49ca-9cf1-f739b338a77e
m
w
y
"

dir=$(mktemp -d)
sleep 2 # wait till udev creates /dev/disk/by-partuuid/ link
sudo modprobe zfs

# The pool has to write a cachefile: booster imports with
# `zpool import -c /etc/zfs/zpool.cache`, so an empty one leaves it with nothing
# to import.  Ask for it at creation: setting the property afterwards does not
# materialise the file.
cache=$(mktemp -u)
if [ "${ZFS_PASSPHRASE}" != "" ]; then
  echo -e "${ZFS_PASSPHRASE}\n${ZFS_PASSPHRASE}" | sudo zpool create -o cachefile="${cache}" -O encryption=on -O keylocation=prompt -O keyformat=passphrase testpool /dev/disk/by-partuuid/308eb65b-292a-49ca-9cf1-f739b338a77e
else
  sudo zpool create -o cachefile="${cache}" testpool /dev/disk/by-partuuid/308eb65b-292a-49ca-9cf1-f739b338a77e
fi
sudo zfs create -o mountpoint=/ testpool/root
sudo mount -t zfs -o zfsutil testpool/root "${dir}"
sudo chown "${USER}" "${dir}"
mkdir "${dir}/sbin"
cp assets/init "${dir}/sbin/init"
mkdir -p assets/zfs
# Copy the cache away while the pool still exists: the exit trap destroys the
# pool, and destroying it rewrites the cachefile.
# One cache per asset: each image holds its own pool, so a shared path leaves
# the other test importing a cache describing a pool it does not have.
cachedst="assets/zfs/$(basename "${OUTPUT%.img}").cache"
sudo cp "${cache}" "${cachedst}"
sudo chown "${USER}" "${cachedst}"
sudo rm -f "${cache}"
