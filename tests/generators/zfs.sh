trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount $dir
  rm -r $dir
  sudo zpool destroy testpool
  sudo losetup -d $lodev
}

truncate --size 100M $OUTPUT
lodev=$(sudo losetup -f -P --show $OUTPUT)
sudo gdisk $lodev <<<"o
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
sudo zpool create testpool /dev/disk/by-partuuid/308eb65b-292a-49ca-9cf1-f739b338a77e
sudo zfs create -o mountpoint=/ testpool/root
sudo mount -t zfs -o zfsutil testpool/root $dir
sudo chown $USER $dir
mkdir $dir/sbin
cp assets/init $dir/sbin/init
mkdir -p assets/zfs
cp /etc/zfs/zpool.cache assets/zfs/zpool.cache
