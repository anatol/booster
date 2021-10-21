trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount $mount
  rm -rf $mount
  sudo losetup -d $lodev
}

truncate --size 200M $OUTPUT
mkfs.ext4 $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
mount=$(mktemp -d)
sudo mount $lodev $mount

sudo mkdir -p $mount/etc/apk/
echo "http://dl-cdn.alpinelinux.org/alpine/edge/main" | sudo tee -a $mount/etc/apk/repositories
echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" | sudo tee -a $mount/etc/apk/repositories
sudo apk --root $mount --initdb --update-cache --allow-untrusted add alpine-base util-linux-misc

sudo chroot $mount /bin/sh -eu <<EOT
cd /etc/init.d
/bin/ln -s agetty agetty.ttyS0
/sbin/rc-update add agetty.ttyS0 default
EOT
