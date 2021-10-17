trap 'quit' EXIT ERR

quit() {
  set +o errexit
  rm -rf assets/voidlinux/{modules,config,vmlinuz}
  sudo umount $mount
  rm -rf $mount
  sudo losetup -d $lodev
}

truncate --size 5G $OUTPUT
mkfs.ext4 $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
mount=$(mktemp -d)
sudo mount $lodev $mount

mkdir -p assets/voidlinux

wget https://raw.githubusercontent.com/void-linux/void-packages/master/common/repo-keys/60%3Aae%3A0c%3Ad6%3Af0%3A95%3A17%3A80%3Abc%3A93%3A46%3A7a%3A89%3Aaf%3Aa3%3A2d.plist
sudo mkdir -p $mount/var/db/xbps/keys/
sudo mv 60:ae:0c:d6:f0:95:17:80:bc:93:46:7a:89:af:a3:2d.plist $mount/var/db/xbps/keys/

sudo xbps-install -y -R https://alpha.de.repo.voidlinux.org/current -c /var/cache/xbps -r $mount -Su base-system linux

kernelver=$(ls $mount/usr/lib/modules/)
sudo cp -r $mount/usr/lib/modules/$kernelver assets/voidlinux/modules
sudo mv $mount/boot/config-$kernelver assets/voidlinux/config
sudo mv $mount/boot/vmlinuz-$kernelver assets/voidlinux/vmlinuz
sudo chown -R $USER assets/voidlinux
