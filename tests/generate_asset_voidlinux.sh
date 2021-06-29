trap 'rm $OUTPUT; rm -rf assets/voidlinux/{modules,config,dracut.img,vmlinuz}' ERR
trap 'sudo umount $mount; rm -rf $mount; sudo losetup -d $lodev' EXIT

truncate --size 5G $OUTPUT
mkfs.ext4 $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
mount=$(mktemp -d)
sudo mount $lodev $mount

mkdir -p assets/voidlinux

#install xbps package from AUR instead
#xbps_archive=xbps-static-static-0.59_5.x86_64-musl.tar.xz
#wget -nc https://alpha.de.repo.voidlinux.org/static/$xbps_archive -P assets/voidlinux
#tar -xf assets/voidlinux/$xbps_archive -C assets/voidlinux ./usr/bin/xbps-install.static

sudo xbps-install -y -R https://alpha.de.repo.voidlinux.org/current -c "$(pwd)"/assets/voidlinux/pkgcache -r $mount -Su base-system linux

kernelver=$(ls $mount/usr/lib/modules/)
sudo cp -r $mount/usr/lib/modules/$kernelver assets/voidlinux/modules
sudo mv $mount/boot/config-$kernelver assets/voidlinux/config
sudo mv $mount/boot/initramfs-$kernelver.img assets/voidlinux/dracut.img
sudo mv $mount/boot/vmlinuz-$kernelver assets/voidlinux/vmlinuz
sudo chown -R $USER assets/voidlinux
