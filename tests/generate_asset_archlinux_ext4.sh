trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount $mount
  rm -rf $mount
  sudo losetup -d $lodev
}

truncate --size 1G $OUTPUT
mkfs.ext4 $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
mount=$(mktemp -d)
sudo mount $lodev $mount

sudo pacstrap -c -M $mount base openssh
genfstab -U $mount | sudo tee $mount/etc/fstab

echo "[Match]
Name=*

[Network]
DHCP=yes" | sudo tee $mount/etc/systemd/network/20-wired.network

sudo sed -i '/^root/ { s/:x:/::/ }' $mount/etc/passwd
sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' $mount/etc/ssh/sshd_config
sudo sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/' $mount/etc/ssh/sshd_config

sudo arch-chroot $mount systemctl enable sshd systemd-networkd
