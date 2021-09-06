# generates an image with 2 partitions, one for ESP (EFI bootloader) and one for root
trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount $mount/boot
  sudo umount $mount
  rm -r $mount
  sudo losetup -d $lodev
}

truncate --size 500M $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
sudo gdisk $lodev <<<"o
y
n


+200M
ef00
n



8304
w
y
"

sudo partprobe $lodev

sudo mkfs.fat -F32 ${lodev}p1
sudo mkfs.ext4 ${lodev}p2
mount=$(mktemp -d)
sudo mount ${lodev}p2 $mount
sudo mkdir $mount/boot
sudo mount ${lodev}p1 $mount/boot
sudo mkdir -p $mount/{boot/loader/entries,boot/EFI/BOOT,sbin}

echo "default booster
timeout 0
" | sudo tee $mount/boot/loader/loader.conf
echo "title Booster
linux /vmlinuz-linux
initrd /booster-linux.img
options $KERNEL_OPTIONS
" | sudo tee $mount/boot/loader/entries/booster.conf

sudo cp assets/init $mount/sbin/init
sudo cp $KERNEL_IMAGE $mount/boot/vmlinuz-linux
sudo cp $INITRAMFS_IMAGE $mount/boot/booster-linux.img
sudo cp /usr/lib/systemd/boot/efi/systemd-bootx64.efi $mount/boot/EFI/BOOT/BOOTX64.EFI
