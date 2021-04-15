trap 'rm $OUTPUT' ERR
trap 'sudo umount $mount/{home,srv,var,.}; rm -r $mount; sudo cryptsetup close $cryptname' EXIT

truncate --size 1G $OUTPUT
cryptname=booster.tests.btrfs
cryptdev=/dev/mapper/$cryptname
sudo cryptsetup luksFormat -q --uuid=724151bb-84be-493c-8e32-53e123c8351b --perf-no_read_workqueue --perf-no_write_workqueue --type luks2 --cipher aes-xts-plain64 --key-size 512 --iter-time 2000 --pbkdf argon2id --hash sha3-512 $OUTPUT <<<"$LUKS_PASSWORD"
sudo cryptsetup --allow-discards --perf-no_read_workqueue --perf-no_write_workqueue --persistent open $OUTPUT $cryptname <<<"$LUKS_PASSWORD"
sudo mkfs.btrfs -L Arch --uuid=15700169-8c12-409d-8781-37afa98442a8 $cryptdev
mount=$(mktemp -d)
sudo mount $cryptdev $mount
sudo btrfs sub create $mount/@
sudo btrfs sub create $mount/@home
sudo btrfs sub create $mount/@srv
sudo btrfs sub create $mount/@var
sudo umount $mount
sudo mount -o noatime,compress-force=zstd,commit=120,space_cache=v2,ssd,discard=async,autodefrag,subvol=@ $cryptdev $mount
sudo mkdir -p $mount/{home,srv,var}
sudo mount -o noatime,compress-force=zstd,commit=120,space_cache=v2,ssd,discard=async,autodefrag,subvol=@home $cryptdev $mount/home
sudo mount -o noatime,compress-force=zstd,commit=120,space_cache=v2,ssd,discard=async,autodefrag,subvol=@srv $cryptdev $mount/srv
sudo mount -o noatime,compress-force=zstd,commit=120,space_cache=v2,ssd,discard=async,autodefrag,subvol=@var $cryptdev $mount/var
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
