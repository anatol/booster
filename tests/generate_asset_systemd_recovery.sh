trap 'quit' EXIT
trap 'quit' ERR

quit() {
  set +o errexit
  sudo umount $dir
  rm assets/cryptenroll.passphrase
  rm -r $dir
  sudo cryptsetup close $LUKS_DEV_NAME
  sudo losetup -d $lodev
}

err() {
  set +o errexit
  rm assets/systemd.recovery.key
}

LUKS_DEV_NAME=luks-booster-recover

truncate --size 40M $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
sudo cryptsetup luksFormat --uuid $LUKS_UUID --type luks2 $lodev <<<"$LUKS_PASSWORD"

echo -n "$LUKS_PASSWORD" >assets/cryptenroll.passphrase
recovery_key=$(sudo CREDENTIALS_DIRECTORY="$(pwd)/assets" systemd-cryptenroll --recovery-key $lodev)
echo -n "$recovery_key" > assets/systemd.recovery.key

sudo cryptsetup open $lodev $LUKS_DEV_NAME <<<"$LUKS_PASSWORD"
sudo mkfs.ext4 -v -U $FS_UUID -L atestlabel12 /dev/mapper/$LUKS_DEV_NAME
dir=$(mktemp -d)
sudo mount /dev/mapper/$LUKS_DEV_NAME $dir
sudo chown $USER $dir
mkdir $dir/sbin
cp assets/init $dir/sbin/init

sudo cryptsetup -v luksKillSlot $lodev 0
