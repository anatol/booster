trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount $dir
  rm assets/{cryptenroll.passphrase,fido2-pin}
  rm -r $dir
  sudo cryptsetup close $LUKS_DEV_NAME
  sudo losetup -d $lodev
}

LUKS_DEV_NAME=luks-booster-systemd

truncate --size 40M $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
sudo cryptsetup luksFormat --uuid $LUKS_UUID --type luks2 $lodev <<<"$LUKS_PASSWORD"

echo -n "$LUKS_PASSWORD" >assets/cryptenroll.passphrase
echo -n "$FIDO2_PIN" >assets/fido2-pin
sudo CREDENTIALS_DIRECTORY="$(pwd)/assets" systemd-cryptenroll --fido2-device=auto --fido2-with-client-pin=yes $lodev

sudo cryptsetup open --disable-external-tokens --type luks2 $lodev $LUKS_DEV_NAME <<<"$LUKS_PASSWORD"
sudo mkfs.ext4 -U $FS_UUID -L atestlabel12 /dev/mapper/$LUKS_DEV_NAME
dir=$(mktemp -d)
sudo mount /dev/mapper/$LUKS_DEV_NAME $dir
sudo chown $USER $dir
mkdir $dir/sbin
cp assets/init $dir/sbin/init

sudo cryptsetup -v luksKillSlot $lodev 0