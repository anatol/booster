trap 'quit' EXIT ERR

quit() {
  set +o errexit
  swtpm_ioctl --tcp :2322 -s
  rm assets/cryptenroll.passphrase
  sudo umount $dir
  rm -r $dir
  sudo cryptsetup close $LUKS_DEV_NAME
  sudo losetup -d $lodev
}

LUKS_DEV_NAME=luks-booster-systemd

swtpm socket --tpmstate dir=assets/tpm2 --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &

truncate --size 40M $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
sudo cryptsetup luksFormat --uuid $LUKS_UUID --type luks2 $lodev <<<"$LUKS_PASSWORD"

echo -n "$LUKS_PASSWORD" >assets/cryptenroll.passphrase
# it looks like edk2 extends PCR 0-7 so let's use some other PCR outside of this range
sudo CREDENTIALS_DIRECTORY="$(pwd)/assets" systemd-cryptenroll --tpm2-device=swtpm: --tpm2-pcrs=10+13 $lodev

sudo cryptsetup open --disable-external-tokens --type luks2 $lodev $LUKS_DEV_NAME <<<"$LUKS_PASSWORD"
sudo mkfs.ext4 -U $FS_UUID -L atestlabel12 /dev/mapper/$LUKS_DEV_NAME
dir=$(mktemp -d)
sudo mount /dev/mapper/$LUKS_DEV_NAME $dir
sudo chown $USER $dir
mkdir $dir/sbin
cp assets/init $dir/sbin/init
