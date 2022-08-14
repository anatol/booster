trap 'quit' EXIT ERR

quit() {
  set +o errexit
  if [ "$CLEVIS_PIN" == "tpm2" ]; then
    swtpm_ioctl --tcp :2322 -s
    rm -rf assets/tpm2.generate
  fi
  sudo umount $dir
  rm -r $dir
  sudo cryptsetup close $LUKS_DEV_NAME
  sudo losetup -d $lodev
}

LUKS_TYPE=luks${LUKS_VERSION}
LUKS_DEV_NAME=luks-$LUKS_UUID

if [ "$CLEVIS_PIN" == "tpm2" ]; then
  mkdir assets/tpm2.generate
  cp assets/tpm2/tpm2-00.permall.pristine assets/tpm2.generate/tpm2-00.permall

  swtpm socket --tpmstate dir=assets/tpm2.generate --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
fi

if [ "$CLEVIS_PIN" == "remote" ]; then
  mkdir -p assets/remote
  tangctl create > assets/remote/key.priv
  tangctl public assets/remote/key.priv > assets/remote/key.pub

fi

truncate --size 40M $OUTPUT
lodev=$(sudo losetup -f -P --show $OUTPUT)
sudo cryptsetup luksFormat --uuid $LUKS_UUID --type $LUKS_TYPE $lodev <<<"$LUKS_PASSWORD"

if [ "$CLEVIS_PIN" != "" ]; then
  # custom TPM2TOOLS_TCTI does not work due to https://github.com/latchset/clevis/issues/244
  sudo TPM2TOOLS_TCTI=swtpm clevis luks bind -y -k - -d $lodev $CLEVIS_PIN "$CLEVIS_CONFIG" <<<"$LUKS_PASSWORD"
fi
# sudo cryptsetup open --disable-external-tokens --type $LUKS_TYPE $lodev $LUKS_DEV_NAME <<<"$LUKS_PASSWORD"
sudo cryptsetup open --type $LUKS_TYPE $lodev $LUKS_DEV_NAME <<<"$LUKS_PASSWORD"
sudo mkfs.ext4 -U $FS_UUID -L atestlabel12 /dev/mapper/$LUKS_DEV_NAME
dir=$(mktemp -d)
sudo mount /dev/mapper/$LUKS_DEV_NAME $dir
sudo chown $USER $dir
mkdir $dir/sbin
cp assets/init $dir/sbin/init
