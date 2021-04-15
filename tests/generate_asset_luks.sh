trap 'kill_swtpm; sudo umount $dir; rm -r $dir; sudo cryptsetup close $LUKS_DEV_NAME; sudo losetup -d $lodev' EXIT
trap 'rm $OUTPUT' ERR

kill_swtpm() {
  if [ ! -z "$SWTPM_PID" ]
  then
      kill $SWTPM_PID
  fi
}

LUKS_TYPE=luks${LUKS_VERSION}
LUKS_DEV_NAME=luks-$LUKS_UUID

if [ "$CLEVIS_PIN" == "tpm2" ]; then
  swtpm socket --tpmstate dir=assets/tpm2 --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
  SWTPM_PID=$!
fi

truncate --size 40M $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
sudo cryptsetup luksFormat --uuid $LUKS_UUID --type $LUKS_TYPE $lodev <<<"$LUKS_PASSWORD"

if [ "$CLEVIS_PIN" != "" ]; then
  # custom TPM2TOOLS_TCTI does not work due to https://github.com/latchset/clevis/issues/244
  sudo TPM2TOOLS_TCTI=swtpm clevis luks bind -y -k - -d $lodev $CLEVIS_PIN "$CLEVIS_CONFIG" <<<"$LUKS_PASSWORD"
fi

sudo cryptsetup open --type $LUKS_TYPE $lodev $LUKS_DEV_NAME <<<"$LUKS_PASSWORD"
sudo mkfs.ext4 -U $FS_UUID -L atestlabel12 /dev/mapper/$LUKS_DEV_NAME
dir=$(mktemp -d)
sudo mount /dev/mapper/$LUKS_DEV_NAME $dir
sudo chown $USER $dir
mkdir $dir/sbin
cp assets/init $dir/sbin/init
