# Initialize your Yubikey
# Insert your Yubikey with PIV support
# sudo systemctl start pcscd.service
# ykman piv reset
#   this will make default PIN: 123456     PUK: 12345678
# ykman piv certificates generate --subject "YUBIKEY PIV CERT SUBJECT" 9d pubkey.pem
# rm pubkey.pem

# edit /etc/pkcs11/modules/ykcs11.module and add "module: /usr/lib/libykcs11.so"

# p11tool --list-all
#   set the Yubikey token to TOKEN_URI
# p11tool --list-all $TOKEN_URI
#   choose 'X.509 Certificate' with label 'X.509 Certificate for Key Management' and set it to $CERT_URI
#   then
# sudo systemd-cryptenroll --pkcs11-token-uri=$CERT_URI $BLOCK_DEVICE

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount $dir
  rm assets/cryptenroll.passphrase
  rm -r $dir
  sudo cryptsetup close $LUKS_DEV_NAME
  sudo losetup -d $lodev
}

LUKS_DEV_NAME=luks-booster-systemd

TOKEN_URI=$(p11tool --list-all | grep YubiKey)
CERT_URI=$(p11tool --list-all $TOKEN_URI --only-urls | grep 'type=cert' | grep object=X.509%20Certificate%20for%20Key%20Management)
PKCS11_PIN=123456

truncate --size 40M $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
sudo cryptsetup luksFormat --uuid $LUKS_UUID --type luks2 $lodev <<<"$LUKS_PASSWORD"

echo -n "$LUKS_PASSWORD" >assets/cryptenroll.passphrase
echo -n "$PKCS11_PIN" >assets/pkcs11-pin
sudo CREDENTIALS_DIRECTORY="$(pwd)/assets" systemd-cryptenroll --pkcs11-token-uri=$CERT_URI $lodev

sudo cryptsetup open --disable-external-tokens --type luks2 $lodev $LUKS_DEV_NAME <<<"$LUKS_PASSWORD"
sudo mkfs.ext4 -U $FS_UUID -L atestlabel12 /dev/mapper/$LUKS_DEV_NAME
dir=$(mktemp -d)
sudo mount /dev/mapper/$LUKS_DEV_NAME $dir
sudo chown $USER $dir
mkdir $dir/sbin
cp assets/init $dir/sbin/init

sudo cryptsetup -v luksKillSlot $lodev 0
