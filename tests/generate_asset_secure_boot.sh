# explanation can be found at https://wiki.archlinux.org/title/Unified_Extensible_Firmware_Interface/Secure_Boot

dir=assets/secureboot

mkdir -p $dir

guid=$(uuidgen --random)

openssl req -newkey rsa:4096 -nodes -keyout $dir/PK.key -new -x509 -sha256 -days 3650 -subj "/CN=my Platform Key/" -out $dir/PK.crt
openssl x509 -outform DER -in $dir/PK.crt -out $dir/PK.cer
cert-to-efi-sig-list -g $guid $dir/PK.crt $dir/PK.esl
sign-efi-sig-list -g $guid -k $dir/PK.key -c $dir/PK.crt PK $dir/PK.esl $dir/PK.auth