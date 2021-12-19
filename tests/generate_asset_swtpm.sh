# if you run this command first time at the machine please also run
#   sudo mkdir /var/lib/swtpm-localca
#   sudo chown $USER /var/lib/swtpm-localca

mkdir assets/tpm2
swtpm_setup --tpm-state assets/tpm2 --tpm2 --ecc --create-ek-cert --create-platform-cert --lock-nvram
mv assets/tpm2/tpm2-00.permall assets/tpm2/tpm2-00.permall.pristine
