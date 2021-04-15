mkdir assets/tpm2
swtpm_setup --tpm-state assets/tpm2 --tpm2 --ecc --create-ek-cert --create-platform-cert --lock-nvram
