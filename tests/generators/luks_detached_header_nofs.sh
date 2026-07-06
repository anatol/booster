#!/usr/bin/env bash
# Creates a LUKS2 image with a DETACHED header and NO filesystem — a decoy
# volume for the multi-device detached-header test. It operates on plain files
# (no losetup, no dm-crypt open), so unlike luks_detached_header.sh it needs no
# root: booster only needs to open it, never mount it.
#
# A keyfile is also enrolled so the decoy can unlock non-interactively via
# rd.luks.key= at boot. That keeps the multi-device test's passphrase prompt to
# a single, deterministic prompt for the root volume (no concurrent-prompt race).
#
# Required env vars:
#   OUTPUT         path for the encrypted data image (payload container)
#   HEADER_OUTPUT  path where the detached header file is written
#   KEYFILE_OUTPUT path where the keyfile is written
#   LUKS_UUID      UUID for the LUKS container

set -o errexit

truncate --size 40M "${OUTPUT}"
truncate --size 2M  "${HEADER_OUTPUT}"

# luksFormat writes the metadata to HEADER_OUTPUT; OUTPUT holds only ciphertext.
# Fast pbkdf keeps generation quick and avoids needing locked memory as non-root.
cryptsetup luksFormat \
  --type luks2 \
  --uuid "${LUKS_UUID}" \
  --header "${HEADER_OUTPUT}" \
  --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
  "${OUTPUT}" <<< "1234"

# Enroll a random keyfile into a second keyslot (still root-free: --header only
# touches the header file).
head -c 64 /dev/urandom > "${KEYFILE_OUTPUT}"
cryptsetup luksAddKey \
  --header "${HEADER_OUTPUT}" \
  --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
  "${OUTPUT}" "${KEYFILE_OUTPUT}" <<< "1234"
