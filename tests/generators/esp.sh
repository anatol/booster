#!/usr/bin/env bash
# tools: gdisk sgdisk mcopy

# Writes the per-test half of the ESP autodiscovery image: the kernel, the
# initramfs the test just built, its kernel options, and the GPT attribute under
# test.  Everything static comes from a base image esp_base.sh built once.
#
# Nothing here needs root.  sgdisk edits the partition table in the file and
# mtools writes into the ESP at its byte offset, so a test run never meets a
# sudo prompt.

base=assets/esp-base.img
if [ -n "${ENABLE_LUKS+1}" ]; then
  base=assets/esp-base-luks.img
fi

if [ ! -f "${base}" ]; then
  echo "esp.sh: ${base} is missing, run with -bootstrap to build it" >&2
  exit 1
fi

cp --reflink=auto "${base}" "${OUTPUT}"

if [ -n "${GPT_ATTR+1}" ]; then
  # sgdisk rather than gdisk's expert mode: it takes the bit as an argument and
  # reports failure in its exit status.  The interactive form returns 0 whatever
  # happens, so an attribute that never got written surfaced much later as a
  # boot that simply did not print what the test was waiting for, and the test
  # failed on a qemu timeout two minutes on.
  sgdisk --attributes=2:set:"${GPT_ATTR}" "${OUTPUT}" > /dev/null
  if [ "$(sgdisk --attributes=2:get:"${GPT_ATTR}" "${OUTPUT}")" != "2:${GPT_ATTR}:1" ]; then
    echo "esp.sh: GPT attribute ${GPT_ATTR} did not take on ${OUTPUT}" >&2
    exit 1
  fi
fi

esp="${OUTPUT}@@$((2048 * 512))"
mcopy -i "${esp}" -o "${KERNEL_IMAGE}" ::/vmlinuz-linux
mcopy -i "${esp}" -o "${INITRAMFS_IMAGE}" ::/booster-linux.img
printf "title Booster\nlinux /vmlinuz-linux\ninitrd /booster-linux.img\noptions %s\n" "${KERNEL_OPTIONS}" |
  mcopy -i "${esp}" -o - ::/loader/entries/booster.conf
