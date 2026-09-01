#!/usr/bin/env bash

trap 'err' ERR

err() {
  set +o errexit
  sudo umount "${MNTPOINT}"
  rm -r "${MNTPOINT}"
  sudo vgchange -an booster_test_vg
  sudo losetup -d "${lodev}"
}

lodev=$(sudo losetup -f -P --show "${OUTPUT}")
sudo vgchange -ay booster_test_vg
mkdir -p "${MNTPOINT}"
sudo mount /dev/booster_test_vg/booster_test_lv "${MNTPOINT}"
