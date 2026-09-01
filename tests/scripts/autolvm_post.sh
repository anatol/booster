#!/usr/bin/env bash

set +o errexit

sudo umount "${MNTPOINT}"
sudo rm -r "${MNTPOINT}"
sudo vgchange -an booster_test_vg
lodev=$(sudo losetup -n -O name -j "${OUTPUT}")
if [ -z "${lodev}" ]; then
	echo "Couldn't find loop dev for ${OUTPUT}" >&2
	exit 1
fi
sudo losetup -d "${lodev}"
