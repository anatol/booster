#!/usr/bin/env bash
# Creates a small ext4 "header device" image containing a LUKS detached header
# file at /root.hdr.  Used by TestLUKS2DetachedHeaderCmdlineOnDevice to exercise
# the rd.luks.header=UUID=/root.hdr:UUID=<devuuid> cmdline syntax.
#
# Required env vars:
#   OUTPUT        path for the header device image
#   HDRDEV_UUID   UUID for the ext4 header-device filesystem
#   HEADER_INPUT  path to the detached LUKS header file to embed

set -o errexit

lodev=
hdrdir=

trap 'quit' EXIT ERR

quit() {
  set +o errexit
  [ -n "${hdrdir}" ] && { sudo umount "${hdrdir}"; rm -rf "${hdrdir}"; }
  [ -n "${lodev}" ]  && sudo losetup -d "${lodev}"
}

truncate --size 10M "${OUTPUT}"
mkfs.ext4 -U "${HDRDEV_UUID}" "${OUTPUT}"
lodev=$(sudo losetup -f --show "${OUTPUT}")
hdrdir=$(mktemp -d)
sudo mount "${lodev}" "${hdrdir}"
sudo chown "${USER}" "${hdrdir}"
cp "${HEADER_INPUT}" "${hdrdir}/root.hdr"
sudo umount "${hdrdir}"; hdrdir=
sudo losetup -d "${lodev}"; lodev=
