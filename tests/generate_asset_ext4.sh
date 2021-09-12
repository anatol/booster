trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo umount $dir
  rm -r $dir
}

truncate --size 40M $OUTPUT
mkfs.ext4 -U $FS_UUID -L $FS_LABEL $OUTPUT
dir=$(mktemp -d)
sudo mount $OUTPUT $dir
sudo chown $USER $dir
mkdir $dir/sbin
cp assets/init $dir/sbin/init
