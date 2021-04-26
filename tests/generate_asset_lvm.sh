trap 'rm $OUTPUT' ERR
trap 'sudo umount $dir; rm -r $dir; sudo vgchange -an booster_test_vg; sudo losetup -d $lodev' EXIT

truncate --size 100M $OUTPUT
lodev=$(sudo losetup -f --show $OUTPUT)
# create 4 partitions of size 10, 15, 11, 63 megabytes
sudo fdisk $lodev <<<"g
n


+10M
n


+15M
n


+11M
n



w
" || true # adding 'true' here to workaround 'Re-reading the partition table failed.: Invalid argument' error

sudo partprobe $lodev

sudo pvcreate ${lodev}p1 ${lodev}p2 ${lodev}p4
sudo vgcreate booster_test_vg ${lodev}p2 ${lodev}p4 ${lodev}p1
sudo lvcreate -L 60M -n booster_test_lv booster_test_vg

sudo mkfs.ext4 -U $FS_UUID -L $FS_LABEL /dev/booster_test_vg/booster_test_lv
dir=$(mktemp -d)
sudo mount /dev/booster_test_vg/booster_test_lv $dir

sudo chown $USER $dir
mkdir $dir/sbin
cp assets/init $dir/sbin/init
