trap 'quit' EXIT ERR

quit() {
  set +o errexit
  sudo losetup -d $lodev
}

truncate --size 10G $OUTPUT
lodev=$(sudo losetup -f -P --show $OUTPUT)
sudo fdisk $lodev <<<"g
n



x
u
c0824b8c-c4a4-4e99-bb3e-b9418db5c180
r
w
"

sudo mkswap --uuid 5ec330f5-ac5e-48d2-98b6-87fd3e9b272f ${lodev}p1