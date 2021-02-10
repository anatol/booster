package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anatol/clevis.go"
	"github.com/anatol/luks.go"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/client4"
	"github.com/s-urbaniak/uevent"
	"github.com/vishvananda/netlink"
	"github.com/yookoala/realpath"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	newRoot    = "/booster.root"
	newInitBin = "/sbin/init"
)

var (
	cmdline      = make(map[string]string)
	debugEnabled bool
	modulesDir   string
	rootMounted  sync.WaitGroup // waits until the root partition is mounted
)

type alias struct{ pattern, module string } // module alias info

func getKernelVersion() (string, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}
	release := uts.Release
	length := bytes.IndexByte(release[:], 0)
	return string(uts.Release[:length]), nil
}

func parseCmdline() error {
	b, err := ioutil.ReadFile("/proc/cmdline")
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimSpace(string(b)), " ")
	for _, part := range parts {
		// separate key/value based on the first = character;
		// there may be multiple (e.g. in rd.luks.name)
		if idx := strings.IndexByte(part, '='); idx > -1 {
			cmdline[part[:idx]] = part[idx+1:]
		} else {
			cmdline[part] = ""
		}
	}

	if _, ok := cmdline["booster.debug"]; ok {
		debugEnabled = true
	}

	return nil
}

var (
	addedDevices      = map[string]bool{}
	addedDevicesMutex sync.Mutex
)

// devAdd is called upon receiving a uevent from the kernel with action “add”
// from subsystem “block”.
//
// Booster handles following kernel command line parameters:
//    - rd.luks=1 to enable looking for LUKS-encrypted block devices
//    - rd.luks.name=<uuid>=<name>
//    - rd.luks.options=opt1,opt2
//    - root=/dev/mapper/<name>
//    - root=/dev/<name>
//    - root=UUID=<uuid>
//    - rootfstype=<fs>, e.g. rootfstype=ext4
//    - rootflags=<mount options>
//    - rd.vconsole.font=<font>
func devAdd(syspath, devname string) error {
	// Some devices might receive multiple udev add events
	// Avoid processing these node twice by tracking what has been added already
	addedDevicesMutex.Lock()
	if _, ok := addedDevices[devname]; ok {
		addedDevicesMutex.Unlock()
		return nil
	}
	addedDevices[devname] = true
	addedDevicesMutex.Unlock()

	debug("found a new device with path=%v and name=%v", syspath, devname)

	cmdroot := cmdline["root"]

	devpath := path.Join("/dev", devname)
	if devpath == cmdroot {
		return mountRootFs(devpath)
	}

	if strings.HasPrefix(devname, "dm-") {
		// TODO: check if we can use API similar to what
		// 'sudo dmsetup info -c --noheadings -o name dm-0' does
		dmNameFile := filepath.Join("/sys", syspath, "dm", "name")
		content, err := ioutil.ReadFile(dmNameFile)
		if err != nil {
			return err
		}
		mapperName := string(bytes.TrimSpace(content))
		dmPath := "/dev/mapper/" + mapperName

		// setup symlink /dev/mapper/NAME -> /dev/dm-NN
		if err := os.Symlink(devpath, dmPath); err != nil {
			return err
		}
		devpath = dmPath // later we use /dev/mapper/NAME as a mount point

		if err := writeUdevDb(mapperName); err != nil {
			return err
		}

		if dmPath == cmdroot {
			return mountRootFs(dmPath)
		}
	}

	info, err := readBlkInfo(devpath)
	if err != nil {
		return err
	}

	if strings.HasPrefix(cmdroot, "UUID=") && info.uuid == strings.TrimPrefix(cmdroot, "UUID=") {
		return mountRootFs(devpath)
	}
	if strings.HasPrefix(cmdroot, "LABEL=") && info.label == strings.TrimPrefix(cmdroot, "LABEL=") {
		return mountRootFs(devpath)
	}

	if cmdline["rd.luks.name"] != "" {
		parts := strings.Split(cmdline["rd.luks.name"], "=")
		if len(parts) != 2 {
			return fmt.Errorf("Invalid rd.luks.name kernel parameter. Got: %v   Expected: rd.luks.name=<UUID>=<Name>", cmdline["rd.luks.name"])
		}
		if parts[0] == info.uuid {
			return luksOpen(devpath, parts[1])
		}
	}
	if cmdline["rd.luks.uuid"] == info.uuid {
		return luksOpen(devpath, "luks-"+info.uuid)
	}

	return nil
}

// rd luks options match systemd naming https://www.freedesktop.org/software/systemd/man/crypttab.html
var rdLuksOptions = map[string]string{
	"discard":                luks.FlagAllowDiscards,
	"same-cpu-crypt":         luks.FlagSameCPUCrypt,
	"submit-from-crypt-cpus": luks.FlagSubmitFromCryptCPUs,
	"no-read-workqueue":      luks.FlagNoReadWorkqueue,
	"no-write-workqueue":     luks.FlagNoWriteWorkqueue,
}

func luksApplyFlags(d luks.Device) error {
	param, ok := cmdline["rd.luks.options"]
	if !ok {
		return nil
	}

	for _, o := range strings.Split(param, ",") {
		flag, ok := rdLuksOptions[o]
		if !ok {
			return fmt.Errorf("Unknown value in rd.luks.options: %v", o)
		}
		if err := d.FlagsAdd(flag); err != nil {
			return err
		}
	}
	return nil
}

func luksOpen(dev string, name string) error {
	wg := loadModules("dm_crypt")
	wg.Wait()

	d, err := luks.Open(dev)
	if err != nil {
		return err
	}
	defer d.Close()

	if len(d.Slots()) == 0 {
		return fmt.Errorf("device %s has no slots to unlock", dev)
	}

	if err := luksApplyFlags(d); err != nil {
		return err
	}

	// first try to unlock with token
	tokens, err := d.Tokens()
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.Type != luks.ClevisTokenType {
			continue
		}

		var payload []byte
		// Note that token metadata stored differently in LUKS v1 and v2
		if d.Version() == 1 {
			payload = t.Payload
		} else {
			var node struct {
				Jwe json.RawMessage
			}
			if err := json.Unmarshal(t.Payload, &node); err != nil {
				fmt.Println(err)
				continue
			}
			payload = node.Jwe
		}

		// in case of a (network) error retry it several times. or maybe retry logic needs to be inside the clevis itself?
		var password []byte
		for i := 0; i < 40; i++ {
			password, err = clevis.Decrypt(payload)
			if err == nil {
				break
			} else {
				fmt.Println(err)
				time.Sleep(time.Second)
			}
		}

		for _, s := range t.Slots {
			err = d.Unlock(s, password, name)
			if err == luks.ErrPassphraseDoesNotMatch {
				continue
			}
			MemZeroBytes(password)
			return err
		}
		MemZeroBytes(password)
	}

	// tokens did not work, let's unlock with a password
	for {
		fmt.Print("Enter passphrase for ", name, ":")
		password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		if len(password) == 0 {
			fmt.Println("")
			continue
		}

		for _, s := range d.Slots() {
			err = d.Unlock(s, password, name)
			if err == luks.ErrPassphraseDoesNotMatch {
				continue
			}
			MemZeroBytes(password)
			return err
		}

		// zeroify the password so we do not keep the sensitive data in the memory
		MemZeroBytes(password)

		// retry password
		fmt.Println("   incorrect passphrase, please try again")
	}
}

// deviceNo returns major/minor device number for the given device file
func deviceNo(filename string) (uint32, uint32, error) {
	stat, err := os.Stat(filename)
	if err != nil {
		return 0, 0, err
	}
	sys, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("Cannot determine the device major and minor numbers for %s", filename)
	}
	return unix.Major(sys.Rdev), unix.Minor(sys.Rdev), nil

}

// writeUdevDb writes Udev state to the database.
// It is an equivalent to what "db_persist" udev option does (see 'man 7 udev').
func writeUdevDb(dmName string) error {
	major, minor, err := deviceNo("/dev/mapper/" + dmName)
	if err != nil {
		return err
	}

	if err := os.MkdirAll("/run/udev/data/", 0755); err != nil {
		return err
	}

	dbFile := fmt.Sprintf("/run/udev/data/b%d:%d", major, minor)
	debug("writing udev state to %s", dbFile)
	return ioutil.WriteFile(dbFile, []byte("E:DM_UDEV_PRIMARY_SOURCE_FLAG=1\n"), 0644)
}

func mountRootFs(dev string) error {
	info, err := readBlkInfo(dev)
	if err != nil {
		return fmt.Errorf("%s: %v", dev, err)
	}

	fstype := cmdline["rootfstype"]
	if fstype == "" {
		fstype = info.format
	}
	debug("mounting %s (fstype=%s) to %s", dev, fstype, newRoot)

	wg := loadModules(fstype)
	wg.Wait()

	rootMountFlags := uintptr(syscall.MS_NOATIME)
	if _, rw := cmdline["rw"]; !rw {
		rootMountFlags |= syscall.MS_RDONLY
	}
	options := cmdline["rootflags"]
	if err := mount(dev, newRoot, fstype, rootMountFlags, options); err != nil {
		return err
	}

	rootMounted.Done()
	return nil
}

func isSystemd(path string) (bool, error) {
	myRealpath, err := realpath.Realpath(path)
	if err != nil {
		return false, err
	}
	return strings.HasSuffix(myRealpath, "/systemd"), nil
}

// moveSlashRunMountpoint moves some of the initramfs mounts into the main image
func moveSlashRunMountpoint() error {
	// remount root as it might contain udev state that we need to pass to the new root
	_, err := os.Stat(newRoot + "/run")
	if os.IsNotExist(err) {
		// let's print a warning and hope that the new root works without initrd udev state
		fmt.Println("/run does not exists at the root filesystem")
		return nil
	}

	if err := syscall.Mount("/run", newRoot+"/run", "", syscall.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move /run to new root: %v", err)
	}

	return nil
}

// https://github.com/mirror/busybox/blob/9aa751b08ab03d6396f86c3df77937a19687981b/util-linux/switch_root.c#L297
func switchRoot() error {
	if err := moveSlashRunMountpoint(); err != nil {
		return err
	}

	// TODO: remove everything at "/" but do not cross filesystem mountpoint boundaries

	if err := os.Chdir(newRoot); err != nil {
		return fmt.Errorf("chdir: %v", err)
	}
	if err := syscall.Mount(".", "/", "", syscall.MS_MOVE, ""); err != nil {
		return fmt.Errorf("mount dir to root: %v", err)
	}
	if err := syscall.Chroot("."); err != nil {
		return fmt.Errorf("chroot: %v", err)
	}
	if err := os.Chdir("."); err != nil {
		return fmt.Errorf("chdir: %v", err)
	}

	initArgs := []string{newInitBin}
	isSystemdInit, err := isSystemd(newInitBin)
	if err != nil {
		return err
	}
	if isSystemdInit {
		// pass serialized state to userspace, this way we can export for example initrd execution time
		fd, err := unix.MemfdCreate("systemd-state", 0)
		if err != nil {
			return fmt.Errorf("memfd create: %v", err)
		}
		state := fmt.Sprintf("initrd-timestamp=%d %d\n", startRealtime, startMonotonic)
		if _, err := unix.Write(fd, []byte(state)); err != nil {
			return err
		}
		if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
			return err
		}

		initArgs = append(initArgs, "--switched-root", "--system", "--deserialize", strconv.Itoa(fd))
	}

	// Run the OS init
	debug("Switching to the new userspace now. Да пабачэння!")
	if err := syscall.Exec(newInitBin, initArgs, nil); err != nil {
		return fmt.Errorf("Can't run the rootfs init (%v): %v", newInitBin, err)
	}
	return nil // unreachable
}

// Cleanup the state before handing off the machine to the new init
func cleanup() {
	// We need to close our uevent connection, otherwise it will stay open forever and mess with the new init. .
	// See https://github.com/s-urbaniak/uevent/pull/1 and https://github.com/anatol/booster/issues/22
	// _ = udevReader.Close()

	shutdownNetwork()
}

// isValidDmEvent checks whether this udev event has correct flags.
// This is similar to checks done by /usr/lib/udev/rules.d/10-dm.rules udev rules.
func isValidDmEvent(dmCookie string) bool {
	if dmCookie == "" {
		return false
	}

	cookie, err := strconv.ParseUint(dmCookie, 0, 32)
	if err != nil {
		return false // invalid cookie
	}

	const (
		DM_UDEV_FLAGS_SHIFT           = 16
		DM_UDEV_DISABLE_DM_RULES_FLAG = 0x0001
		DM_UDEV_PRIMARY_SOURCE_FLAG   = 0x0040
	)
	flags := cookie >> DM_UDEV_FLAGS_SHIFT

	// Quoting https://fossies.org/linux/LVM2/libdm/libdevmapper.h
	//
	// DM_UDEV_PRIMARY_SOURCE_FLAG is automatically appended by
	// libdevmapper for all ioctls generating udev uevents. Once used in
	// udev rules, we know if this is a real "primary sourced" event or not.
	// We need to distinguish real events originated in libdevmapper from
	// any spurious events to gather all missing information (e.g. events
	// generated as a result of "udevadm trigger" command or as a result
	// of the "watch" udev rule).
	if flags&DM_UDEV_PRIMARY_SOURCE_FLAG == 0 {
		return false
	}

	// Quoting https://fossies.org/linux/LVM2/libdm/libdevmapper.h
	//
	// DM_UDEV_DISABLE_DM_RULES_FLAG is set in case we need to disable
	// basic device-mapper udev rules that create symlinks in /dev/<DM_DIR>
	if flags&DM_UDEV_DISABLE_DM_RULES_FLAG != 0 {
		return false
	}

	return true
}

func loadModalias(alias string) error {
	mods, err := matchAlias(alias)
	if err != nil {
		debug("unable to match modalias %s: %v", alias, err)
		return nil
	}
	if len(mods) == 0 {
		return fmt.Errorf("no match found for alias %s", alias)
	}
	_ = loadModules(mods...)
	return nil
}

var udevReader io.ReadCloser

func udevListener() {
	var err error
	udevReader, err = uevent.NewReader()
	if err != nil {
		log.Fatalf("uevent: %v", err)
	}
	defer udevReader.Close()

	dec := uevent.NewDecoder(udevReader)

	for {
		ev, err := dec.Decode() // TODO: there is a race condition with closing udevReader that causes panic in bufio.go
		if err != nil {
			log.Fatalf("uevent: %v", err)
		}
		debug("udev event %+v", ev)

		if modalias, ok := ev.Vars["MODALIAS"]; ok {
			if err := loadModalias(modalias); err != nil {
				debug("unable to load modalias %s: %v", modalias, err)
				continue
			}
		} else if devname, ok := ev.Vars["DEVNAME"]; ok {
			if ev.Subsystem != "block" {
				continue
			}

			if strings.HasPrefix(devname, "dm-") {
				cookie := ev.Vars["DM_COOKIE"]
				if !isValidDmEvent(cookie) {
					debug("skipping device mapper device %s because of DM_COOKIE: %s", devname, cookie)
					continue
				}
			} else if ev.Action != "add" {
				continue
			}

			go func() {
				// run luks log-in init in a separate goroutine as it is a slow operation
				if err := devAdd(ev.Devpath, devname); err != nil {
					fmt.Printf("devAdd: %v\n", err)
				}
			}()
		} else if ev.Subsystem == "net" && ev.Action == "add" {
			if config.Network == nil {
				continue
			}
			ifname := ev.Vars["INTERFACE"]
			go func() {
				// run network init in a separate goroutine to avoid it blocking with clevis+tang unlocking
				if err := initializeNetworkInterface(ifname); err != nil {
					fmt.Printf("unable to initialize network interface %s: %v\n", ifname, err)
				}
			}()
		}
	}
}

var initializedIfnames []string

func initializeNetworkInterface(ifname string) error {
	if ifname == "lo" {
		return nil
	}

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.LinkSubscribe(ch, done); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	initializedIfnames = append(initializedIfnames, ifname)

	timeout := time.After(20 * time.Second)
linkReadinessLoop:
	for {
		select {
		case ev := <-ch:
			if ifname == ev.Link.Attrs().Name && (ev.IfInfomsg.Flags&unix.IFF_UP != 0) {
				break linkReadinessLoop
			}
		case <-timeout:
			return fmt.Errorf("Unable to setup network link %s: timeout", ifname)
		}
	}

	c := config.Network
	if c.Dhcp {
		if err := runDhcp(ifname); err != nil {
			return err
		}
	} else {
		// static address
		if c.Ip != "" {
			addr, err := netlink.ParseAddr(c.Ip)
			if err != nil {
				return err
			}
			if err := netlink.AddrAdd(link, addr); err != nil {
				return err
			}
		}

		if c.Gateway != "" {
			gw := net.ParseIP(c.Gateway)
			if gw == nil {
				return fmt.Errorf("network.gateway: unable to parse ip address %s", c.Gateway)
			}
			defaultRoute := netlink.Route{Gw: gw}
			if err := netlink.RouteAdd(&defaultRoute); err != nil {
				return err
			}
		}

		if c.DNSServers != "" {
			servers := strings.Split(c.DNSServers, ",")
			ips := make([]net.IP, 0)
			for _, s := range servers {
				ip := net.ParseIP(s)
				if ip == nil {
					return fmt.Errorf("Unable to parse IP address for DNS server: %v", s)
				}
				ips = append(ips, ip)
			}
			if err := writeResolvConf(ips); err != nil {
				return err
			}
		}
	}

	return nil
}

func runDhcp(ifname string) error {
	dhcp := client4.NewClient()
	var conversation []*dhcpv4.DHCPv4
	for i := 0; i < 40; i++ {
		var err error
		conversation, err = dhcp.Exchange(ifname)
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	var ack *dhcpv4.DHCPv4
	for _, m := range conversation {
		switch m.MessageType() {
		case dhcpv4.MessageTypeAck:
			ack = m
		}
	}
	if ack == nil {
		return fmt.Errorf("DHCP: no ACK received")
	}

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}

	addr := netlink.Addr{IPNet: &net.IPNet{
		IP:   ack.YourIPAddr,
		Mask: ack.SubnetMask(),
	}}
	if err := netlink.AddrAdd(link, &addr); err != nil {
		return err
	}

	dnsServers := dhcpv4.GetIPs(dhcpv4.OptionDomainNameServer, ack.Options)
	if dnsServers != nil {
		if err := writeResolvConf(dnsServers); err != nil {
			return err
		}
	}

	return nil
}

func writeResolvConf(servers []net.IP) error {
	var resolvConf bytes.Buffer
	for _, ip := range servers {
		resolvConf.WriteString("nameserver ")
		resolvConf.WriteString(ip.String())
		resolvConf.WriteByte('\n')
	}
	resolvConf.WriteString("search .\n")

	return ioutil.WriteFile("/etc/resolv.conf", resolvConf.Bytes(), 0644)
}

func shutdownNetwork() {
	for _, ifname := range initializedIfnames {
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			continue
		}

		addrs, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		for _, a := range addrs {
			_ = netlink.AddrDel(link, &a)
		}

		routes, _ := netlink.RouteList(link, netlink.FAMILY_ALL)
		for _, r := range routes {
			_ = netlink.RouteDel(&r)
		}

		_ = netlink.LinkSetDown(link)
	}
}

// returns all module names that match given alias
func matchAlias(alias string) ([]string, error) {
	var result []string
	for _, a := range aliases {
		match, err := path.Match(a.pattern, alias)
		if err != nil {
			return nil, err
		}
		if match {
			debug("modalias %v matched module %v", alias, a.module)
			result = append(result, a.module)
		}
	}
	return result, nil
}

func scanSysBlock() error {
	devs, err := ioutil.ReadDir("/sys/block")
	if err != nil {
		return err
	}
	for _, d := range devs {
		target := filepath.Join("/sys/block/", d.Name())
		if err := devAdd(target, d.Name()); err != nil {
			// even if it fails to find UUID here (e.g. in case of MBR) we still want to check
			// its partitions
			fmt.Printf("devAdd: %v\n", err)
		}

		// Probe all partitions of this block device, too:
		parts, err := ioutil.ReadDir(target)
		if err != nil {
			return err
		}
		for _, p := range parts {
			// partition name should start with the same prefix as the device itself
			if !strings.HasPrefix(p.Name(), d.Name()) {
				continue
			}
			devpath := filepath.Join(target, p.Name())
			if err := devAdd(devpath, p.Name()); err != nil {
				fmt.Printf("devAdd: %v\n", err)
			}
		}
	}
	return nil
}

func scanSysModaliases(path string, info os.FileInfo, err error) error {
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	if info.Name() != "modalias" {
		return nil
	}

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	alias := strings.TrimSpace(string(b))
	if alias == "" {
		return nil
	}
	if err := loadModalias(alias); err != nil {
		debug("loadModalias: %v", err)
	}

	return nil
}

func boost() error {
	if err := readConfig(); err != nil {
		return err
	}

	kernelVersion, err := getKernelVersion()
	if err != nil {
		return err
	}

	if kernelVersion != config.Kernel {
		return fmt.Errorf("Linux kernel version mismatch. "+
			"This initramfs image was built for version '%s' and it is incompatible with the currently running version '%s'. "+
			"Please rebuild booster image for kernel '%s'.", config.Kernel, kernelVersion, kernelVersion)
	}

	modulesDir = path.Join("/usr/lib/modules", kernelVersion)

	if err := readAliases(modulesDir); err != nil {
		return err
	}

	if err := mount("dev", "/dev", "devtmpfs", syscall.MS_NOSUID, "mode=0755"); err != nil {
		return err
	}
	if err := mount("sys", "/sys", "sysfs", syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		return err
	}
	if err := mount("proc", "/proc", "proc", syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		return err
	}
	if err := mount("run", "/run", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_STRICTATIME, "mode=755"); err != nil {
		return err
	}

	// Per systemd convention https://systemd.io/INITRD_INTERFACE/
	if err := os.Mkdir("/run/initramfs", 0755); err != nil {
		return err
	}

	if err := parseCmdline(); err != nil {
		return err
	}

	rootMounted.Add(1)

	go udevListener()

	_ = loadModules(config.ModulesForceLoad...)

	if err := filepath.Walk("/sys/devices", scanSysModaliases); err != nil {
		return err
	}
	if err := scanSysBlock(); err != nil {
		return err
	}

	if config.MountTimeout != 0 {
		timeout := waitTimeout(&rootMounted, time.Duration(config.MountTimeout)*time.Second)
		if timeout {
			return fmt.Errorf("Timeout waiting for root filesystem")
		}
	} else {
		// wait for mount forever
		rootMounted.Wait()
	}

	cleanup()
	return switchRoot()
}

// waitTimeout waits for the waitgroup for the specified max timeout.
// Returns true if waiting timed out.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}

var aliases []alias

func readAliases(dir string) error {
	f, err := os.Open(path.Join(dir, "booster.alias"))
	if err != nil {
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		parts := strings.Split(line, " ")
		aliases = append(aliases, alias{parts[0], parts[1]})
	}

	return s.Err()
}

var config InitConfig

func readConfig() error {
	data, err := ioutil.ReadFile(initConfigPath)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &config)
}

var (
	loadedModules  = make(map[string]bool)
	loadingModules = make(map[string][]*sync.WaitGroup)
	modulesMutex   sync.Mutex
)

func loadModuleUnlocked(wg *sync.WaitGroup, modules ...string) {
	for _, module := range modules {
		if _, ok := loadedModules[module]; ok {
			continue // the module is already loaded
		}

		_, alreadyLoading := loadingModules[module]
		wg.Add(1)
		loadingModules[module] = append(loadingModules[module], wg)

		if alreadyLoading {
			// we already incremented 'wg' counter
			// now wait till the module is loaded
			continue
		}

		var depsWg sync.WaitGroup
		if deps, ok := config.ModuleDependencies[module]; ok {
			loadModuleUnlocked(&depsWg, deps...)
		}

		// pay attention that 'module' is a loop variable and cannot be passed to goroutine
		// https://github.com/golang/go/wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		mod := module
		go func() {
			depsWg.Wait()
			debug("loading module %s", mod)
			if err := finitModule(mod); err != nil {
				fmt.Println(err)
				return
			}

			modulesMutex.Lock()
			defer modulesMutex.Unlock()

			for _, w := range loadingModules[mod] {
				// signal waiters that the module is loaded
				w.Done()
			}
			delete(loadingModules, mod)
			loadedModules[mod] = true
		}()
	}
}

func finitModule(module string) error {
	f, err := os.Open(path.Join(modulesDir, module+".ko"))
	if err != nil {
		return err
	}
	defer f.Close()

	if err := unix.FinitModule(int(f.Fd()), "", 0); err != nil {
		return fmt.Errorf("finit(%v): %v", module, err)
	}

	return nil
}

func loadModules(modules ...string) *sync.WaitGroup {
	var wg sync.WaitGroup

	modulesMutex.Lock()
	defer modulesMutex.Unlock()

	loadModuleUnlocked(&wg, modules...)
	return &wg
}

func mount(source, target, fstype string, flags uintptr, options string) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	if err := syscall.Mount(source, target, fstype, flags, options); err != nil {
		return fmt.Errorf("mount(%v): %v", source, err)
	}
	return nil
}

func debug(format string, v ...interface{}) {
	if debugEnabled {
		fmt.Printf(format+"\n", v...)
	}
}

// readClock returns value of the clock in usec units
func readClock(clockId int32) (uint64, error) {
	var t unix.Timespec
	err := unix.ClockGettime(clockId, &t)
	if err != nil {
		return 0, err
	}
	return uint64(t.Sec)*1000000 + uint64(t.Nsec)/1000, nil
}

var startRealtime, startMonotonic uint64

func readStartTime() {
	var err error
	startRealtime, err = readClock(unix.CLOCK_REALTIME)
	if err != nil {
		fmt.Printf("read realtime clock: %v\n", err)
	}
	startMonotonic, err = readClock(unix.CLOCK_MONOTONIC)
	if err != nil {
		fmt.Printf("read monotonic clock: %v\n", err)
	}
}

func emergencyShell() {
	if _, err := os.Stat("/usr/bin/busybox"); !os.IsNotExist(err) {
		if err := syscall.Exec("/usr/bin/busybox", []string{"sh", "-I"}, nil); err != nil {
			fmt.Printf("Unable to start an emergency shell: %v\n", err)
		}
	}
}

// checkIfInitrd checks whether this binary run in a prepared initrd environment
func checkIfInitrd() error {
	if os.Getpid() != 1 {
		return fmt.Errorf("Booster init binary does not run as PID 1")
	}

	if _, err := os.Stat("/etc/initrd-release"); os.IsNotExist(err) {
		return fmt.Errorf("initrd-release cannot be found")
	}

	return nil
}

func main() {
	readStartTime()

	if err := checkIfInitrd(); err != nil {
		panic(err)
	}

	debug("Starting booster initramfs")

	// function boost() should never return
	if err := boost(); err != nil {
		// if it does then it indicates some problem
		fmt.Println(err)
	}
	emergencyShell()
}
