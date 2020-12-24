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

// TODO: find out how to avoid synchronous waiting for files
func waitForFile(filename string) error {
	deadline := time.Now().Add(1 * time.Second)

	for {
		_, err := os.Stat(filename)
		if err == nil {
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("waitForFile: %v", err)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %v", filename)
		}

		time.Sleep(10 * time.Millisecond)
	}
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

	debug("Found a new device with path=%v and name=%v", syspath, devname)

	cmdroot := cmdline["root"]

	devpath := path.Join("/dev", devname)
	if !strings.HasPrefix(cmdroot, "UUID=") && devpath == cmdroot {
		return mountRootFs(devpath)
	}

	if strings.HasPrefix(devname, "dm-") {
		dmNameFile := filepath.Join("/sys", syspath, "dm", "name")
		if err := waitForFile(dmNameFile); err != nil {
			return err
		}
		content, err := ioutil.ReadFile(dmNameFile)
		if err != nil {
			return err
		}
		mapperName := string(bytes.TrimSpace(content))
		dmPath := "/dev/mapper/" + mapperName

		// setup symlink /dev/dm-NN -> /dev/mapper/NAME
		if err := os.Symlink(devpath, dmPath); err != nil {
			return err
		}

		if err := waitForFile(devpath); err != nil {
			return err
		}
		devpath = dmPath // later we use /dev/mapper/NAME as a mount point

		if dmPath == cmdroot {
			return mountRootFs(dmPath)
		}
	}

	fstype, uuid, err := blkid(devpath)
	if err != nil {
		return err
	}
	debug("blkid for %s: type=%s UUID='%s'", devpath, fstype, uuid)

	if strings.HasPrefix(cmdroot, "UUID=") && uuid == strings.TrimPrefix(cmdroot, "UUID=") {
		return mountRootFs(devpath)
	}

	if cmdline["rd.luks.name"] != "" {
		parts := strings.Split(cmdline["rd.luks.name"], "=")
		if len(parts) != 2 {
			return fmt.Errorf("Invalid rd.luks.name kernel parameter. Got: %v   Expected: rd.luks.name=<UUID>=<Name>", cmdline["rd.luks.name"])
		}
		if parts[0] == uuid {
			return luksOpen(devpath, parts[1])
		}
	}
	if cmdline["rd.luks.uuid"] == uuid {
		return luksOpen(devpath, "luks-"+uuid)
	}

	return nil
}

func luksOpen(dev string, name string) error {
	if err := loadModules("dm_crypt"); err != nil {
		return err
	}

	d, err := luks.Open(dev)
	if err != nil {
		return err
	}
	defer d.Close()

	if len(d.Slots()) == 0 {
		return fmt.Errorf("device %s has no slots to unlock", dev)
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
			if err == nil {
				MemZeroBytes(password)
				return nil
			}
			if err != luks.ErrPassphraseDoesNotMatch {
				MemZeroBytes(password)
				return fmt.Errorf("unlocking clevis slot %d: %v", s, err)
			}
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
			if err == nil || err != luks.ErrPassphraseDoesNotMatch {
				MemZeroBytes(password)
				return err
			}
		}

		// zeroify the password so we do not keep the sensitive data in the memory
		MemZeroBytes(password)

		// retry password
		fmt.Println("   incorrect passphrase, please try again")
	}
}

func mountRootFs(dev string) error {
	fstype := cmdline["rootfstype"]
	if fstype == "" {
		var err error
		fstype, _, err = blkid(dev)
		if err != nil {
			return fmt.Errorf("%s: %v", dev, err)
		}
	}
	debug("mounting %s (fstype=%s) to %s", dev, fstype, newRoot)

	if err := loadModules(fstype); err != nil {
		return err
	}

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

// https://github.com/mirror/busybox/blob/9aa751b08ab03d6396f86c3df77937a19687981b/util-linux/switch_root.c#L297
func switchRoot() error {
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

	// Run the OS init
	debug("Booster initialization took %v. Switching to the new userspace now. Да пабачэння!", time.Now().Sub(start))
	if err := syscall.Exec(newInitBin, []string{newInitBin}, nil); err != nil {
		return fmt.Errorf("Can't run the rootfs init (%v): %v", newInitBin, err)
	}
	return nil // unreachable
}

// Cleanup the state before handing off the machine to the new init
func cleanup() {
	// We need to close our uevent connection, otherwise it will stay open forever and mess with the new init. .
	// See https://github.com/s-urbaniak/uevent/pull/1
	_ = udevReader.Close()

	shutdownNetwork()
}

func skipDeviceMapper(dmCookie string) bool {
	if dmCookie == "" {
		return false // device not set up by libdevmapper
	}

	// skip device mapper devices if their cookie has flag
	// DM_UDEV_DISABLE_DISK_RULES_FLAG set:
	// https://sourceware.org/git/?p=lvm2.git;a=blob;f=lib/activate/dev_manager.c;hb=d9e8895a96539d75166c0f74e58f5ed4e729e551#l1935
	cookie, err := strconv.ParseUint(dmCookie, 0, 32)
	if err != nil {
		return false // invalid cookie
	}
	// libdevmapper.h
	const (
		DM_UDEV_FLAGS_SHIFT             = 16
		DM_UDEV_DISABLE_DISK_RULES_FLAG = 0x0004
	)
	flags := cookie >> DM_UDEV_FLAGS_SHIFT
	return flags&DM_UDEV_DISABLE_DISK_RULES_FLAG > 0
}

func loadModalias(alias string) error {
	mods, err := matchAlias(alias)
	if err != nil {
		debug("unable to match modalias %s", alias)
		return nil
	}
	if len(mods) == 0 {
		return fmt.Errorf("no match found for alias %s", alias)
	}
	// for topological module sorting use https://github.com/paultag/go-topsort
	return loadModules(mods...)
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

		if modalias, ok := ev.Vars["MODALIAS"]; ok {
			if err := loadModalias(modalias); err != nil {
				debug("unable to load modalias %s: %v", modalias, err)
				continue
			}
		} else if devname, ok := ev.Vars["DEVNAME"]; ok {
			// The libdevmapper activation sequence results in an add uevent
			// before the device is ready, so wait for the change uevent:
			// https://www.redhat.com/archives/linux-lvm/2020-April/msg00004.html
			if !(((!strings.HasPrefix(devname, "dm-") && ev.Action == "add") ||
				(strings.HasPrefix(devname, "dm-") && ev.Action == "change")) &&
				ev.Subsystem == "block") {
				continue
			}

			if skipDeviceMapper(ev.Vars["DM_COOKIE"]) {
				debug("skipping device mapper device %s because of DM_COOKIE", devname)
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
					fmt.Printf("unable to initialize network interface %s: %v", ifname, err)
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
	return nil
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
			debug("Modalias %v matched module %v", alias, a.module)
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
			fmt.Printf("devAdd: %v", err)
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
				fmt.Printf("devAdd: %v", err)
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
	if err := mount("run", "/run", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0755"); err != nil {
		return err
	}

	if err := parseCmdline(); err != nil {
		return err
	}

	rootMounted.Add(1)

	go udevListener()

	if err := loadModules(config.ModulesForceLoad...); err != nil {
		return err
	}

	if err := filepath.Walk("/sys/devices", scanSysModaliases); err != nil {
		return err
	}
	if err := scanSysBlock(); err != nil {
		return err
	}

	rootMounted.Wait()
	cleanup()
	return switchRoot()
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
	loadedModules      = make(map[string]bool)
	loadedModulesMutex sync.Mutex
)

// TODO: implement parallel/asynchronous modules load
func loadModules(modules ...string) error {
	for _, mod := range modules {
		loadedModulesMutex.Lock()
		if loadedModules[mod] {
			loadedModulesMutex.Unlock()
			continue
		}
		loadedModules[mod] = true
		loadedModulesMutex.Unlock()

		if deps, ok := config.ModuleDependencies[mod]; ok {
			if err := loadModules(deps...); err != nil {
				return err
			}
		}

		debug("loading module %s", mod)

		f, err := os.Open(path.Join(modulesDir, mod+".ko"))
		if err != nil {
			return err
		}
		defer f.Close()

		if err := unix.FinitModule(int(f.Fd()), "", 0); err != nil {
			return fmt.Errorf("finit(%v): %v", mod, err)
		}
	}
	return nil
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

var start time.Time // booster start time

func main() {
	start = time.Now()
	if os.Getpid() != 1 {
		panic("Booster init binary does not run as PID 1")
	}

	debug("Starting booster initramfs")

	// function boost() should never return
	err := boost()
	// if it does that it indicates some problem. TODO: switch to emergency shell.
	panic(err)
}
