package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yookoala/realpath"
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
	rootMounted  sync.WaitGroup // waits until the root partition is mounted
)

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
	b, err := os.ReadFile("/proc/cmdline")
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
		content, err := os.ReadFile(dmNameFile)
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
		return fmt.Errorf("%s: %v", devpath, err)
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

func fsck(dev string) error {
	if _, err := os.Stat("/usr/bin/fsck"); !os.IsNotExist(err) {
		cmd := exec.Command("/usr/bin/fsck", "-y", dev)
		if debugEnabled {
			cmd.Stderr = os.Stderr
			cmd.Stdout = os.Stdout
		}
		if err := cmd.Run(); err != nil {
			if err, ok := err.(*exec.ExitError); ok {
				code := err.ExitCode()
				code &^= 0x1 // bit 1 means errors were corrected successfully which is good

				if code != 0 {
					return fmt.Errorf("fsck for %s failed with code 0x%x", dev, err.ExitCode())
				}
			}

			return fmt.Errorf("fsck for %s: unknown error %v", dev, err)
		}
	}

	return nil
}

func mountRootFs(dev string) error {
	info, err := readBlkInfo(dev)
	if err != nil {
		return fmt.Errorf("%s: %v", dev, err)
	}

	fstype := cmdline["rootfstype"]
	if fstype == "" {
		// use detected filetype, but first let's check if it is a real filesystem
		if !info.isFs {
			return fmt.Errorf("%s: device you are trying to mount has type '%s' that does not look like a mountable filesystem", dev, info.format)
		}

		fstype = info.format
	}
	debug("mounting %s (fstype=%s) to %s", dev, fstype, newRoot)

	wg := loadModules(fstype)
	wg.Wait()

	if err := fsck(dev); err != nil {
		return err
	}

	rootMountFlags, options := sunderMountFlags(cmdline["rootflags"])
	if _, ro := cmdline["ro"]; ro {
		rootMountFlags |= unix.MS_RDONLY
	}
	if _, rw := cmdline["rw"]; rw {
		rootMountFlags &^= unix.MS_RDONLY
	}
	if err := mount(dev, newRoot, fstype, rootMountFlags, options); err != nil {
		return err
	}

	rootMounted.Done()
	return nil
}

// sunderMountFlags separates list of mount parameters (usually provided by a user) into `flags` and `options`
// consumable by mount() functions.
// for example 'noatime,user_xattr,nodev,nobarrier' becomes MS_NOATIME|MS_NODEV and 'user_xattr,nobarrier'
func sunderMountFlags(options string) (uintptr, string) {
	var outOptions []string
	var flags uintptr
	for _, o := range strings.Split(options, ",") {
		switch o {
		case "dirsync":
			flags |= unix.MS_DIRSYNC
		case "lazytime":
			flags |= unix.MS_LAZYTIME
		case "nolazytime":
			flags &^= unix.MS_LAZYTIME
		case "noatime":
			flags |= unix.MS_NOATIME
		case "atime":
			flags &^= unix.MS_NOATIME
		case "nodev":
			flags |= unix.MS_NODEV
		case "dev":
			flags &^= unix.MS_NODEV
		case "nodiratime":
			flags |= unix.MS_NODIRATIME
		case "diratime":
			flags &^= unix.MS_NODIRATIME
		case "noexec":
			flags |= unix.MS_NOEXEC
		case "exec":
			flags &^= unix.MS_NOEXEC
		case "nosuid":
			flags |= unix.MS_NOSUID
		case "suid":
			flags &^= unix.MS_NOSUID
		case "ro":
			flags |= unix.MS_RDONLY
		case "rw":
			flags &^= unix.MS_RDONLY
		case "relatime":
			flags |= unix.MS_RELATIME
		case "norelatime":
			flags &^= unix.MS_RELATIME
		case "silent":
			flags |= unix.MS_SILENT
		case "strictatime":
			flags |= unix.MS_STRICTATIME
		case "nostrictatime":
			flags &^= unix.MS_STRICTATIME
		case "sync":
			flags |= unix.MS_SYNC
		case "async":
			flags &^= unix.MS_SYNC
		case "nosymfollow":
			flags |= unix.MS_NOSYMFOLLOW
		default:
			// if it did not match any flag then return it back and use as an option
			outOptions = append(outOptions, o)
		}
	}

	return flags, strings.Join(outOptions, ",")
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
		fmt.Println("/run does not exist at the root filesystem")

		// unmount /run so its directory can be removed and reclaimed
		if err := syscall.Unmount("/run", 0); err != nil {
			return err
		}
		return nil
	}

	if err := syscall.Mount("/run", newRoot+"/run", "", syscall.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move /run to new root: %v", err)
	}

	return nil
}

// deleteContent deletes content of the path recursively but without crossing mountpoints.
// It checks that deleted files belong to the same device id (i.e. not a mountpoint).
func deleteContent(path string, rootDev uint64) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}

	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("expected stat_t structure for '%s'", path)
	}
	if stat.Dev != rootDev {
		// we crossed the fs boundary, it is time to stop deleting files
		return nil
	}

	if st.IsDir() {
		dirEntries, err := os.ReadDir(path)
		if err != nil {
			return err
		}

		for _, e := range dirEntries {
			if e.Name() == "." || e.Name() == ".." {
				continue
			}
			if err := deleteContent(filepath.Join(path, e.Name()), rootDev); err != nil {
				return err
			}
		}
	}

	if path != "/" {
		// root directory cannot be removed as it is busy (initramfs is mounted here).
		// "/" and newRoot are going to be the only leftovers from initramfs stage.
		if err := os.Remove(path); err != nil {
			return err
		}
	}

	return nil
}

// Once we completed rootfs identification/mount it is time to remove the ramfs and reclaime some mempry back
// to the system.
// IT IS A DANGEROUS OPERATION
// We need to be *extra* careful here and do not remove user's content from the root filesystem.
// Thus we perform many checks to be sure that
//   * current process is a booster init
//   * remove files at the iniramfs only and do not cross mount boundaries
func deleteRamfs() error {
	if os.Getpid() != 1 {
		return fmt.Errorf("init PID is not 1")
	}

	rootStat, err := os.Stat("/")
	if err != nil {
		return err
	}
	s, ok := rootStat.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("expected stat_t structure for '/' mountpoint")
	}
	rootDev := s.Dev

	newStat, err := os.Stat(".")
	if err != nil {
		return err
	}
	n, ok := newStat.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("expected stat_t structure for '.' mountpoint")
	}
	if n.Dev == rootDev {
		return fmt.Errorf("new root fs is the same device as initramfs")
	}

	// extra sanity check that we really at booster initramfs
	for _, f := range []string{"/init", "/etc/booster.init.yaml", "/etc/initrd-release"} {
		st, err := os.Stat(f)
		if err != nil {
			return err
		}

		if st.IsDir() {
			return fmt.Errorf("expected that %s is a file", f)
		}

		n, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("expected stat_t structure for '%s' file", f)
		}
		if n.Dev != rootDev {
			return fmt.Errorf("file %s is not at the initramfs", f)
		}
	}

	// initramfs should be mounted as ramfs/tmpfs
	var statfs unix.Statfs_t
	if err := unix.Statfs("/", &statfs); err != nil {
		return fmt.Errorf("statfs(/): %v", err)
	}
	if uint32(statfs.Type) != unix.RAMFS_MAGIC && uint32(statfs.Type) != unix.TMPFS_MAGIC {
		return fmt.Errorf("initramfs is not of ramfs/tmpfs type")
	}

	return deleteContent("/", rootDev)
}

// https://github.com/mirror/busybox/blob/9aa751b08ab03d6396f86c3df77937a19687981b/util-linux/switch_root.c#L297
func switchRoot() error {
	if err := moveSlashRunMountpoint(); err != nil {
		return err
	}

	// note that /run has been unmounted earlier
	for _, m := range []string{"/dev", "/proc", "/sys"} {
		if err := syscall.Unmount(m, 0); err != nil {
			return err
		}
	}

	if err := os.Chdir(newRoot); err != nil {
		return fmt.Errorf("chdir: %v", err)
	}
	if err := deleteRamfs(); err != nil {
		return err
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

func scanSysBlock() error {
	devs, err := os.ReadDir("/sys/block")
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
		parts, err := os.ReadDir(target)
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

	b, err := os.ReadFile(path)
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
	if err := os.Setenv("PATH", "/usr/bin"); err != nil {
		return err
	}

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

	if err := readAliases(); err != nil {
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

	if err := configureVirtualConsole(); err != nil {
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

var config InitConfig

func readConfig() error {
	data, err := os.ReadFile(initConfigPath)
	if err != nil {
		return err
	}

	return yaml.Unmarshal(data, &config)
}

func mount(source, target, fstype string, flags uintptr, options string) error {
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	debug("mounting %s->%s, fs=%s, flags=0x%x, options=%s", source, target, fstype, flags, options)
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
