package main

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	cmdline = make(map[string]string)
	// all boot params (from cmdline) that look like module.name=value considered as potential module parameters for 'module'
	// it preserved to moduleParams for later use. cmdline is not modified.
	moduleParams            = make(map[string][]string)
	rootMounted             sync.WaitGroup // waits until the root partition is mounted
	concurrentModuleLoading = true
)

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
			key, val := part[:idx], part[idx+1:]
			cmdline[key] = val

			if dot := strings.IndexByte(key, '.'); dot != -1 {
				// this param looks like a module options
				mod, param := key[:dot], key[dot+1:]
				mod = normalizeModuleName(mod)
				moduleParams[mod] = append(moduleParams[mod], param+"="+val)
			}
		} else {
			cmdline[part] = ""
		}
	}

	if _, ok := cmdline["booster.debug"]; ok {
		verbosityLevel = levelDebug

		// booster debug generates a lot of kmsg logs, to be able to preserve all these logs we disable kmsg throttling
		if err := disableKmsgThrottling(); err != nil {
			// user might set 'printk.devkmsg' param and it disables changing the throttling level
			// in this case ignore the error
			debug("%v", err)
		}
	} else if _, ok := cmdline["quiet"]; ok {
		verbosityLevel = levelSevere
	}

	if _, ok := cmdline["booster.disable_concurrent_module_loading"]; ok {
		concurrentModuleLoading = false
	}

	return nil
}

var (
	addedDevices      = map[string]bool{}
	addedDevicesMutex sync.Mutex
)

// addBlockDevice is called upon receiving a uevent from the kernel with action “add”
// from subsystem “block”.
func addBlockDevice(devname string) error {
	// Some devices might receive multiple udev add events
	// Avoid processing these node twice by tracking what has been added already
	addedDevicesMutex.Lock()
	if _, ok := addedDevices[devname]; ok {
		addedDevicesMutex.Unlock()
		return nil
	}
	addedDevices[devname] = true
	addedDevicesMutex.Unlock()

	debug("found a new device %s", devname)

	cmdroot := cmdline["root"]

	devpath := path.Join("/dev", devname)
	info, err := readBlkInfo(devpath)
	if err == errUnknownBlockType {
		// provide a fake blkid with fs type specified by user
		info = &blkInfo{
			format: cmdline["rootfstype"],
			isFs:   true,
		}
		debug("unable to detect fs type for %s, using one specified by rootfstype boot param %s", devpath, cmdline["rootfstype"])
	} else if err != nil {
		return fmt.Errorf("%s: %v", devpath, err)
	}

	if cmdresume, ok := cmdline["resume"]; ok {
		if cmdresume == devpath || blkIdMatches(cmdresume, info) {
			if err := resume(devpath); err != nil {
				return err
			}
		}
	}

	matchesRoot := devpath == cmdroot || blkIdMatches(cmdroot, info)

	if matchesRoot {
		if !info.isFs {
			return fmt.Errorf("specified root %s has type %s and cannot be mounted as a filesystem", cmdroot, info.format)
		}
		if info.format == "" {
			return fmt.Errorf("unable to detect filesystem type for device %s and no 'rootfstype' boot parameter specified", devpath)
		}
		return mountRootFs(devpath, info.format)
	}

	if info.format == "luks" {
		return handleLuksBlockDevice(info, devpath)
	}

	return nil
}

func blkIdMatches(blkId string, info *blkInfo) bool {
	if strings.HasPrefix(blkId, "UUID=") {
		uuid := strings.TrimPrefix(blkId, "UUID=")
		u, err := parseUUID(stripQuotes(uuid))
		if err != nil {
			warning("unable to parse UUID parameter %s: %v", blkId, err)
			return false
		}
		return bytes.Equal(u, info.uuid)
	}
	if strings.HasPrefix(blkId, "LABEL=") {
		label := strings.TrimPrefix(blkId, "LABEL=")
		return info.label == label
	}

	return false
}

func resume(devpath string) error {
	devNo, err := deviceNo(devpath)
	if err != nil {
		return err
	}
	major := unix.Major(devNo)
	minor := unix.Minor(devNo)

	debug("resuming device %s, devno=(%d,%d)", devpath, major, minor)
	rd := fmt.Sprintf("%d:%d", major, minor)
	return os.WriteFile("/sys/power/resume", []byte(rd), 0644)
}

func fsck(dev string) error {
	if _, err := os.Stat("/usr/bin/fsck"); !os.IsNotExist(err) {
		cmd := exec.Command("/usr/bin/fsck", "-y", dev)
		if verbosityLevel >= levelDebug {
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

func mountRootFs(dev, fstype string) error {
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
		warning("/run does not exist at the newly mounted root filesystem")

		// unmount /run so its directory can be removed and reclaimed
		if err := unix.Unmount("/run", 0); err != nil {
			return fmt.Errorf("unmount(/run): %v", err)
		}
		return nil
	}

	if err := unix.Mount("/run", newRoot+"/run", "", unix.MS_MOVE, ""); err != nil {
		return fmt.Errorf("move /run to new root: %v", err)
	}

	return nil
}

// deleteContent deletes content of the path recursively but without crossing mountpoints.
// It checks that deleted files belong to the same device id (i.e. not a mountpoint).
func deleteContent(path string, rootDev uint64) error {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}

	if stat.Dev != rootDev {
		// we crossed the fs boundary, it is time to stop deleting files
		return nil
	}

	if fs.FileMode(stat.Mode).IsDir() {
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
			return fmt.Errorf("remove(%s): %v", path, err)
		}
	}

	return nil
}

// Once we completed rootfs identification/mount it is time to remove the ramfs and reclaime some memory back
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

	var stat, newStat unix.Stat_t
	if err := unix.Stat("/", &stat); err != nil {
		return err
	}
	rootDev := stat.Dev

	if err := unix.Stat(newRoot, &newStat); err != nil {
		return err
	}
	if newStat.Dev == rootDev {
		return fmt.Errorf("new root fs is the same device as initramfs")
	}

	// extra sanity check that we really at booster initramfs
	for _, f := range []string{"/init", "/etc/booster.init.yaml", "/etc/initrd-release"} {
		var st unix.Stat_t
		if err := unix.Stat(f, &st); err != nil {
			return err
		}

		if fs.FileMode(st.Mode).IsDir() {
			return fmt.Errorf("expected that %s is a file", f)
		}
		if st.Dev != rootDev {
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
		// some drivers (e.g. GPU) might use these filesystems, unmount it lazily
		if err := unix.Unmount(m, unix.MNT_DETACH); err != nil {
			return fmt.Errorf("unmount(%s): %v", m, err)
		}
	}

	if err := deleteRamfs(); err != nil {
		return fmt.Errorf("wiping ramfs: %v", err)
	}
	if err := os.Chdir(newRoot); err != nil {
		return fmt.Errorf("chdir: %v", err)
	}
	if err := unix.Mount(".", "/", "", unix.MS_MOVE, ""); err != nil {
		return fmt.Errorf("mount dir to root: %v", err)
	}
	if err := unix.Chroot("."); err != nil {
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
	if err := unix.Exec(newInitBin, initArgs, nil); err != nil {
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
		if err := addBlockDevice(d.Name()); err != nil {
			// even if it fails to find UUID here (e.g. in case of unsupported partition table)
			// we still want to check its partitions
			return err
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
			if err := addBlockDevice(p.Name()); err != nil {
				return err
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
		debug("%v", err)
	}

	return nil
}

func boost() error {
	debug("Starting booster initramfs")

	var err error
	if err := mount("dev", "/dev", "devtmpfs", unix.MS_NOSUID, "mode=0755"); err != nil {
		return err
	}
	kmsg, err = os.OpenFile("/dev/kmsg", unix.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	if err := mount("sys", "/sys", "sysfs", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, ""); err != nil {
		return err
	}
	if err := mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, ""); err != nil {
		return err
	}
	if err := mount("run", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_STRICTATIME, "mode=755"); err != nil {
		return err
	}

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
	if err := unix.Mount(source, target, fstype, flags, options); err != nil {
		return fmt.Errorf("mount(%v): %v", source, err)
	}
	return nil
}

var startRealtime, startMonotonic uint64

func readStartTime() {
	var err error
	startRealtime, err = readClock(unix.CLOCK_REALTIME)
	if err != nil {
		severe("read realtime clock: %v\n", err)
	}
	startMonotonic, err = readClock(unix.CLOCK_MONOTONIC)
	if err != nil {
		severe("read monotonic clock: %v\n", err)
	}
}

func emergencyShell() {
	if _, err := os.Stat("/usr/bin/busybox"); !os.IsNotExist(err) {
		if err := unix.Exec("/usr/bin/busybox", []string{"sh", "-I"}, nil); err != nil {
			severe("Unable to start an emergency shell: %v\n", err)
		}
	}
}

func reboot() {
	fmt.Println("Press ENTER to reboot")
	_, _ = fmt.Scanln()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
}

func main() {
	readStartTime()

	if err := checkIfInitrd(); err != nil {
		panic(err)
	}

	// function boost() should never return
	if err := boost(); err != nil {
		// if it does then it indicates some problem
		severe("%v", err)
	}
	emergencyShell()

	// if we are here then emergency shell did not launch
	// in this case suggest user to reboot the computer
	reboot()
}
