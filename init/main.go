package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	rootMounting            int32          // shows if there is a mounting operation in progress
	rootMounted             sync.WaitGroup // waits until the root partition is mounted
	concurrentModuleLoading = true
)

type set map[string]bool

var cmdRoot *deviceRef
var cmdResume *deviceRef

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

	cmdRoot, err = parseDeviceRef("root", cmdline["root"], true)
	if err != nil {
		return err
	}
	if param, ok := cmdline["resume"]; ok {
		cmdResume, err = parseDeviceRef("resume", param, false)
		if err != nil {
			return err
		}
	}

	return nil
}

var (
	addedDevices sync.Map
)

// addBlockDevice is called upon receiving a uevent from the kernel with action “add”
// from subsystem “block”.
// devpath is a full path to the block device and should include /dev/... prefix
func addBlockDevice(devpath string) error {
	// Some devices might receive multiple udev add events
	// Avoid processing these nodes twice by tracking what has been added already
	if _, alreadyAdded := addedDevices.LoadOrStore(devpath, true); alreadyAdded {
		// this devpath has been processed already
		return nil
	}

	debug("found a new device %s", devpath)

	info, err := readBlkInfo(devpath)
	if err == nil {
		// check non-mountable types that require extra processing
		switch info.format {
		case "luks":
			return handleLuksBlockDevice(info, devpath)
		case "lvm":
			return handleLvmBlockDevice(devpath)
		case "mdraid":
			return handleMdraidBlockDevice(info, devpath)
		case "gpt":
			return handleGptBlockDevice(info, devpath)
		}
	} else if err == errUnknownBlockType {
		// provide a fake blkid with fs type specified by user
		info = &blkInfo{
			path:   devpath,
			format: cmdline["rootfstype"],
			isFs:   true,
		}
		debug("unable to detect fs type for %s, using one specified by rootfstype boot param %s", devpath, cmdline["rootfstype"])
	} else {
		return fmt.Errorf("%s: %v", devpath, err)
	}

	if cmdResume != nil && cmdResume.matchesBlkInfo(info) {
		if err := resume(devpath); err != nil {
			return err
		}
	}

	if cmdRoot.matchesBlkInfo(info) {
		if !info.isFs {
			return fmt.Errorf("specified root %s has type %s and cannot be mounted as a filesystem", devpath, info.format)
		}
		if info.format == "" {
			return fmt.Errorf("unable to detect filesystem type for device %s and no 'rootfstype' boot parameter specified", devpath)
		}
		return mountRootFs(devpath, info.format)
	}

	return nil
}

// handleGptBlockDevice accepts information about GPT partition table and tries to match
// possible root= partition.
func handleGptBlockDevice(info *blkInfo, devPath string) error {
	gptParts := info.data.(gptData).partitions
	cmdRoot = cmdRoot.resolveFromGptTable(devPath, gptParts)
	return nil
}

var raidModules = map[uint32]string{
	levelMultipath: "multipath",
	levelLinear:    "linear",
	levelRaid0:     "raid0",
	levelRaid1:     "raid1",
	levelRaid4:     "raid456",
	levelRaid5:     "raid456",
	levelRaid6:     "raid456",
	levelRaid10:    "raid10",
}

func handleMdraidBlockDevice(info *blkInfo, devpath string) error {
	if !config.EnableMdraid {
		debug("MdRaid support is disabled, ignoring mdraid device %s", devpath)
		return nil
	}
	debug("trying to assemble mdraid array %s", info.uuid.toString())

	if mod, ok := raidModules[info.data.(mdraidData).level]; ok {
		wg := loadModules(mod)
		wg.Wait()
	} else {
		return fmt.Errorf("unknown raid level for device %s", devpath)
	}

	out, err := exec.Command("mdadm", "--export", "--incremental", devpath).CombinedOutput()
	if err != nil {
		return err
	}

	props := parseProperties(string(out))
	arrayName, hasArrayName := props["MD_DEVNAME"]
	if !hasArrayName {
		return fmt.Errorf("mdraid array at %s does not have a MD_DEVNAME property", info.uuid.toString())
	}

	if started, ok := props["MD_STARTED"]; !ok || started != "yes" {
		debug("mdraid array %s is not complete, ignore it", arrayName)
		return nil
	}

	return addBlockDevice("/dev/md/" + arrayName)
}

func handleLvmBlockDevice(devpath string) error {
	if !config.EnableLVM {
		debug("LVM support is disabled, ignoring lvm physical volume %s", devpath)
		return nil
	}

	debug("scanning lvm physical volume %s", devpath)
	cmd := exec.Command("lvm", "pvscan", "--cache", "-aay", devpath)
	if verbosityLevel >= levelDebug {
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
	}
	return cmd.Run()
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
	if !atomic.CompareAndSwapInt32(&rootMounting, 0, 1) {
		return nil // mount process is in progress
	}

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

// moveMountpointsToHost moves some of the initramfs mounts into the host filesystem
// it is needed for example in following cases:
//    /run might contain some udev state that needs to be passed from initramfs to host
//    runit expects that /dev/ is mounted at the moment runit starts
func moveMountpointsToHost() error {
	for _, m := range []string{"/run", "/dev", "/proc", "/sys"} {
		// remount root as it might contain state that we need to pass to the new root
		_, err := os.Stat(newRoot + m)
		if os.IsNotExist(err) {
			// let's print a warning and hope that host OS setup the filesystem if needed
			warning("%s does not exist at the newly mounted root filesystem", m)

			// unmount the directory so its directory can be removed and reclaimed
			if err := unix.Unmount(m, unix.MNT_DETACH); err != nil {
				return fmt.Errorf("unmount(%s): %v", m, err)
			}
			continue
		}

		if err := unix.Mount(m, newRoot+m, "", unix.MS_MOVE, ""); err != nil {
			return fmt.Errorf("move %s to new root: %v", m, err)
		}
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
	if err := moveMountpointsToHost(); err != nil {
		return err
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
	shutdownNetwork()
}

func scanSysBlock() error {
	devs, err := os.ReadDir("/sys/block")
	if err != nil {
		return err
	}
	for _, d := range devs {
		target := filepath.Join("/sys/block/", d.Name())
		if err := addBlockDevice("/dev/" + d.Name()); err != nil {
			// some unimportant block devices (e.g. /dev/sr0) might return errors like 'no medium found'
			// just ignore failing devices and keep enumerating
			warning("%v", err)
			continue
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
			if err := addBlockDevice("/dev/" + p.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

func scanSysModaliases(path string, info os.FileInfo, err error) error {
	if err != nil {
		if os.IsNotExist(err) {
			// /dev/sys has a number of ephemeral files (like 'waiting_for_supplier') that might be added/removed
			// from the fs underneath us. Workaround it, ignore any errors for files that we listed but later unable to read.
			return nil
		}
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

	rootMounted.Add(1)

	go udevListener()

	loadModulesWg := loadModules(config.ModulesForceLoad...)

	if err := configureVirtualConsole(); err != nil {
		return err
	}

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

	loadModulesWg.Wait()

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
