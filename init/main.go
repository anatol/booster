package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	newRoot = "/booster.root"
)

var (
	cmdline = make(map[string]string)
	// all boot params (from cmdline) that look like module.name=value considered as potential module parameters for 'module'
	// it preserved to moduleParams for later use. cmdline is not modified.
	moduleParams = make(map[string][]string)
	rootMounting int32          // shows if there is a mounting operation in progress
	rootMounted  sync.WaitGroup // waits until the root partition is mounted

	cmdRoot   *deviceRef
	cmdResume *deviceRef

	initBinary = "/sbin/init" // path to init binary inside the user's chroot

	luksMappings []luksMapping // list of LUKS devices that booster unlocked during boot process

	rootAutodiscoveryMode       bool
	rootAutodiscoveryMountFlags uintptr // autodiscovery mode uses GPT attribute to configure mount flags
	activeEfiEspGUID            UUID    // partition that was used as Efi system partition last time
)

type set map[string]bool

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

	if param, ok := cmdline["booster.log"]; ok {
		for _, p := range strings.Split(param, ",") {
			switch p {
			case "debug":
				verbosityLevel = levelDebug
			case "info":
				verbosityLevel = levelInfo
			case "warning":
				verbosityLevel = levelWarning
			case "error":
				verbosityLevel = levelError
			case "console":
				printToConsole = true
			default:
				warning("unknown booster.log key: %s", p)
			}
		}
	} else if _, ok := cmdline["booster.debug"]; ok {
		// booster.debug is an obsolete parameter
		verbosityLevel = levelDebug
		printToConsole = true
	} else if _, ok := cmdline["quiet"]; ok {
		verbosityLevel = levelError
	}

	if verbosityLevel >= levelDebug {
		// booster debug generates a lot of kmsg logs, to be able to preserve all these logs we disable kmsg throttling
		if err := disableKmsgThrottling(); err != nil {
			// user might set 'printk.devkmsg' param and it disables changing the throttling level
			// in this case ignore the error
			info("%v", err)
		}
	}

	if param, ok := cmdline["root"]; ok {
		cmdRoot, err = parseDeviceRef(param)
		if err != nil {
			return fmt.Errorf("root=%s: %v", param, err)
		}
	} else {
		// try to auto-discover gpt partition https://www.freedesktop.org/wiki/Specifications/DiscoverablePartitionsSpec/
		rootUUIDType, ok := rootAutodiscoveryGptTypes[runtime.GOARCH]
		if !ok {
			return fmt.Errorf("root= boot option is not specified")
		}
		info("root= param is not specified. Use GPT partition autodiscovery with guid type %s", rootUUIDType)
		gptType, err := parseUUID(rootUUIDType)
		if err != nil {
			return err
		}

		activeEfiEspGUID, err = getActiveEfiEsp()
		if err != nil {
			return fmt.Errorf("unable to detect active ESP: %v", err)
		}

		rootAutodiscoveryMode = true
		cmdRoot = &deviceRef{refGptType, gptType}
	}

	if param, ok := cmdline["resume"]; ok {
		cmdResume, err = parseDeviceRef(param)
		if err != nil {
			return fmt.Errorf("resume=%s: %v", param, err)
		}
	}

	if param, ok := cmdline["init"]; ok {
		initBinary = param
	}

	// parse LUKS-specific kernel parameters
	var luksOptions []string
	if param, ok := cmdline["rd.luks.options"]; ok {
		for _, o := range strings.Split(param, ",") {
			flag, ok := rdLuksOptions[o]
			if !ok {
				return fmt.Errorf("unknown value in rd.luks.options: %v", o)
			}
			luksOptions = append(luksOptions, flag)
		}
	}

	if param, ok := cmdline["rd.luks.name"]; ok {
		parts := strings.Split(param, "=")
		if len(parts) != 2 {
			return fmt.Errorf("invalid rd.luks.name kernel parameter %s, expected format rd.luks.name=<UUID>=<name>", cmdline["rd.luks.name"])
		}
		uuid, err := parseUUID(stripQuotes(parts[0]))
		if err != nil {
			return fmt.Errorf("invalid UUID %s %v", parts[0], err)
		}

		dev := luksMapping{
			ref:     &deviceRef{refFsUUID, uuid},
			name:    parts[1],
			options: luksOptions,
		}
		luksMappings = append(luksMappings, dev)
	} else if uuid, ok := cmdline["rd.luks.uuid"]; ok {
		stripped := stripQuotes(uuid)
		u, err := parseUUID(stripped)
		if err != nil {
			return fmt.Errorf("invalid UUID %s in rd.luks.uuid boot param: %v", uuid, err)
		}

		dev := luksMapping{
			ref:     &deviceRef{refFsUUID, u},
			name:    "luks-" + stripped,
			options: luksOptions,
		}
		luksMappings = append(luksMappings, dev)
	}

	return nil
}

// get the active EFI ESP UUID by reading efivars
func getActiveEfiEsp() (UUID, error) {
	_, data, err := readEfiVar("LoaderDevicePartUUID", "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f")
	if err != nil {
		return nil, err
	}

	uuid := fromUnicode16(data, binary.LittleEndian)
	return parseUUID(uuid)
}

// readEfiVar reads efi variable from Linux's sysfs
// returns var attribute, efi var value and error
func readEfiVar(name, uuid string) (uint32, []byte, error) {
	data, err := os.ReadFile("/sys/firmware/efi/efivars/" + name + "-" + uuid)
	if err != nil {
		return 0, nil, err
	}

	attribute := binary.LittleEndian.Uint32(data[:4])
	data = data[4:]
	return attribute, data, nil
}

var (
	devicesMutex sync.Mutex

	seenDevices       = make(set) // devices that are already seen by the system, the devices might be fully processed or processing right now
	processingDevices = make(map[string]*sync.WaitGroup)
	partitionTables   = make(map[string]string) // devicePath -> tablePath map e.g. "/dev/sda1"->"/dev/sda"
)

func addTableNameForDevice(devPath string, tablePath string) {
	devicesMutex.Lock()
	partitionTables[devPath] = tablePath
	devicesMutex.Unlock()
}

func waitForTableToProcess(dev string) {
	devicesMutex.Lock()

	table, ok := partitionTables[dev]
	if !ok {
		devicesMutex.Unlock()
		return
	}

	wg, ok := processingDevices[table]
	if !ok {
		devicesMutex.Unlock()
		return
	}
	devicesMutex.Unlock()

	wg.Wait()
}

func markDeviceProcessed(dev string) {
	devicesMutex.Lock()
	defer devicesMutex.Unlock()

	wg := processingDevices[dev]
	wg.Done()
	delete(processingDevices, dev)
}

// addBlockDevice is called upon discovering a new block device e.g. via udev events or scanning sysfs.
// devpath is a full path to the block device and should include /dev/... prefix
// symlinks is an array of symlinks to the given block device
func addBlockDevice(devpath string, symlinks []string) error {
	// Some devices might receive multiple udev add events
	// Avoid processing these nodes twice by tracking what has been added already
	devicesMutex.Lock()
	if _, alreadyAdded := seenDevices[devpath]; alreadyAdded {
		// this devpath has been seen already
		devicesMutex.Unlock()
		return nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	processingDevices[devpath] = wg
	devicesMutex.Unlock()
	defer markDeviceProcessed(devpath)

	info("found a new device %s", devpath)

	blk, err := readBlkInfo(devpath)
	if err == errUnknownBlockType {
		// even if booster unable to detect a filesystem we might still try to mount with the type specified by the user
		blk = &blkInfo{
			path: devpath,
		}
		err = nil
	}

	if err != nil {
		return fmt.Errorf("%s: %v", devpath, err)
	}

	blk.symlinks = symlinks

	// check non-mountable types that require extra processing
	switch blk.format {
	case "luks":
		return handleLuksBlockDevice(blk)
	case "lvm":
		return handleLvmBlockDevice(blk)
	case "mdraid":
		return handleMdraidBlockDevice(blk)
	case "gpt":
		return handleGptBlockDevice(blk)
	}

	if cmdResume != nil {
		if cmdResume.dependsOnGpt() {
			waitForTableToProcess(devpath)
		}

		if cmdResume.matchesBlkInfo(blk) {
			if err := resume(devpath); err != nil {
				return err
			}
		}
	}

	if cmdRoot.dependsOnGpt() {
		waitForTableToProcess(devpath)
	}
	if cmdRoot.matchesBlkInfo(blk) {
		if blk.format == "" && cmdline["rootfstype"] != "" {
			blk.format = cmdline["rootfstype"]
			blk.isFs = true
		}
		if blk.format == "" {
			return fmt.Errorf("unable to detect filesystem type for device %s and no 'rootfstype' boot parameter specified", devpath)
		}
		if !blk.isFs {
			return fmt.Errorf("specified root %s has type %s and cannot be mounted as a filesystem", devpath, blk.format)
		}
		return mountRootFs(devpath, blk.format)
	}

	return nil
}

// handleGptBlockDevice accepts information about GPT partition table and tries to match
// possible root= partition.
func handleGptBlockDevice(blk *blkInfo) error {
	gpt := blk.data.(gptData)

	if rootAutodiscoveryMode {
		// per DiscoverablePartitionsSpec: "the first partition with this GUID on the disk containing the active EFI ESP is automatically mounted to the root directory /."
		if gpt.containsEsp() {
			info("%s table contains active ESP, use it to discover root", blk.path)
			cmdRoot.resolveGptRef(blk.path, gpt)
		}
	} else {
		cmdRoot.resolveGptRef(blk.path, gpt)
	}

	if cmdResume != nil {
		cmdResume.resolveGptRef(blk.path, gpt)
	}

	for _, m := range luksMappings {
		m.ref.resolveGptRef(blk.path, gpt)
	}

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

func handleMdraidBlockDevice(blk *blkInfo) error {
	if !config.EnableMdraid {
		info("MdRaid support is disabled, ignoring mdraid device %s", blk.path)
		return nil
	}
	info("trying to assemble mdraid array %s", blk.uuid.toString())

	if mod, ok := raidModules[blk.data.(mdraidData).level]; ok {
		wg, err := loadModules(mod)
		if err != nil {
			return err
		}
		wg.Wait()
	} else {
		return fmt.Errorf("unknown raid level for device %s", blk.path)
	}

	out, err := exec.Command("mdadm", "--export", "--incremental", blk.path).CombinedOutput()
	if err != nil {
		return err
	}

	props := parseProperties(string(out))
	arrayName, hasArrayName := props["MD_DEVNAME"]
	if !hasArrayName {
		return fmt.Errorf("mdraid array at %s does not have a MD_DEVNAME property", blk.uuid.toString())
	}

	if started, ok := props["MD_STARTED"]; !ok || started != "yes" {
		info("mdraid array %s is not complete, ignore it", arrayName)
		return nil
	}

	return addBlockDevice("/dev/md/"+arrayName, nil)
}

func handleLvmBlockDevice(blk *blkInfo) error {
	if !config.EnableLVM {
		info("LVM support is disabled, ignoring lvm physical volume %s", blk.path)
		return nil
	}

	info("scanning lvm physical volume %s", blk.path)
	cmd := exec.Command("lvm", "pvscan", "--cache", "-aay", blk.path)
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

	info("resuming device %s, devno=(%d,%d)", devpath, major, minor)
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

	wg, err := loadModules(fstype)
	if err != nil {
		return err
	}
	wg.Wait()

	if err := fsck(dev); err != nil {
		return err
	}

	rootMountFlags, options := sunderMountFlags(cmdline["rootflags"], rootAutodiscoveryMountFlags)
	if _, ro := cmdline["ro"]; ro {
		rootMountFlags |= unix.MS_RDONLY
	}
	if _, rw := cmdline["rw"]; rw {
		rootMountFlags &^= unix.MS_RDONLY
	}
	info("mounting %s->%s, fs=%s, flags=0x%x, options=%s", dev, newRoot, fstype, rootMountFlags, options)
	if err := mount(dev, newRoot, fstype, rootMountFlags, options); err != nil {
		return err
	}

	rootMounted.Done()
	return nil
}

// sunderMountFlags separates list of mount parameters (usually provided by a user) into `flags` and `options`
// consumable by mount() functions.
// This function receives a parameter 'flags' that represents default flags coming from somewhere else (e.g. GPT attributes via autodiscovery)
// for example 'noatime,user_xattr,nodev,nobarrier' becomes MS_NOATIME|MS_NODEV and 'user_xattr,nobarrier'
func sunderMountFlags(options string, flags uintptr) (uintptr, string) {
	var outOptions []string
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

	if _, err := os.Stat(initBinary); os.IsNotExist(err) {
		return fmt.Errorf("init binary %s does not exist in the user's chroot", initBinary)
	}

	initArgs := []string{initBinary}
	isSystemdInit, err := isSystemd(initBinary)
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
	info("Switching to the new userspace now. Да пабачэння!")
	if err := unix.Exec(initBinary, initArgs, nil); err != nil {
		return fmt.Errorf("Can't run the rootfs init (%v): %v", initBinary, err)
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
		// some unimportant block devices (e.g. /dev/sr0) might return errors like 'no medium found'
		// just ignore failing devices and keep enumerating
		path := "/dev/" + d.Name()
		go func() { check(addBlockDevice(path, nil)) }()

		// Probe all partitions of this block device, too:
		target := filepath.Join("/sys/block/", d.Name())
		parts, err := os.ReadDir(target)
		if err != nil {
			return err
		}
		for _, p := range parts {
			// partition name should start with the same prefix as the device itself
			if !strings.HasPrefix(p.Name(), d.Name()) {
				continue
			}
			partitionPath := "/dev/" + p.Name()
			addTableNameForDevice(partitionPath, path)
			go func() { check(addBlockDevice(partitionPath, nil)) }()
		}
	}
	return nil
}

func scanSysModaliases() error {
	return filepath.Walk("/sys/devices", walkSysModaliases)
}

func walkSysModaliases(path string, fi os.FileInfo, err error) error {
	if err != nil {
		if os.IsNotExist(err) {
			// /dev/sys has a number of ephemeral files (like 'waiting_for_supplier') that might be added/removed
			// from the fs underneath us. Workaround it, ignore any errors for files that we listed but later unable to read.
			return nil
		}
		return err
	}
	if fi.IsDir() {
		return nil
	}
	if fi.Name() != "modalias" {
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
	go func() { check(loadModalias(alias)) }()

	return nil
}

func boost() error {
	info("Starting booster initramfs")

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

	// Mount efivarfs if running in EFI mode
	if _, err := os.Stat("/sys/firmware/efi"); !errors.Is(err, os.ErrNotExist) {
		if err := mount("efivarfs", "/sys/firmware/efi/efivars", "efivarfs", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, ""); err != nil {
			return err
		}
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

	go func() { check(udevListener()) }()

	if _, err := loadModules(config.ModulesForceLoad...); err != nil {
		return err
	}

	if err := configureVirtualConsole(); err != nil {
		return err
	}

	go func() { check(scanSysModaliases()) }()
	go func() { check(scanSysBlock()) }()

	if config.MountTimeout != 0 {
		// TODO: cancellable, timeout context?
		timeout := waitTimeout(&rootMounted, time.Duration(config.MountTimeout)*time.Second)
		if timeout {
			return fmt.Errorf("Timeout waiting for root filesystem")
		}
	} else {
		// wait for mount forever
		rootMounted.Wait()
	}

	cleanup()
	loadingModulesWg.Wait() // wait till all modules done loading to kernel
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
		severe("read realtime clock: %v", err)
	}
	startMonotonic, err = readClock(unix.CLOCK_MONOTONIC)
	if err != nil {
		severe("read monotonic clock: %v", err)
	}
}

func emergencyShell() {
	if _, err := os.Stat("/usr/bin/busybox"); !os.IsNotExist(err) {
		if err := unix.Exec("/usr/bin/busybox", []string{"sh", "-I"}, nil); err != nil {
			severe("Unable to start an emergency shell: %v", err)
		}
	}
}

func reboot() {
	console("Press ENTER to reboot")
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
