package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Bluetooth keyboards are reconnected by init before any disk is unlocked,
// using the bonds BlueZ made when they were paired. BlueZ keeps its state
// under /var/lib/bluetooth:
//
//	<adapter>/<device>/info     the device's properties and bond keys
//	<adapter>/cache/<device>    the SDP records and GATT database it learned
//
// where <adapter> and <device> are upper-case addresses, and both files are
// in GLib's key file format.

const (
	uuidHIDClassic  = "00001124-0000-1000-8000-00805f9b34fb" // HID over BR/EDR
	uuidHIDOverGATT = "00001812-0000-1000-8000-00805f9b34fb" // HID over GATT

	appearanceKeyboard = 0x03c1
)

// bluetoothModules are what init's stack needs besides the controller driver.
// hidp loads only once a BR/EDR keyboard connects, and uhid once an LE one
// does, so a host that has not had a keyboard connect since it booted does
// not have them loaded and host mode would leave them out.
var bluetoothModules = []string{"bluetooth", "hidp", "uhid", "hid_generic"}

// bluetoothCryptoModules are the crypto algorithms the bluetooth module asks
// the crypto API for when a controller registers, ECDH for LE Secure
// Connections and, on older kernels, AES-CMAC for LE pairing. The kernel
// would have modprobe load them, and nothing in the initramfs answers that.
var bluetoothCryptoModules = []string{"ecdh_generic", "cmac"}

// activateBluetoothModules adds the modules init's Bluetooth stack needs and
// returns the ones to load at boot, which are not loaded by modalias.
func (k *Kmod) activateBluetoothModules() ([]string, error) {
	// the controller drivers; host mode keeps the ones the host has loaded
	if err := k.activateModules(true, false, "kernel/drivers/bluetooth/"); err != nil {
		return nil, err
	}
	if err := k.activateModules(false, false, bluetoothModules...); err != nil {
		return nil, err
	}
	for _, m := range bluetoothCryptoModules {
		if _, ok := k.nameToPathMapping.forward[m]; !ok {
			continue // built in, or not in this kernel
		}
		if err := k.activateModules(false, false, m); err != nil {
			return nil, err
		}
		// a dependency is loaded before the module, and the controller
		// driver cannot register a controller before bluetooth is loaded
		k.addExtraDep("bluetooth", m)
	}

	var forceLoad []string
	for _, m := range []string{"bluetooth", "hidp", "uhid"} {
		if k.requiredModules[m] {
			forceLoad = append(forceLoad, m)
		}
	}
	return forceLoad, nil
}

// bluetoothFirmwareLog matches the kernel log lines in which a Bluetooth
// driver names the firmware file it loaded. Most drivers also list their
// files in modinfo, which booster adds along with the module, but Intel's
// lists only a few early ones.
var bluetoothFirmwareLog = []*regexp.Regexp{
	regexp.MustCompile(`Bluetooth: hci\d+: Found device firmware: (\S+)`),      // Intel
	regexp.MustCompile(`Bluetooth: hci\d+: Found Intel DDC parameters: (\S+)`), // Intel
	regexp.MustCompile(`Bluetooth: hci\d+: RTL: loading (\S+)`),                // Realtek
	regexp.MustCompile(`Bluetooth: hci\d+: QCA Downloading (\S+)`),             // Qualcomm
	regexp.MustCompile(`Bluetooth: hci\d+: \S+ '(brcm/[^']+)' Patch`),          // Broadcom
}

// bluetoothFirmwareFromLog returns the firmware files the kernel log says
// the host's Bluetooth controllers loaded.
func bluetoothFirmwareFromLog(log []byte) []string {
	var fws []string
	for line := range bytes.Lines(log) {
		for _, re := range bluetoothFirmwareLog {
			m := re.FindSubmatch(line)
			if m == nil {
				continue
			}
			fw := string(m[1])
			if filepath.IsAbs(fw) || strings.Contains(fw, "..") || slices.Contains(fws, fw) {
				continue
			}
			fws = append(fws, fw)
		}
	}
	return fws
}

// appendBluetoothFirmware adds the firmware the host's controllers loaded
// beyond what their drivers list in modinfo. An Intel controller does not
// come up without its firmware.
func (img *Image) appendBluetoothFirmware(conf *generatorConfig) error {
	log, err := conf.readKernelLog()
	if err != nil {
		debug("bluetooth: reading the kernel log: %v", err)
	}
	fws := bluetoothFirmwareFromLog(log)
	debug("bluetooth: the kernel log names firmware %v", fws)
	if err := img.appendFirmwareFiles("bluetooth", fws); err != nil {
		return err
	}

	if slices.ContainsFunc(fws, func(fw string) bool { return strings.HasPrefix(fw, "intel/") }) ||
		!hostHasIntelBluetooth(conf.bluetoothSysfsDir) {
		return nil
	}
	// The log has rotated, or the controller came up before it was read:
	// which of Intel's files the controller needs depends on its hardware
	// revision, so add them all.
	files, err := filepath.Glob(filepath.Join(firmwareDir, "intel", "ibt-*"))
	if err != nil {
		return err
	}
	var size int64
	for _, f := range files {
		if err := img.AppendFile(f); err != nil {
			return err
		}
		if fi, err := os.Stat(f); err == nil {
			size += fi.Size()
		}
	}
	warning("enable_bluetooth: the kernel log does not say which firmware the Intel Bluetooth controller loaded, adding all %d intel/ibt-* files (%d KiB); rebuild the image after a reboot to add only the one it uses",
		len(files), size/1024)
	return nil
}

// hostBluetoothControllers returns the sysfs devices behind the host's
// Bluetooth controllers.
func hostBluetoothControllers(sysfsDir string) []string {
	entries, _ := os.ReadDir(sysfsDir)
	var devs []string
	for _, e := range entries {
		if strings.Contains(e.Name(), ":") {
			continue // hci0:12 and the like are connections, not controllers
		}
		if dev, err := filepath.EvalSymlinks(filepath.Join(sysfsDir, e.Name(), "device")); err == nil {
			devs = append(devs, dev)
		}
	}
	return devs
}

// hostHasIntelBluetooth reports whether one of the host's Bluetooth
// controllers is Intel's, by the USB or PCI vendor of the device behind it.
func hostHasIntelBluetooth(sysfsDir string) bool {
	for _, dev := range hostBluetoothControllers(sysfsDir) {
		// a USB controller's device is the interface, under the USB device
		for _, vendor := range []string{
			filepath.Join(dev, "..", "idVendor"),
			filepath.Join(dev, "vendor"),
		} {
			b, err := os.ReadFile(vendor)
			if err != nil {
				continue
			}
			switch strings.TrimSpace(string(b)) {
			case "8087", "0x8086":
				return true
			}
		}
	}
	return false
}

// readKernelLog returns the messages in the kernel's ring buffer. Reading it
// takes root when kernel.dmesg_restrict is set.
func readKernelLog() ([]byte, error) {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	var log bytes.Buffer
	buf := make([]byte, 8192) // a read returns one whole record, and fails if it does not fit
	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EAGAIN) {
			return log.Bytes(), nil
		} else if errors.Is(err, unix.EPIPE) {
			continue // the record was overwritten before we got to it
		} else if err != nil {
			return log.Bytes(), err
		}
		// "<prefix>;<message>\n" and then lines of " KEY=value" metadata
		rec := buf[:n]
		if i := bytes.IndexByte(rec, ';'); i >= 0 {
			rec = rec[i+1:]
		}
		if i := bytes.IndexByte(rec, '\n'); i >= 0 {
			rec = rec[:i+1]
		}
		log.Write(rec)
	}
}

// parseBluetoothAddress checks that s is a Bluetooth device address written
// the way BlueZ and bluetoothctl write it, six colon-separated hex octets, and
// returns it upper-cased, the form BlueZ names its state directories by.
func parseBluetoothAddress(s string) (string, error) {
	invalid := fmt.Errorf("%q is not a Bluetooth address like 00:1A:7D:DA:71:13", s)
	if len(s) != 17 {
		return "", invalid
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i%3 == 2 {
			if c != ':' {
				return "", invalid
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return "", invalid
		}
	}
	return strings.ToUpper(s), nil
}

// readBluetoothKeyboards returns the paired and trusted keyboards found under
// dir, narrowed to the addresses in allow when it is not empty. It returns nil
// when there is nothing to reconnect. BlueZ's state changes as devices are
// paired and removed, so a keyboard that is not there is a warning rather
// than a failed build: failing would also fail the kernel upgrade that
// triggered the build and leave an image that cannot boot the new kernel.
func readBluetoothKeyboards(dir string, allow []string) (*InitBluetoothConfig, error) {
	adapters, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		warning("enable_bluetooth: %s does not exist, nothing has been paired with BlueZ; the image is built without Bluetooth support", dir)
		return nil, nil
	} else if os.IsPermission(err) {
		warning("enable_bluetooth: %s is unreadable (%v) — re-run as root to include the paired Bluetooth keyboards; the image is built without Bluetooth support", dir, err)
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	included := make(set)
	leftOut := make(map[string]string) // address -> why, for the devices named in allow
	var conf InitBluetoothConfig
	for _, a := range adapters {
		adapterAddr, err := parseBluetoothAddress(a.Name())
		if err != nil || !a.IsDir() {
			continue
		}
		adapterDir := filepath.Join(dir, a.Name())
		devices, err := os.ReadDir(adapterDir)
		if err != nil {
			return nil, err
		}

		adapter := BluetoothAdapter{Address: adapterAddr}
		for _, d := range devices {
			addr, err := parseBluetoothAddress(d.Name())
			if err != nil || !d.IsDir() {
				continue // cache/, settings and the like
			}
			listed := slices.Contains(allow, addr)
			if len(allow) > 0 && !listed {
				continue
			}

			dev, reason, err := readBluetoothDevice(adapterDir, addr, listed)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", filepath.Join(adapterDir, addr), err)
			}
			if dev == nil {
				debug("bluetooth: leaving out %s: %s", addr, reason)
				leftOut[addr] = reason
				continue
			}

			transport := "BR/EDR"
			if dev.LE != nil {
				transport = "LE"
			}
			debug("bluetooth: adding keyboard %q (%s), bonded to %s over %s", dev.Name, addr, adapterAddr, transport)
			adapter.Devices = append(adapter.Devices, *dev)
			included[addr] = true
		}
		if len(adapter.Devices) > 0 {
			conf.Adapters = append(conf.Adapters, adapter)
		}
	}

	for _, addr := range allow {
		if included[addr] {
			continue
		}
		reason, seen := leftOut[addr]
		if !seen {
			reason = "BlueZ has not paired it"
		}
		warning("bluetooth_devices: %s is left out of the image: %s", addr, reason)
	}
	if len(conf.Adapters) == 0 {
		warning("enable_bluetooth: no paired and trusted Bluetooth keyboard found under %s; the image is built without Bluetooth support", dir)
		return nil, nil
	}
	return &conf, nil
}

// readBluetoothDevice reads the device BlueZ paired at adapterDir/addr. It
// returns nil and the reason when the device is not one to reconnect at boot:
// it must be paired, trusted, not blocked, offer HID, and be a keyboard unless
// the user named it in bluetooth_devices.
func readBluetoothDevice(adapterDir, addr string, listed bool) (*BluetoothDevice, string, error) {
	data, err := os.ReadFile(filepath.Join(adapterDir, addr, "info"))
	if os.IsNotExist(err) {
		return nil, "BlueZ has no info file for it", nil
	} else if err != nil {
		return nil, "", err
	}
	info := parseKeyFile(data)

	_, hasLinkKey := info["LinkKey"]
	hasLTK := leKeyGroup(info) != ""
	switch {
	case !hasLinkKey && !hasLTK:
		return nil, "it is not paired", nil
	case info.get("General", "Trusted") != "true":
		return nil, "it is not trusted", nil
	case info.get("General", "Blocked") == "true":
		return nil, "it is blocked", nil
	}

	services := strings.Split(strings.ToLower(info.get("General", "Services")), ";")
	class, _ := strconv.ParseUint(info.get("General", "Class"), 0, 32)
	appearance, _ := strconv.ParseUint(info.get("General", "Appearance"), 0, 16)
	// Class of Device: major class Peripheral with the keyboard bit of its minor class
	classKeyboard := (class>>8)&0x1f == 0x05 && class&0x40 != 0

	dev := &BluetoothDevice{
		Address: addr,
		Name:    info.get("General", "Alias"),
	}
	if dev.Name == "" {
		dev.Name = info.get("General", "Name")
	}
	dev.Vendor = keyFileUint16(info.get("DeviceID", "Vendor"))
	dev.Product = keyFileUint16(info.get("DeviceID", "Product"))
	dev.Version = keyFileUint16(info.get("DeviceID", "Version"))

	var keyboard bool
	var reason string
	switch {
	case hasLinkKey && (slices.Contains(services, uuidHIDClassic) || classKeyboard):
		keyboard = classKeyboard
		dev.Classic, reason = readClassicBond(info)
		if dev.Classic != nil {
			dev.Classic.SDPRecords, err = cachedSDPRecords(adapterDir, addr)
			if err != nil {
				return nil, "", err
			}
		}
	case hasLTK && (slices.Contains(services, uuidHIDOverGATT) || appearance == appearanceKeyboard):
		keyboard = appearance == appearanceKeyboard
		dev.LE, reason = readLEBond(info, addr)
	default:
		return nil, "it offers no HID service", nil
	}
	if reason != "" {
		return nil, reason, nil
	}
	if !keyboard && !listed {
		return nil, "it is not a keyboard; name it in bluetooth_devices to include it anyway", nil
	}
	return dev, "", nil
}

// readClassicBond reads the BR/EDR link key. It returns the reason instead
// when the key is unusable.
func readClassicBond(info keyFile) (*BluetoothClassic, string) {
	key, ok := bluezKey(info.get("LinkKey", "Key"))
	if !ok {
		return nil, "its link key is malformed"
	}
	keyType, err := strconv.ParseUint(info.get("LinkKey", "Type"), 10, 8)
	if err != nil || keyType > 0x08 {
		return nil, fmt.Sprintf("its link key has an unknown type %q", info.get("LinkKey", "Type"))
	}
	pinLength, _ := strconv.ParseUint(info.get("LinkKey", "PINLength"), 10, 8)
	return &BluetoothClassic{
		LinkKey:     key,
		LinkKeyType: uint8(keyType),
		PINLength:   uint8(pinLength),
	}, ""
}

// leKeyGroup returns the group BlueZ keeps a device's long term key in, or ""
// when it has none. [LongTermKey] is the key for when this host is central.
// An LE Secure Connections key is the same in both roles, and BlueZ files it
// as the peripheral's, under [PeripheralLongTermKey] or, before BlueZ renamed
// it, [SlaveLongTermKey].
func leKeyGroup(info keyFile) string {
	for _, group := range []string{"LongTermKey", "PeripheralLongTermKey", "SlaveLongTermKey"} {
		if _, ok := info[group]; ok {
			return group
		}
	}
	return ""
}

// readLEBond reads the long term key this host encrypts the link with as
// central, and the keyboard's identity resolving key. It returns the reason
// instead when the bond is unusable.
func readLEBond(info keyFile, addr string) (*BluetoothLE, string) {
	le := &BluetoothLE{AddressType: info.get("General", "AddressType")}
	switch le.AddressType {
	case "":
		le.AddressType = "public"
	case "public":
	case "static":
		// a static random address has the two most significant bits set; any
		// other random address is not an identity BlueZ can store a bond for
		if b, _ := strconv.ParseUint(addr[:2], 16, 8); b&0xc0 != 0xc0 {
			return nil, "its random address is not a static one"
		}
	default:
		return nil, fmt.Sprintf("its address type %q is unknown", le.AddressType)
	}

	group := leKeyGroup(info)
	var ok bool
	if le.LongTermKey, ok = bluezKey(info.get(group, "Key")); !ok {
		return nil, "its long term key is malformed"
	}
	// BlueZ's Authenticated= holds the mgmt key type: 0 and 1 for legacy
	// pairing, 2 and 3 for LE Secure Connections, 4 for a debug key
	authenticated, err := strconv.ParseUint(info.get(group, "Authenticated"), 10, 8)
	if err != nil || authenticated > 4 {
		return nil, fmt.Sprintf("its long term key has an unknown type %q", info.get(group, "Authenticated"))
	}
	if authenticated == 4 {
		return nil, "it is bonded with a debug key, which the kernel refuses to load"
	}
	if group != "LongTermKey" && authenticated < 2 {
		// legacy pairing gives each role a key of its own
		return nil, "it has only the key for when this host is the peripheral, not the central"
	}
	le.Authenticated = uint8(authenticated)
	encSize, err := strconv.ParseUint(info.get(group, "EncSize"), 10, 8)
	if err != nil || encSize < 7 || encSize > 16 {
		return nil, fmt.Sprintf("its long term key has an invalid size %q", info.get(group, "EncSize"))
	}
	le.EncSize = uint8(encSize)
	ediv, _ := strconv.ParseUint(info.get(group, "EDiv"), 10, 16)
	le.EDiv = uint16(ediv)
	if le.Rand, ok = bluezRand(info.get(group, "Rand")); !ok {
		return nil, "its long term key has a malformed Rand"
	}

	if irk := info.get("IdentityResolvingKey", "Key"); irk != "" {
		if le.IdentityResolvingKey, ok = bluezKey(irk); !ok {
			return nil, "its identity resolving key is malformed"
		}
	}
	return le, ""
}

// cachedSDPRecords returns the SDP records BlueZ cached for the device, in
// handle order. init creates the keyboard from the HID one, and asks the
// keyboard for it when the cache has none.
func cachedSDPRecords(adapterDir, addr string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(adapterDir, "cache", addr))
	if os.IsNotExist(err) {
		debug("bluetooth: BlueZ has no cache for %s, init will ask the keyboard for its HID record", addr)
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	records := parseKeyFile(data)["ServiceRecords"]
	handles := make([]string, 0, len(records))
	for h := range records {
		handles = append(handles, h)
	}
	slices.Sort(handles) // BlueZ writes the handles as fixed-width hex

	var result []string
	for _, h := range handles {
		rec := records[h]
		if _, err := hex.DecodeString(rec); err != nil || rec == "" {
			debug("bluetooth: ignoring malformed cached SDP record %s of %s", h, addr)
			continue
		}
		result = append(result, strings.ToUpper(rec))
	}
	return result, nil
}

// bluezKey checks a 128-bit key as BlueZ writes them, 32 hex digits, with
// the 0x that some older versions prefixed.
func bluezKey(s string) (string, bool) {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 32 {
		return "", false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", false
	}
	return strings.ToUpper(s), true
}

// bluezRand parses the Rand of a legacy long term key. BlueZ writes it in
// decimal; older versions wrote 0x and the little-endian bytes, which BlueZ
// still reads.
func bluezRand(s string) (uint64, bool) {
	if s == "" {
		return 0, true
	}
	if h, ok := strings.CutPrefix(s, "0x"); ok {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 8 {
			return 0, false
		}
		return binary.LittleEndian.Uint64(b), true
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

func keyFileUint16(s string) uint16 {
	v, _ := strconv.ParseUint(s, 10, 16)
	return uint16(v)
}

// keyFile is a file in GLib's key file format, the .ini dialect BlueZ keeps
// its state in, as group -> key -> value.
type keyFile map[string]map[string]string

func (kf keyFile) get(group, key string) string {
	return kf[group][key]
}

// parseKeyFile parses GLib's key file format. As in GLib, a key repeated in
// a group keeps its last value, and comments start with #.
func parseKeyFile(data []byte) keyFile {
	kf := make(keyFile)
	var group map[string]string
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || line[0] == '#':
		case line[0] == '[' && line[len(line)-1] == ']':
			name := line[1 : len(line)-1]
			if kf[name] == nil {
				kf[name] = make(map[string]string)
			}
			group = kf[name]
		case group != nil:
			if key, value, ok := strings.Cut(line, "="); ok {
				group[strings.TrimSpace(key)] = unescapeKeyFileValue(strings.TrimSpace(value))
			}
		}
	}
	return kf
}

// unescapeKeyFileValue undoes the escapes GLib writes into string values.
func unescapeKeyFileValue(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i == len(s)-1 {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 's':
			b.WriteByte(' ')
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		default:
			b.WriteByte(s[i]) // \\ and anything GLib would reject
		}
	}
	return b.String()
}
