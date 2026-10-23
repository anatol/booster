package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseBluetoothAddress(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in, want string
	}{
		{"00:1A:7D:DA:71:13", "00:1A:7D:DA:71:13"},
		{"00:1a:7d:da:71:13", "00:1A:7D:DA:71:13"},
	} {
		got, err := parseBluetoothAddress(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.want, got)
	}

	for _, in := range []string{
		"",
		"00:1A:7D:DA:71",
		"00:1A:7D:DA:71:13:00",
		"00-1A-7D-DA-71-13",
		"001A.7DDA.7113",
		"00:1A:7D:DA:71:1G",
		" 00:1A:7D:DA:71:13",
	} {
		_, err := parseBluetoothAddress(in)
		require.Error(t, err, "%q must be rejected", in)
	}
}

func TestParseKeyFile(t *testing.T) {
	t.Parallel()

	kf := parseKeyFile([]byte(`# written by BlueZ
[General]
Name=Example\sKeyboard\\x
 Alias = My keyboard
Trusted=false
Trusted=true

[LinkKey]
Key=D3F47A6E2E5BC1A5B6C4AD3E2D2F1A0B
ignored line without equals sign
`))
	require.Equal(t, `Example Keyboard\x`, kf.get("General", "Name"))
	require.Equal(t, "My keyboard", kf.get("General", "Alias"))
	require.Equal(t, "true", kf.get("General", "Trusted"))
	require.Equal(t, "D3F47A6E2E5BC1A5B6C4AD3E2D2F1A0B", kf.get("LinkKey", "Key"))
	require.Equal(t, "", kf.get("LongTermKey", "Key"))
	require.Len(t, kf["LinkKey"], 1)
}

func TestBluezRand(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"", 0, true},
		{"0", 0, true},
		{"14102912364589137713", 14102912364589137713, true},
		{"0x31ba7f9c1ac94bc3", 0xc34bc91a9c7fba31, true}, // little-endian bytes
		{"0x31ba7f9c", 0, false},
		{"-1", 0, false},
		{"12a", 0, false},
	} {
		got, ok := bluezRand(tc.in)
		require.Equal(t, tc.ok, ok, tc.in)
		require.Equal(t, tc.want, got, tc.in)
	}
}

const (
	testAdapter = "00:1A:7D:DA:71:13"

	classicKeyboard = "12:34:56:78:9A:BC"
	leKeyboard      = "F1:2A:3B:4C:5D:6E"
	classicMouse    = "2A:3B:4C:5D:6E:7F"
	scKeyboard      = "C2:23:34:45:56:67"
)

// writeBluezState lays out a /var/lib/bluetooth with a classic keyboard, an
// LE keyboard and devices that must be left out, each for one reason.
func writeBluezState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	write := func(path, content string) {
		path = filepath.Join(dir, path)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	write(testAdapter+"/settings", "[General]\nDiscoverable=false\n")

	write(testAdapter+"/"+classicKeyboard+"/info", `[General]
Name=Example Keyboard
Class=0x000540
SupportedTechnologies=BR/EDR;
Trusted=true
Blocked=false
WakeAllowed=true
Services=00001000-0000-1000-8000-00805f9b34fb;00001124-0000-1000-8000-00805f9b34fb;00001200-0000-1000-8000-00805f9b34fb;

[LinkKey]
Key=d3f47a6e2e5bc1a5b6c4ad3e2d2f1a0b
Type=4
PINLength=0

[DeviceID]
Source=2
Vendor=4660
Product=22136
Version=4865
`)
	write(testAdapter+"/cache/"+classicKeyboard, `[General]
Name=Example Keyboard

[ServiceRecords]
0x00010001=3601920900000A00010001
0x00010000=3601560900000A0001000009000135031911240900
0x00010002=not hex
`)

	write(testAdapter+"/"+leKeyboard+"/info", `[General]
Name=Example LE Keyboard
Alias=Desk keyboard
Appearance=0x03c1
AddressType=static
SupportedTechnologies=LE;
Trusted=true
Blocked=false
Services=00001800-0000-1000-8000-00805f9b34fb;0000180a-0000-1000-8000-00805f9b34fb;00001812-0000-1000-8000-00805f9b34fb;

[IdentityResolvingKey]
Key=8E1D2A9C4B3F5E6D7A8B9C0D1E2F3A4B

[LongTermKey]
Key=0123456789ABCDEF0123456789ABCDEF
Authenticated=0
EncSize=16
EDiv=40219
Rand=14102912364589137713

[PeripheralLongTermKey]
Key=FEDCBA9876543210FEDCBA9876543210
Authenticated=0
EncSize=16
EDiv=1
Rand=2

[DeviceID]
Source=2
Vendor=4660
Product=39612
Version=18
`)

	// LE Secure Connections: BlueZ files the one key, good in both roles, as
	// the peripheral's, under both of its names
	write(testAdapter+"/"+scKeyboard+"/info", `[General]
Name=Example SC Keyboard
Appearance=0x03c1
AddressType=static
SupportedTechnologies=LE;
Trusted=true
Blocked=false
Services=00001800-0000-1000-8000-00805f9b34fb;0000180f-0000-1000-8000-00805f9b34fb;00001812-0000-1000-8000-00805f9b34fb;

[IdentityResolvingKey]
Key=00112233445566778899AABBCCDDEEFF

[PeripheralLongTermKey]
Key=FFEEDDCCBBAA99887766554433221100
Authenticated=3
EncSize=16
EDiv=0
Rand=0

[SlaveLongTermKey]
Key=FFEEDDCCBBAA99887766554433221100
Authenticated=3
EncSize=16
EDiv=0
Rand=0
`)

	// HID, paired and trusted, but a mouse
	write(testAdapter+"/"+classicMouse+"/info", `[General]
Name=Example Mouse
Class=0x002580
Trusted=true
Services=00001124-0000-1000-8000-00805f9b34fb;

[LinkKey]
Key=00112233445566778899AABBCCDDEEFF
Type=5
PINLength=0
`)

	keyboard := func(general, keys string) string {
		return "[General]\nName=Keyboard\nClass=0x000540\nServices=00001124-0000-1000-8000-00805f9b34fb;\n" + general + "\n" + keys
	}
	linkKey := "[LinkKey]\nKey=00112233445566778899AABBCCDDEEFF\nType=4\nPINLength=0\n"
	write(testAdapter+"/11:11:11:11:11:11/info", keyboard("Trusted=false", linkKey))
	write(testAdapter+"/22:22:22:22:22:22/info", keyboard("Trusted=true\nBlocked=true", linkKey))
	write(testAdapter+"/33:33:33:33:33:33/info", keyboard("Trusted=true", ""))
	write(testAdapter+"/44:44:44:44:44:44/info", keyboard("Trusted=true", "[LinkKey]\nKey=0011\nType=4\n"))
	write(testAdapter+"/55:55:55:55:55:55/info", "[General]\nName=Headphones\nClass=0x240404\nTrusted=true\n"+
		"Services=0000110b-0000-1000-8000-00805f9b34fb;\n"+linkKey)
	write(testAdapter+"/C6:66:66:66:66:66/info", "[General]\nName=Debug\nAppearance=0x03c1\nAddressType=static\nTrusted=true\n"+
		"[LongTermKey]\nKey=0123456789ABCDEF0123456789ABCDEF\nAuthenticated=4\nEncSize=16\nEDiv=0\nRand=0\n")
	// legacy pairing, and only the key for when this host is the peripheral
	write(testAdapter+"/E6:66:66:66:66:66/info", "[General]\nName=Legacy\nAppearance=0x03c1\nAddressType=static\nTrusted=true\n"+
		"[PeripheralLongTermKey]\nKey=0123456789ABCDEF0123456789ABCDEF\nAuthenticated=0\nEncSize=16\nEDiv=1\nRand=2\n")
	write(testAdapter+"/77:77:77:77:77:77/info", "[General]\nName=Not static\nAppearance=0x03c1\nAddressType=static\nTrusted=true\n"+
		"[LongTermKey]\nKey=0123456789ABCDEF0123456789ABCDEF\nAuthenticated=2\nEncSize=16\nEDiv=0\nRand=0\n")

	// an adapter that has nothing to offer is left out entirely
	write("AA:BB:CC:DD:EE:FF/88:88:88:88:88:88/info", keyboard("Trusted=false", linkKey))

	return dir
}

var (
	wantClassicKeyboard = BluetoothDevice{
		Address: classicKeyboard,
		Name:    "Example Keyboard",
		Vendor:  4660,
		Product: 22136,
		Version: 4865,
		Classic: &BluetoothClassic{
			LinkKey:     "D3F47A6E2E5BC1A5B6C4AD3E2D2F1A0B",
			LinkKeyType: 4,
			SDPRecords: []string{
				"3601560900000A0001000009000135031911240900",
				"3601920900000A00010001",
			},
		},
	}
	wantSCKeyboard = BluetoothDevice{
		Address: scKeyboard,
		Name:    "Example SC Keyboard",
		LE: &BluetoothLE{
			AddressType:          "static",
			LongTermKey:          "FFEEDDCCBBAA99887766554433221100",
			Authenticated:        3,
			EncSize:              16,
			IdentityResolvingKey: "00112233445566778899AABBCCDDEEFF",
		},
	}
	wantLEKeyboard = BluetoothDevice{
		Address: leKeyboard,
		Name:    "Desk keyboard",
		Vendor:  4660,
		Product: 39612,
		Version: 18,
		LE: &BluetoothLE{
			AddressType:          "static",
			LongTermKey:          "0123456789ABCDEF0123456789ABCDEF",
			EncSize:              16,
			EDiv:                 40219,
			Rand:                 14102912364589137713,
			IdentityResolvingKey: "8E1D2A9C4B3F5E6D7A8B9C0D1E2F3A4B",
		},
	}
)

func TestReadBluetoothKeyboards(t *testing.T) {
	dir := writeBluezState(t)

	var conf *InitBluetoothConfig
	out := captureStdout(t, func() {
		var err error
		conf, err = readBluetoothKeyboards(dir, nil)
		require.NoError(t, err)
	})
	// only devices named in bluetooth_devices are worth a warning
	require.NotContains(t, out, "left out of the image")
	require.NotContains(t, out, "without Bluetooth support")

	require.Equal(t, &InitBluetoothConfig{Adapters: []BluetoothAdapter{{
		Address: testAdapter,
		Devices: []BluetoothDevice{wantClassicKeyboard, wantSCKeyboard, wantLEKeyboard},
	}}}, conf)
}

func TestReadBluetoothKeyboardsNamed(t *testing.T) {
	dir := writeBluezState(t)

	var conf *InitBluetoothConfig
	out := captureStdout(t, func() {
		var err error
		conf, err = readBluetoothKeyboards(dir, []string{
			classicMouse, leKeyboard, "11:11:11:11:11:11", "33:33:33:33:33:33",
			"44:44:44:44:44:44", "55:55:55:55:55:55", "C6:66:66:66:66:66",
			"77:77:77:77:77:77", "99:99:99:99:99:99", "E6:66:66:66:66:66",
		})
		require.NoError(t, err)
	})

	// naming a device includes it even when it is not a keyboard, and leaves
	// out the keyboards that were not named
	require.Len(t, conf.Adapters, 1)
	require.Len(t, conf.Adapters[0].Devices, 2)
	require.Equal(t, classicMouse, conf.Adapters[0].Devices[0].Address)
	require.Equal(t, wantLEKeyboard, conf.Adapters[0].Devices[1])

	for _, want := range []string{
		"11:11:11:11:11:11 is left out of the image: it is not trusted",
		"33:33:33:33:33:33 is left out of the image: it is not paired",
		"44:44:44:44:44:44 is left out of the image: its link key is malformed",
		"55:55:55:55:55:55 is left out of the image: it offers no HID service",
		"C6:66:66:66:66:66 is left out of the image: it is bonded with a debug key",
		"77:77:77:77:77:77 is left out of the image: its random address is not a static one",
		"99:99:99:99:99:99 is left out of the image: BlueZ has not paired it",
		"E6:66:66:66:66:66 is left out of the image: it has only the key for when this host is the peripheral",
	} {
		require.Contains(t, out, want)
	}
	require.NotContains(t, out, classicMouse+" is left out")
	require.NotContains(t, out, leKeyboard+" is left out")
}

func TestReadBluetoothKeyboardsWithoutState(t *testing.T) {
	var conf *InitBluetoothConfig
	out := captureStdout(t, func() {
		var err error
		conf, err = readBluetoothKeyboards(filepath.Join(t.TempDir(), "bluetooth"), nil)
		require.NoError(t, err)
	})
	require.Nil(t, conf)
	require.Contains(t, out, "the image is built without Bluetooth support")

	// paired devices but no keyboard among them
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, testAdapter, classicMouse), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, testAdapter, classicMouse, "info"),
		[]byte("[General]\nClass=0x002580\nTrusted=true\nServices=00001124-0000-1000-8000-00805f9b34fb;\n"+
			"[LinkKey]\nKey=00112233445566778899AABBCCDDEEFF\nType=4\n"), 0o600))
	out = captureStdout(t, func() {
		var err error
		conf, err = readBluetoothKeyboards(dir, nil)
		require.NoError(t, err)
	})
	require.Nil(t, conf)
	require.Contains(t, out, "no paired and trusted Bluetooth keyboard found")
}

func TestBluetoothImage(t *testing.T) {
	opts := options{
		bluetoothDir: writeBluezState(t),
		unpackImage:  true,
	}
	createTestInitRamfs(t, &opts)

	cfg := readGeneratedInitConfig(t, opts.workDir)
	require.Equal(t, &InitBluetoothConfig{Adapters: []BluetoothAdapter{{
		Address: testAdapter,
		Devices: []BluetoothDevice{wantClassicKeyboard, wantSCKeyboard, wantLEKeyboard},
	}}}, cfg.Bluetooth)

	// the bond keys must not be readable by anyone who can read /boot
	fi, err := os.Stat(opts.workDir + "/booster.img")
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestImageWithoutBluetoothStaysReadable(t *testing.T) {
	opts := options{
		bluetoothDir: t.TempDir(), // enabled, but nothing paired
		unpackImage:  true,
	}
	createTestInitRamfs(t, &opts)

	require.Nil(t, readGeneratedInitConfig(t, opts.workDir).Bluetooth)
	fi, err := os.Stat(opts.workDir + "/booster.img")
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fi.Mode().Perm())
}

func TestBluetoothModules(t *testing.T) {
	opts := options{
		bluetoothDir: writeBluezState(t),
		prepareModulesAt: []string{
			"kernel/net/bluetooth/bluetooth.ko",
			"kernel/net/bluetooth/hidp/hidp.ko",
			"kernel/drivers/hid/uhid.ko",
			"kernel/drivers/bluetooth/btusb.ko",
			"kernel/drivers/bluetooth/hci_vhci.ko",
			"kernel/crypto/ecdh_generic.ko",
		},
		// in host mode the driver of the host's controller is kept, and the
		// stack's own modules are added whether or not the host loaded them
		hostModules: []string{"btusb"},
		unpackImage: true,
	}
	createTestInitRamfs(t, &opts)

	checkDirListing(t, opts.workDir+"/image.unpacked/usr/lib/modules/",
		"bluetooth.ko", "hidp.ko", "uhid.ko", "btusb.ko", "ecdh_generic.ko", "booster.alias")
	cfg := readGeneratedInitConfig(t, opts.workDir)
	require.Equal(t, []string{"bluetooth", "hidp", "uhid"}, cfg.ModulesForceLoad)
	// SMP asks the crypto API for ECDH when a controller registers, which
	// cannot happen before bluetooth is loaded
	require.Contains(t, cfg.ModuleDependencies["bluetooth"], "ecdh_generic")
}

func TestBluetoothFirmwareFromLog(t *testing.T) {
	t.Parallel()

	log := `Bluetooth: Core ver 2.22
Bluetooth: hci0: Found device firmware: intel/ibt-0040-0041.sfi
Bluetooth: hci0: Boot Address: 0x100800
Bluetooth: hci0: Found Intel DDC parameters: intel/ibt-0040-0041.ddc
Bluetooth: hci1: RTL: loading rtl_bt/rtl8761bu_fw.bin
Bluetooth: hci1: RTL: loading rtl_bt/rtl8761bu_config.bin
Bluetooth: hci2: QCA Downloading qca/rampatch_00130302.bin
Bluetooth: hci3: BCM20702A1 'brcm/BCM20702A1-0a5c-21e8.hcd' Patch
Bluetooth: hci0: Found device firmware: intel/ibt-0040-0041.sfi
Bluetooth: hci4: RTL: loading ../../etc/shadow
Bluetooth: hci4: RTL: loading /etc/shadow
iwlwifi 0000:00:14.3: Found device firmware: iwlwifi-so-a0-gf-a0-89.ucode
`
	require.Equal(t, []string{
		"intel/ibt-0040-0041.sfi",
		"intel/ibt-0040-0041.ddc",
		"rtl_bt/rtl8761bu_fw.bin",
		"rtl_bt/rtl8761bu_config.bin",
		"qca/rampatch_00130302.bin",
		"brcm/BCM20702A1-0a5c-21e8.hcd",
	}, bluetoothFirmwareFromLog([]byte(log)))
	require.Nil(t, bluetoothFirmwareFromLog(nil))
}

func TestHostBluetoothControllers(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mkdir := func(p string) string {
		p = filepath.Join(root, p)
		require.NoError(t, os.MkdirAll(p, 0o755))
		return p
	}
	write := func(p, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(root, p), []byte(content), 0o644))
	}
	class := mkdir("class/bluetooth")
	// controller adds itself to the class, with device pointing at what it sits on
	addController := func(name, dev string) {
		hci := mkdir(filepath.Join(dev, "bluetooth", name))
		require.NoError(t, os.Symlink("../..", filepath.Join(hci, "device")))
		require.NoError(t, os.Symlink(hci, filepath.Join(class, name)))
	}

	require.Empty(t, hostBluetoothControllers(class))
	require.False(t, hostHasIntelBluetooth(class))

	// a Realtek controller on USB: the device is interface 1-2:1.0 of USB device 1-2
	mkdir("devices/usb1/1-2/1-2:1.0")
	write("devices/usb1/1-2/idVendor", "0bda\n")
	addController("hci0", "devices/usb1/1-2/1-2:1.0")
	require.NoError(t, os.Symlink(filepath.Join(class, "hci0"), filepath.Join(class, "hci0:256"))) // a connection
	require.Len(t, hostBluetoothControllers(class), 1)
	require.False(t, hostHasIntelBluetooth(class))

	// an Intel one on USB
	mkdir("devices/usb3/3-10/3-10:1.0")
	write("devices/usb3/3-10/idVendor", "8087\n")
	addController("hci1", "devices/usb3/3-10/3-10:1.0")
	require.True(t, hostHasIntelBluetooth(class))

	// an Intel one on PCIe
	require.NoError(t, os.Remove(filepath.Join(class, "hci1")))
	mkdir("devices/pci0000:00/0000:00:14.3")
	write("devices/pci0000:00/0000:00:14.3/vendor", "0x8086\n")
	addController("hci2", "devices/pci0000:00/0000:00:14.3")
	require.True(t, hostHasIntelBluetooth(class))
	require.Len(t, hostBluetoothControllers(class), 2)
}
