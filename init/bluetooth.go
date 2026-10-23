package main

// bluetooth.go reconnects the Bluetooth keyboards the generator found paired
// with BlueZ, so that a passphrase can be typed on one. BlueZ itself does not
// fit an initramfs, bluetoothd needs D-Bus, so this is a small stack of
// booster's own. The kernel does the protocol work, HCI, L2CAP, the pairing
// crypto and HID over BR/EDR. What is left is bluetoothd's part: configure
// the controller through the management interface (bluetooth_mgmt.go), and
// hand the keyboards to the HID subsystem, through the kernel's HIDP for a
// BR/EDR keyboard (bluetooth_hidp.go) and through uhid for an LE one, whose
// HID-over-GATT profile has no kernel driver (bluetooth_hogp.go).
//
// Nothing pairs here. The keyboards reconnect with the bonds BlueZ made, and
// a keyboard asking to pair is turned down: anyone could ask, and a new bond
// could not be stored anyway.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// btGo runs fn on a goroutine of its own. A panic in any goroutine takes
// PID 1 and with it the boot down, and the stack works on what devices send
// over the air; Bluetooth is one way to the passphrase prompt among others,
// so a bug here only ends the goroutine it hit, with a warning.
func btGo(fn func()) {
	go func() {
		defer btRecover()
		fn()
	}()
}

func btRecover() {
	if r := recover(); r != nil {
		stack := make([]byte, 4096)
		warning("bluetooth: internal error: %v\n%s", r, stack[:runtime.Stack(stack, false)])
	}
}

// bdaddr is a Bluetooth device address in the order it is written:
// 00:1A:7D:DA:71:13 is {0x00, 0x1a, 0x7d, 0xda, 0x71, 0x13}. On the wire and
// in the kernel's structures the bytes go the other way round.
type bdaddr [6]byte

func parseBdaddr(s string) (bdaddr, error) {
	var a bdaddr
	if len(s) != 17 {
		return a, fmt.Errorf("invalid Bluetooth address %q", s)
	}
	for i := range a {
		if i > 0 && s[i*3-1] != ':' {
			return a, fmt.Errorf("invalid Bluetooth address %q", s)
		}
		v, err := strconv.ParseUint(s[i*3:i*3+2], 16, 8)
		if err != nil {
			return a, fmt.Errorf("invalid Bluetooth address %q", s)
		}
		a[i] = byte(v)
	}
	return a, nil
}

func (a bdaddr) String() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", a[0], a[1], a[2], a[3], a[4], a[5])
}

// wire returns the address in the kernel's byte order.
func (a bdaddr) wire() (w [6]byte) {
	for i := range a {
		w[5-i] = a[i]
	}
	return w
}

func bdaddrFromWire(b []byte) (a bdaddr) {
	for i := range a {
		a[5-i] = b[i]
	}
	return a
}

// parseKey decodes a 128-bit key from the hex the generator copied from BlueZ.
func parseKey(s string) (k [16]byte, err error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(k) {
		return k, fmt.Errorf("invalid key")
	}
	copy(k[:], b)
	return k, nil
}

const (
	l2capPSMSDP          = 0x0001
	l2capPSMHIDControl   = 0x0011
	l2capPSMHIDInterrupt = 0x0013
	l2capCIDATT          = 0x0004

	// the security level a socket asks the kernel for, from <bluetooth/bluetooth.h>
	btSecurityOpt    = 4
	btSecurityLow    = 1 // no encryption, as SDP needs none
	btSecurityMedium = 2 // encrypted with the bond's key; nothing a keyboard sends is trusted without that
)

// l2capAddr is struct sockaddr_l2. x/sys/unix converts it with the address
// reversed one way and not the other, so booster does its own conversion.
type l2capAddr struct {
	psm      uint16
	cid      uint16
	addr     bdaddr
	addrType uint8 // BDADDR_BREDR, BDADDR_LE_PUBLIC or BDADDR_LE_RANDOM, the same values as mgmt's
}

func (a l2capAddr) raw() (rsa unix.RawSockaddrL2) {
	rsa.Family = unix.AF_BLUETOOTH
	binary.LittleEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa.Psm))[:], a.psm)
	rsa.Bdaddr = a.addr.wire()
	binary.LittleEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rsa.Cid))[:], a.cid)
	rsa.Bdaddr_type = a.addrType
	return rsa
}

func l2capAddrFromRaw(rsa *unix.RawSockaddrL2) l2capAddr {
	return l2capAddr{
		psm:      binary.LittleEndian.Uint16((*[2]byte)(unsafe.Pointer(&rsa.Psm))[:]),
		cid:      binary.LittleEndian.Uint16((*[2]byte)(unsafe.Pointer(&rsa.Cid))[:]),
		addr:     bdaddrFromWire(rsa.Bdaddr[:]),
		addrType: rsa.Bdaddr_type,
	}
}

// withFd runs fn with f's descriptor, which stays open while fn runs. Unlike
// f.Fd(), it leaves the descriptor non-blocking.
func withFd(f *os.File, fn func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var fnErr error
	if err := rc.Control(func(fd uintptr) { fnErr = fn(int(fd)) }); err != nil {
		return err
	}
	return fnErr
}

// l2capSocket returns a new L2CAP socket that asks for the given security
// level. It is non-blocking and known to the runtime poller, so a goroutine
// blocked on it returns once it is closed.
func l2capSocket(security uint8) (*os.File, error) {
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.BTPROTO_L2CAP)
	if err != nil {
		return nil, fmt.Errorf("L2CAP socket: %v", err)
	}
	// struct bt_security: the level, and a key size the kernel ignores here
	if err := unix.SetsockoptString(fd, unix.SOL_BLUETOOTH, btSecurityOpt, string([]byte{security, 0})); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("L2CAP security: %v", err)
	}
	return os.NewFile(uintptr(fd), "l2cap"), nil
}

func l2capBind(f *os.File, a l2capAddr) error {
	rsa := a.raw()
	return withFd(f, func(fd int) error {
		_, _, errno := unix.Syscall(unix.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&rsa)), unsafe.Sizeof(rsa))
		if errno != 0 {
			return errno
		}
		return nil
	})
}

func l2capListen(f *os.File) error {
	return withFd(f, func(fd int) error { return unix.Listen(fd, 4) })
}

// l2capConnect connects f to a and waits for the channel to be up, with the
// security f asked for in place. A zero timeout leaves it to the kernel to
// give up.
func l2capConnect(f *os.File, a l2capAddr, timeout time.Duration) error {
	rsa := a.raw()
	err := withFd(f, func(fd int) error {
		_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&rsa)), unsafe.Sizeof(rsa))
		if errno != 0 {
			return errno
		}
		return nil
	})
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EINPROGRESS) {
		return err
	}

	if timeout > 0 {
		if err := f.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		defer func() { _ = f.SetWriteDeadline(time.Time{}) }()
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var connErr error
	err = rc.Write(func(fd uintptr) bool {
		// called right away and then each time the socket changes state,
		// so check it is done before asking how it went
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		if n, err := unix.Poll(pfd, 0); err != nil || n == 0 {
			return false
		}
		v, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			connErr = err
		} else if v != 0 {
			connErr = unix.Errno(v)
		}
		return true
	})
	if err != nil {
		return err
	}
	return connErr
}

// l2capAccept waits for a connection on listening socket f and returns it
// with the address of the controller it came in on and of the peer.
func l2capAccept(f *os.File) (*os.File, l2capAddr, l2capAddr, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, l2capAddr{}, l2capAddr{}, err
	}
	var nfd int
	var peer unix.RawSockaddrL2
	var acceptErr error
	err = rc.Read(func(fd uintptr) bool {
		size := uint32(unsafe.Sizeof(peer))
		r, _, errno := unix.Syscall6(unix.SYS_ACCEPT4, fd, uintptr(unsafe.Pointer(&peer)), uintptr(unsafe.Pointer(&size)),
			unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0, 0)
		if errno == unix.EAGAIN {
			return false
		}
		nfd, acceptErr = int(r), nil
		if errno != 0 {
			acceptErr = errno
		}
		return true
	})
	if err != nil {
		return nil, l2capAddr{}, l2capAddr{}, err
	}
	if acceptErr != nil {
		return nil, l2capAddr{}, l2capAddr{}, acceptErr
	}

	var local unix.RawSockaddrL2
	size := uint32(unsafe.Sizeof(local))
	if _, _, errno := unix.Syscall(unix.SYS_GETSOCKNAME, uintptr(nfd), uintptr(unsafe.Pointer(&local)), uintptr(unsafe.Pointer(&size))); errno != 0 {
		_ = unix.Close(nfd)
		return nil, l2capAddr{}, l2capAddr{}, errno
	}
	return os.NewFile(uintptr(nfd), "l2cap"), l2capAddrFromRaw(&local), l2capAddrFromRaw(&peer), nil
}

// btClassic is a keyboard bonded over BR/EDR.
type btClassic struct {
	stack                    *btStack
	addr                     bdaddr
	name                     string
	vendor, product, version uint16
	linkKey                  [16]byte
	linkKeyType, pinLength   uint8

	mu        sync.Mutex
	record    *hidRecord // from BlueZ's cache or else from the keyboard, once it has connected
	ctrl      *os.File   // a control channel waiting for its interrupt channel
	connected bool
	changed   chan struct{} // closed and replaced whenever connected changes
}

// btLE is a keyboard bonded over LE.
type btLE struct {
	stack                    *btStack
	addr                     bdaddr
	addrType                 uint8
	name                     string
	vendor, product, version uint16
	ltk                      [16]byte
	ltkType, encSize         uint8
	ediv                     uint16
	rand                     uint64
	irk                      *[16]byte

	services []*hogpService // found on the first connection and reused for the others
}

func (k *btClassic) String() string { return keyboardName(k.name, k.addr) }
func (k *btLE) String() string      { return keyboardName(k.name, k.addr) }

func keyboardName(name string, addr bdaddr) string {
	if name == "" {
		return addr.String()
	}
	return fmt.Sprintf("%q (%s)", name, addr)
}

// btAdapter is a controller with the keyboards bonded to it.
type btAdapter struct {
	addr    bdaddr
	classic []*btClassic
	le      []*btLE
}

type btStack struct {
	adapters []*btAdapter
	classic  map[bdaddr]*btClassic

	mgmt *mgmtConn

	mu        sync.Mutex
	closed    bool
	done      chan struct{} // closed on shutdown
	claimed   map[uint16]bool
	powered   []uint16 // controllers this stack powered on, to power off again
	listening bool
	closers   map[io.Closer]bool // sockets and devices to close on shutdown
}

// newBtStack turns the generator's config into the stack's keyboards,
// leaving out, with a warning, any it cannot use. It returns nil when no
// keyboard is left.
func newBtStack(cfg *InitBluetoothConfig) *btStack {
	s := &btStack{
		classic: make(map[bdaddr]*btClassic),
		done:    make(chan struct{}),
		claimed: make(map[uint16]bool),
		closers: make(map[io.Closer]bool),
	}
	for _, a := range cfg.Adapters {
		addr, err := parseBdaddr(a.Address)
		if err != nil {
			warning("bluetooth: %v", err)
			continue
		}
		ad := &btAdapter{addr: addr}
		for _, d := range a.Devices {
			if err := s.addKeyboard(ad, d); err != nil {
				warning("bluetooth: leaving out keyboard %s: %v", d.Address, err)
			}
		}
		if len(ad.classic)+len(ad.le) > 0 {
			s.adapters = append(s.adapters, ad)
		}
	}
	if len(s.adapters) == 0 {
		return nil
	}
	return s
}

func (s *btStack) addKeyboard(ad *btAdapter, d BluetoothDevice) error {
	addr, err := parseBdaddr(d.Address)
	if err != nil {
		return err
	}
	switch {
	case d.Classic != nil:
		k := &btClassic{
			stack: s, addr: addr, name: d.Name,
			vendor: d.Vendor, product: d.Product, version: d.Version,
			linkKeyType: d.Classic.LinkKeyType, pinLength: d.Classic.PINLength,
			changed: make(chan struct{}),
		}
		if k.linkKey, err = parseKey(d.Classic.LinkKey); err != nil {
			return fmt.Errorf("link key: %v", err)
		}
		var records [][]byte
		for _, r := range d.Classic.SDPRecords {
			if b, err := hex.DecodeString(r); err == nil {
				records = append(records, b)
			}
		}
		if len(records) > 0 {
			if k.record, err = findHIDRecord(records); err != nil {
				debug("bluetooth: %s: the cached SDP records have no usable HID record: %v", k, err)
			}
		}
		ad.classic = append(ad.classic, k)
		s.classic[addr] = k
	case d.LE != nil:
		k := &btLE{
			stack: s, addr: addr, name: d.Name,
			vendor: d.Vendor, product: d.Product, version: d.Version,
			ltkType: d.LE.Authenticated, encSize: d.LE.EncSize, ediv: d.LE.EDiv, rand: d.LE.Rand,
		}
		switch d.LE.AddressType {
		case "public":
			k.addrType = mgmtAddrLEPublic
		case "static":
			k.addrType = mgmtAddrLERandom
		default:
			return fmt.Errorf("unknown address type %q", d.LE.AddressType)
		}
		if k.ltk, err = parseKey(d.LE.LongTermKey); err != nil {
			return fmt.Errorf("long term key: %v", err)
		}
		if d.LE.IdentityResolvingKey != "" {
			irk, err := parseKey(d.LE.IdentityResolvingKey)
			if err != nil {
				return fmt.Errorf("identity resolving key: %v", err)
			}
			k.irk = &irk
		}
		ad.le = append(ad.le, k)
	default:
		return fmt.Errorf("it has no bond")
	}
	return nil
}

var btGlobal struct {
	sync.Mutex
	stack    *btStack
	shutdown bool
}

// bluetoothRun brings up the controllers the keyboards in cfg are bonded to
// and keeps the keyboards connected until bluetoothShutdown. It returns once
// the stack is running; controllers that show up later are set up as they
// do. Intended to be invoked as a goroutine.
func bluetoothRun(cfg *InitBluetoothConfig) {
	defer btRecover()

	s := newBtStack(cfg)
	if s == nil {
		return
	}

	// hidp and uhid are only needed once a keyboard connects, but the
	// generator force-loads them anyway, so waiting costs nothing
	loadModules("bluetooth", "hidp", "uhid").Wait()

	m, err := openMgmt()
	if err != nil {
		warning("bluetooth: %v", err)
		return
	}
	btGlobal.Lock()
	if btGlobal.shutdown {
		btGlobal.Unlock()
		_ = m.Close()
		return
	}
	s.mgmt = m
	btGlobal.stack = s
	btGlobal.Unlock()

	btGo(s.eventLoop)

	// Listing the controllers is also what subscribes this socket to the
	// events about controllers coming and going.
	rsp, err := m.command(mgmtIndexNone, mgmtOpReadIndexList, nil)
	if err != nil {
		warning("bluetooth: listing controllers: %v", err)
		return
	}
	if len(rsp) < 2 {
		return
	}
	for i := 0; i < int(binary.LittleEndian.Uint16(rsp)) && 4+2*i <= len(rsp); i++ {
		index := binary.LittleEndian.Uint16(rsp[2+2*i:])
		btGo(func() { s.setUpController(index) })
	}
}

// bluetoothShutdown disconnects the keyboards and powers the controllers
// off, so that bluetoothd finds them as if nothing had used them. Safe to
// call when the stack was never started.
func bluetoothShutdown() {
	btGlobal.Lock()
	btGlobal.shutdown = true
	s := btGlobal.stack
	btGlobal.Unlock()

	if s != nil {
		s.close()
	}
}

func (s *btStack) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.done)
	closers := s.closers
	s.closers = nil
	powered := s.powered
	s.mu.Unlock()

	for c := range closers {
		_ = c.Close()
	}
	for _, k := range s.classic {
		k.disconnect()
	}
	for _, index := range powered {
		if _, err := s.mgmt.commandTimeout(index, mgmtOpSetPowered, []byte{0}, 2*time.Second); err != nil {
			debug("bluetooth: powering hci%d off: %v", index, err)
		}
	}
	_ = s.mgmt.Close()
}

func (s *btStack) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// track has c closed on shutdown, until the returned function is called.
// It closes c right away when the stack is already shut down.
func (s *btStack) track(c io.Closer) (untrack func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = c.Close()
		return func() {}
	}
	s.closers[c] = true
	return func() {
		s.mu.Lock()
		delete(s.closers, c)
		s.mu.Unlock()
	}
}

// sleep waits for d, or less when the stack shuts down meanwhile.
func (s *btStack) sleep(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-s.done:
	}
}

func (s *btStack) eventLoop() {
	for ev := range s.mgmt.events {
		s.handleEvent(ev)
	}
}

func (s *btStack) handleEvent(ev mgmtPacket) {
	switch ev.code {
	case mgmtEvIndexAdded:
		btGo(func() { s.setUpController(ev.index) })
	case mgmtEvIndexRemoved:
		info("bluetooth: hci%d is gone", ev.index)
		s.mu.Lock()
		delete(s.claimed, ev.index)
		s.mu.Unlock()
	case mgmtEvDeviceConnected:
		if len(ev.data) >= 7 {
			debug("bluetooth: hci%d: %s connected", ev.index, bdaddrFromWire(ev.data))
		}
	case mgmtEvDeviceDisconnected:
		if len(ev.data) >= 8 {
			addr := bdaddrFromWire(ev.data)
			debug("bluetooth: hci%d: %s disconnected, reason 0x%02x", ev.index, addr, ev.data[7])
			if k := s.classic[addr]; k != nil && ev.data[6] == mgmtAddrBREDR {
				k.setConnected(false)
			}
		}
	case mgmtEvPinCodeRequest, mgmtEvUserConfirmRequest, mgmtEvUserPasskeyRequest:
		if len(ev.data) < 7 {
			return
		}
		reply := map[uint16]uint16{
			mgmtEvPinCodeRequest:     mgmtOpPinCodeNegReply,
			mgmtEvUserConfirmRequest: mgmtOpUserConfirmNegReply,
			mgmtEvUserPasskeyRequest: mgmtOpUserPasskeyNegReply,
		}[ev.code]
		addr := bdaddrFromWire(ev.data)
		warning("bluetooth: %s asked to pair, which booster does not do; pair keyboards in the running system and rebuild the image", addr)
		btGo(func() {
			if _, err := s.mgmt.command(ev.index, reply, ev.data[:7]); err != nil {
				debug("bluetooth: turning down %s: %v", addr, err)
			}
		})
	case mgmtEvNewLinkKey, mgmtEvNewLongTermKey:
		// a store hint, then the key, which starts with the address
		if len(ev.data) >= 8 {
			warning("bluetooth: %s has a new key, which booster cannot store; if it does not reconnect later, pair it again and rebuild the image",
				bdaddrFromWire(ev.data[1:]))
		}
	case mgmtEvAuthFailed:
		if len(ev.data) >= 8 {
			warning("bluetooth: authenticating %s failed with status 0x%02x; if it was paired again after this image was built, rebuild the image",
				bdaddrFromWire(ev.data), ev.data[7])
		}
	}
}

// setUpController brings controller index up for the keyboards bonded to
// it and starts waiting for them.
func (s *btStack) setUpController(index uint16) {
	ad := s.configureController(index)
	if ad == nil {
		return
	}
	if len(ad.classic) > 0 {
		s.listenClassic()
	}
	for _, k := range ad.classic {
		if k.hostReconnects() {
			btGo(func() { k.reconnectLoop(ad.addr) })
		}
	}
	for _, k := range ad.le {
		btGo(func() { k.run(ad.addr) })
	}
}

// configureController configures controller index for the keyboards bonded
// to it, in the order bluetoothd does: settings, then keys, then power. It
// returns the controller's keyboards, or nil when it is not one to use.
func (s *btStack) configureController(index uint16) *btAdapter {
	s.mu.Lock()
	if s.closed || s.claimed[index] {
		s.mu.Unlock()
		return nil
	}
	s.claimed[index] = true
	s.mu.Unlock()

	rsp, err := s.mgmt.command(index, mgmtOpReadInfo, nil)
	if err != nil {
		warning("bluetooth: hci%d: %v", index, err)
		return nil
	}
	ctrl, err := parseMgmtControllerInfo(rsp)
	if err != nil {
		warning("bluetooth: hci%d: %v", index, err)
		return nil
	}
	var ad *btAdapter
	for _, a := range s.adapters {
		if a.addr == ctrl.address {
			ad = a
		}
	}
	if ad == nil {
		info("bluetooth: hci%d (%s) has no paired keyboard, leaving it alone", index, ctrl.address)
		return nil
	}

	set := func(op uint16, what string, v byte) {
		if _, err := s.mgmt.command(index, op, []byte{v}); err != nil {
			debug("bluetooth: hci%d: %s: %v", index, what, err)
		}
	}
	// keyboards reconnect with their bonds; pairing would make a new one
	set(mgmtOpSetBondable, "turning bonding off", 0)
	if len(ad.classic) > 0 && ctrl.supported&mgmtSettingBREDR != 0 {
		set(mgmtOpSetBREDR, "turning BR/EDR on", 1)
		set(mgmtOpSetSSP, "turning Secure Simple Pairing on", 1)
	}
	if len(ad.le) > 0 && ctrl.supported&mgmtSettingLE != 0 {
		set(mgmtOpSetLE, "turning LE on", 1)
	}
	if ctrl.supported&mgmtSettingSecureConn != 0 {
		set(mgmtOpSetSecureConn, "turning Secure Connections on", 1)
	}

	if len(ad.classic) > 0 {
		if _, err := s.mgmt.command(index, mgmtOpLoadLinkKeys, mgmtLinkKeys(ad.classic)); err != nil {
			warning("bluetooth: hci%d: loading link keys: %v", index, err)
		}
	}
	if len(ad.le) > 0 {
		if _, err := s.mgmt.command(index, mgmtOpLoadLongTermKeys, mgmtLongTermKeys(ad.le)); err != nil {
			warning("bluetooth: hci%d: loading long term keys: %v", index, err)
		}
		if _, err := s.mgmt.command(index, mgmtOpLoadIRKs, mgmtIRKs(ad.le)); err != nil {
			warning("bluetooth: hci%d: loading identity resolving keys: %v", index, err)
		}
	}

	// noted first, so that a shutdown while powering on still powers it off
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.powered = append(s.powered, index)
	s.mu.Unlock()
	if _, err := s.mgmt.command(index, mgmtOpSetPowered, []byte{1}); err != nil {
		if errors.Is(err, mgmtError(mgmtStatusRFKilled)) {
			warning("bluetooth: hci%d is blocked by rfkill, its keyboards cannot connect", index)
		} else {
			warning("bluetooth: hci%d: powering on: %v", index, err)
		}
		return nil
	}

	var names []string
	for _, k := range ad.classic {
		names = append(names, k.String())
	}
	for _, k := range ad.le {
		names = append(names, k.String())
	}
	info("bluetooth: hci%d (%s) is up, waiting for %s", index, ctrl.address, strings.Join(names, ", "))

	for _, k := range ad.classic {
		// The controller scans for the devices on this list, and accepts
		// connections from them and no one else.
		params := append(mgmtAddr(k.addr, mgmtAddrBREDR), mgmtActionAllowIncoming)
		if _, err := s.mgmt.command(index, mgmtOpAddDevice, params); err != nil {
			warning("bluetooth: hci%d: letting %s connect: %v", index, k, err)
		}
	}
	return ad
}
