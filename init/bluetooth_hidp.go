package main

// bluetooth_hidp.go connects BR/EDR keyboards. A BR/EDR HID device opens
// two L2CAP channels to the host, control first and then interrupt, and the
// kernel's HIDP takes both over once it is given the report descriptor from
// the device's HID record. HIDP then creates the input device. This is how
// bluetoothd's input plugin does it too.

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// hidpConnaddReq is struct hidp_connadd_req from the kernel's
// net/bluetooth/hidp/hidp.h.
type hidpConnaddReq struct {
	ctrlSock int32
	intrSock int32
	parser   uint16
	rdSize   uint16
	rdData   *byte
	country  uint8
	subclass uint8
	vendor   uint16
	product  uint16
	version  uint16
	flags    uint32
	idleTo   uint32
	name     [128]byte
}

// hidpConndelReq is struct hidp_conndel_req.
type hidpConndelReq struct {
	bdaddr [6]byte
	flags  uint32 // never HIDP_VIRTUAL_CABLE_UNPLUG, which would have the keyboard forget its bond
}

const (
	hidpConnAdd = 0x400448c8 // _IOW('H', 200, int)
	hidpConnDel = 0x400448c9 // _IOW('H', 201, int)

	hidpChannelTimeout    = 10 * time.Second // for the interrupt channel to follow the control one
	hidpConnectTimeout    = 15 * time.Second
	hidpReconnectInterval = 5 * time.Second
)

// hidpRequest is hidpIoctl, indirected through a var so tests can stub the
// kernel's HIDP.
var hidpRequest = hidpIoctl

func hidpIoctl(req uintptr, arg unsafe.Pointer) error {
	sock, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.BTPROTO_HIDP)
	if err != nil {
		return fmt.Errorf("HIDP socket: %v", err)
	}
	defer unix.Close(sock)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// listenClassic listens for the channels BR/EDR keyboards open to this
// host, on any controller.
func (s *btStack) listenClassic() {
	s.mu.Lock()
	if s.listening || s.closed {
		s.mu.Unlock()
		return
	}
	s.listening = true
	s.mu.Unlock()

	for _, psm := range []uint16{l2capPSMHIDControl, l2capPSMHIDInterrupt} {
		// The kernel encrypts the link with the bond's key before it lets
		// a connection through, and pairing anew is turned down, so a
		// device that does not have the key cannot open a channel, whatever
		// address it claims.
		f, err := l2capSocket(btSecurityMedium)
		if err != nil {
			warning("bluetooth: listening for keyboards: %v", err)
			return
		}
		if err := l2capBind(f, l2capAddr{psm: psm}); err != nil {
			_ = f.Close()
			warning("bluetooth: listening on PSM %d: %v", psm, err)
			return
		}
		if err := l2capListen(f); err != nil {
			_ = f.Close()
			warning("bluetooth: listening on PSM %d: %v", psm, err)
			return
		}
		s.track(f)
		btGo(func() { s.acceptClassic(f, psm) })
	}
}

func (s *btStack) acceptClassic(l *os.File, psm uint16) {
	for {
		ch, local, peer, err := l2capAccept(l)
		if err != nil {
			if s.isClosed() || errors.Is(err, os.ErrClosed) {
				return
			}
			warning("bluetooth: accepting on PSM %d: %v", psm, err)
			s.sleep(time.Second)
			continue
		}
		k := s.classic[peer.addr]
		if k == nil || peer.addrType != mgmtAddrBREDR {
			info("bluetooth: turning down a connection from %s, which is not a paired keyboard", peer.addr)
			_ = ch.Close()
			continue
		}
		k.channelUp(psm, ch, local.addr)
	}
}

// channelUp takes a channel the keyboard opened. The session starts once
// the interrupt channel follows the control channel.
func (k *btClassic) channelUp(psm uint16, ch *os.File, local bdaddr) {
	k.mu.Lock()
	if psm == l2capPSMHIDControl {
		if k.ctrl != nil {
			_ = k.ctrl.Close() // the keyboard gave up on that one
		}
		k.ctrl = ch
		k.mu.Unlock()
		time.AfterFunc(hidpChannelTimeout, func() {
			k.mu.Lock()
			defer k.mu.Unlock()
			if k.ctrl == ch {
				debug("bluetooth: %s opened no interrupt channel", k)
				k.ctrl = nil
				_ = ch.Close()
			}
		})
		return
	}
	ctrl := k.ctrl
	k.ctrl = nil
	k.mu.Unlock()

	if ctrl == nil {
		debug("bluetooth: %s opened an interrupt channel without a control channel", k)
		_ = ch.Close()
		return
	}
	btGo(func() {
		if err := k.startSession(local, ctrl, ch); err != nil {
			warning("bluetooth: %s: %v", k, err)
		}
	})
}

// startSession hands the keyboard's two channels to HIDP.
func (k *btClassic) startSession(local bdaddr, ctrl, intr *os.File) error {
	// HIDP takes its own references to the sockets
	defer ctrl.Close()
	defer intr.Close()

	k.mu.Lock()
	rec := k.record
	k.mu.Unlock()
	if rec == nil {
		debug("bluetooth: %s: no cached HID record, asking the keyboard for it", k)
		var err error
		if rec, err = querySDPHIDRecord(local, k.addr, k.stack.track); err != nil {
			return fmt.Errorf("reading its HID record: %v", err)
		}
		k.mu.Lock()
		k.record = rec
		k.mu.Unlock()
	}

	req := hidpConnaddReq{
		parser:   rec.parserVersion,
		rdSize:   uint16(len(rec.descriptor)),
		rdData:   &rec.descriptor[0],
		country:  rec.country,
		subclass: rec.subclass,
		vendor:   k.vendor,
		product:  k.product,
		version:  k.version,
	}
	name := k.name
	if name == "" {
		name = rec.name
	}
	copy(req.name[:len(req.name)-1], name)
	err := withFd(ctrl, func(c int) error {
		return withFd(intr, func(i int) error {
			req.ctrlSock, req.intrSock = int32(c), int32(i)
			return hidpRequest(hidpConnAdd, unsafe.Pointer(&req))
		})
	})
	runtime.KeepAlive(rec.descriptor)
	if errors.Is(err, unix.EEXIST) {
		debug("bluetooth: %s is connected already", k)
		return nil
	} else if err != nil {
		return fmt.Errorf("creating the keyboard: %v", err)
	}

	k.setConnected(true)
	info("bluetooth: %s connected", k)
	return nil
}

func (k *btClassic) setConnected(connected bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.connected == connected {
		return
	}
	k.connected = connected
	close(k.changed)
	k.changed = make(chan struct{})
	if !connected {
		info("bluetooth: %s disconnected", k)
	}
}

// hostReconnects reports whether the keyboard's HID record says it waits
// for the host to connect to it instead of connecting itself.
func (k *btClassic) hostReconnects() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.record != nil && !k.record.reconnectInitiate && k.record.normallyConnectable
}

// reconnectLoop keeps connecting to a keyboard that waits for the host to.
func (k *btClassic) reconnectLoop(local bdaddr) {
	for {
		k.mu.Lock()
		connected, changed := k.connected, k.changed
		k.mu.Unlock()
		if connected {
			select {
			case <-changed:
				continue
			case <-k.stack.done:
				return
			}
		}
		if k.stack.isClosed() {
			return
		}
		if err := k.connect(local); err != nil {
			debug("bluetooth: connecting to %s: %v", k, err)
			k.stack.sleep(hidpReconnectInterval)
		}
	}
}

func (k *btClassic) connect(local bdaddr) error {
	open := func(psm uint16) (*os.File, error) {
		f, err := l2capSocket(btSecurityMedium)
		if err != nil {
			return nil, err
		}
		defer k.stack.track(f)()
		if err := l2capBind(f, l2capAddr{addr: local}); err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := l2capConnect(f, l2capAddr{psm: psm, addr: k.addr}, hidpConnectTimeout); err != nil {
			_ = f.Close()
			return nil, err
		}
		return f, nil
	}
	ctrl, err := open(l2capPSMHIDControl)
	if err != nil {
		return err
	}
	intr, err := open(l2capPSMHIDInterrupt)
	if err != nil {
		_ = ctrl.Close()
		return err
	}
	if err := k.startSession(local, ctrl, intr); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.connected {
		return fmt.Errorf("the session did not start")
	}
	return nil
}

// disconnect ends the keyboard's HIDP session, on shutdown.
func (k *btClassic) disconnect() {
	k.mu.Lock()
	connected := k.connected
	if k.ctrl != nil {
		_ = k.ctrl.Close()
		k.ctrl = nil
	}
	k.mu.Unlock()
	if !connected {
		return
	}
	req := hidpConndelReq{bdaddr: k.addr.wire()}
	if err := hidpRequest(hidpConnDel, unsafe.Pointer(&req)); err != nil && !errors.Is(err, unix.ENOENT) {
		debug("bluetooth: disconnecting %s: %v", k, err)
	}
}
