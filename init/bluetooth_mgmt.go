package main

// bluetooth_mgmt.go speaks the kernel's Bluetooth management protocol, the
// interface bluetoothd configures controllers through: a raw HCI socket on
// the control channel that carries commands to the kernel and events from
// it. The protocol is documented in BlueZ's doc/mgmt-api.txt.

import (
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	mgmtIndexNone = 0xffff // commands that are not about one controller

	mgmtOpReadIndexList       = 0x0003
	mgmtOpReadInfo            = 0x0004
	mgmtOpSetPowered          = 0x0005
	mgmtOpSetBondable         = 0x0009
	mgmtOpSetSSP              = 0x000b
	mgmtOpSetLE               = 0x000d
	mgmtOpLoadLinkKeys        = 0x0012
	mgmtOpLoadLongTermKeys    = 0x0013
	mgmtOpPinCodeNegReply     = 0x0017
	mgmtOpUserConfirmNegReply = 0x001d
	mgmtOpUserPasskeyNegReply = 0x001f
	mgmtOpSetBREDR            = 0x002a
	mgmtOpSetSecureConn       = 0x002d
	mgmtOpLoadIRKs            = 0x0030
	mgmtOpAddDevice           = 0x0033

	mgmtEvCmdComplete        = 0x0001
	mgmtEvCmdStatus          = 0x0002
	mgmtEvIndexAdded         = 0x0004
	mgmtEvIndexRemoved       = 0x0005
	mgmtEvNewLinkKey         = 0x0009
	mgmtEvNewLongTermKey     = 0x000a
	mgmtEvDeviceConnected    = 0x000b
	mgmtEvDeviceDisconnected = 0x000c
	mgmtEvPinCodeRequest     = 0x000e
	mgmtEvUserConfirmRequest = 0x000f
	mgmtEvUserPasskeyRequest = 0x0010
	mgmtEvAuthFailed         = 0x0011

	mgmtSettingPowered    = 1 << 0
	mgmtSettingSSP        = 1 << 6
	mgmtSettingBREDR      = 1 << 7
	mgmtSettingLE         = 1 << 9
	mgmtSettingSecureConn = 1 << 11

	mgmtStatusRFKilled = 0x12

	// mgmt's address types, which tell BR/EDR from the two kinds of LE address
	mgmtAddrBREDR    = 0x00
	mgmtAddrLEPublic = 0x01
	mgmtAddrLERandom = 0x02

	// the ADD_DEVICE action that lets a BR/EDR device connect to the host
	mgmtActionAllowIncoming = 0x01

	mgmtCommandTimeout = 10 * time.Second
)

// mgmtError is the status a command failed with.
type mgmtError uint8

func (e mgmtError) Error() string {
	switch e {
	case 0x01:
		return "unknown command"
	case 0x03:
		return "failed"
	case 0x0a:
		return "busy"
	case 0x0b:
		return "rejected"
	case 0x0c:
		return "not supported"
	case 0x0d:
		return "invalid parameters"
	case 0x0f:
		return "not powered"
	case 0x11:
		return "invalid index"
	case mgmtStatusRFKilled:
		return "blocked by rfkill"
	case 0x14:
		return "permission denied"
	}
	return fmt.Sprintf("status 0x%02x", uint8(e))
}

// mgmtPacket is a command or an event: a 16-bit code, the controller it is
// about and the parameters.
type mgmtPacket struct {
	code  uint16
	index uint16
	data  []byte
}

// mgmtConn is a management socket. Commands go one at a time; their
// results and the events in between arrive on the same socket, read by
// readLoop.
type mgmtConn struct {
	f       *os.File
	cmdMu   sync.Mutex
	replies chan mgmtPacket // command complete and command status
	events  chan mgmtPacket // everything else; closed once the socket is
	closed  chan struct{}
	once    sync.Once
}

func openMgmt() (*mgmtConn, error) {
	fd, err := unix.Socket(unix.AF_BLUETOOTH, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.BTPROTO_HCI)
	if err != nil {
		return nil, fmt.Errorf("management socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrHCI{Dev: mgmtIndexNone, Channel: unix.HCI_CHANNEL_CONTROL}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("management socket: %v", err)
	}
	return newMgmtConn(os.NewFile(uintptr(fd), "bluetooth-mgmt")), nil
}

func newMgmtConn(f *os.File) *mgmtConn {
	c := &mgmtConn{
		f:       f,
		replies: make(chan mgmtPacket, 4),
		events:  make(chan mgmtPacket, 64),
		closed:  make(chan struct{}),
	}
	btGo(c.readLoop)
	return c
}

func (c *mgmtConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.f.Close()
}

func (c *mgmtConn) readLoop() {
	defer close(c.events)

	buf := make([]byte, 6+0xffff)
	for {
		n, err := c.f.Read(buf)
		if err != nil {
			return
		}
		if n < 6 {
			continue
		}
		p := mgmtPacket{
			code:  binary.LittleEndian.Uint16(buf[0:]),
			index: binary.LittleEndian.Uint16(buf[2:]),
		}
		size := int(binary.LittleEndian.Uint16(buf[4:]))
		if 6+size > n {
			continue
		}
		p.data = slices.Clone(buf[6 : 6+size])

		if p.code == mgmtEvCmdComplete || p.code == mgmtEvCmdStatus {
			select {
			case c.replies <- p:
			default: // the reply to a command that gave up waiting for it
			}
			continue
		}
		select {
		case c.events <- p:
		case <-c.closed:
			return
		}
	}
}

// command sends a command and waits for its result, returning the result's
// parameters.
func (c *mgmtConn) command(index, op uint16, params []byte) ([]byte, error) {
	return c.commandTimeout(index, op, params, mgmtCommandTimeout)
}

func (c *mgmtConn) commandTimeout(index, op uint16, params []byte, timeout time.Duration) ([]byte, error) {
	c.cmdMu.Lock()
	defer c.cmdMu.Unlock()

	pkt := make([]byte, 6, 6+len(params))
	binary.LittleEndian.PutUint16(pkt[0:], op)
	binary.LittleEndian.PutUint16(pkt[2:], index)
	binary.LittleEndian.PutUint16(pkt[4:], uint16(len(params)))
	pkt = append(pkt, params...)
	if _, err := c.f.Write(pkt); err != nil {
		return nil, err
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case p := <-c.replies:
			// opcode and status come first in both kinds of reply
			if len(p.data) < 3 || binary.LittleEndian.Uint16(p.data) != op || p.index != index {
				continue // the late reply to an earlier command
			}
			status := p.data[2]
			if status != 0 {
				return nil, mgmtError(status)
			}
			if p.code == mgmtEvCmdStatus {
				continue // accepted, and the result is still to come
			}
			return p.data[3:], nil
		case <-timer.C:
			return nil, fmt.Errorf("no reply in %v", timeout)
		case <-c.closed:
			return nil, os.ErrClosed
		}
	}
}

// mgmtAddr encodes struct mgmt_addr_info: the address and its type.
func mgmtAddr(addr bdaddr, addrType uint8) []byte {
	w := addr.wire()
	return append(w[:], addrType)
}

// mgmtControllerInfo is the part of READ_INFO's result booster uses.
type mgmtControllerInfo struct {
	address   bdaddr
	supported uint32 // settings the controller supports
	current   uint32 // settings in effect
}

func parseMgmtControllerInfo(b []byte) (mgmtControllerInfo, error) {
	// address(6) version(1) manufacturer(2) supported(4) current(4) class(3) name(249) short name(11)
	if len(b) < 17 {
		return mgmtControllerInfo{}, fmt.Errorf("controller information is %d bytes long", len(b))
	}
	return mgmtControllerInfo{
		address:   bdaddrFromWire(b[0:6]),
		supported: binary.LittleEndian.Uint32(b[9:]),
		current:   binary.LittleEndian.Uint32(b[13:]),
	}, nil
}

// mgmtLinkKeys encodes LOAD_LINK_KEYS' parameters.
func mgmtLinkKeys(keyboards []*btClassic) []byte {
	b := []byte{0} // do not keep debug keys
	b = binary.LittleEndian.AppendUint16(b, uint16(len(keyboards)))
	for _, k := range keyboards {
		b = append(b, mgmtAddr(k.addr, mgmtAddrBREDR)...)
		b = append(b, k.linkKeyType)
		b = append(b, k.linkKey[:]...)
		b = append(b, k.pinLength)
	}
	return b
}

// mgmtLongTermKeys encodes LOAD_LONG_TERM_KEYS' parameters.
func mgmtLongTermKeys(keyboards []*btLE) []byte {
	b := binary.LittleEndian.AppendUint16(nil, uint16(len(keyboards)))
	for _, k := range keyboards {
		b = append(b, mgmtAddr(k.addr, k.addrType)...)
		b = append(b, k.ltkType)
		b = append(b, 1) // used when this host initiates encryption, as central
		b = append(b, k.encSize)
		b = binary.LittleEndian.AppendUint16(b, k.ediv)
		b = binary.LittleEndian.AppendUint64(b, k.rand)
		b = append(b, k.ltk[:]...)
	}
	return b
}

// mgmtIRKs encodes LOAD_IRKS' parameters for the keyboards that have an
// identity resolving key.
func mgmtIRKs(keyboards []*btLE) []byte {
	var irks []byte
	count := 0
	for _, k := range keyboards {
		if k.irk == nil {
			continue
		}
		irks = append(irks, mgmtAddr(k.addr, k.addrType)...)
		irks = append(irks, k.irk[:]...)
		count++
	}
	return append(binary.LittleEndian.AppendUint16(nil, uint16(count)), irks...)
}
