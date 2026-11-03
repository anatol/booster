package main

// bluetooth_uhid.go creates HID devices from user space through /dev/uhid,
// for the LE keyboards, whose HID over GATT has no kernel driver. The
// kernel parses the report descriptor and makes an input device of it as it
// does for any HID device; booster feeds it the reports the keyboard sends
// and answers its requests. The events are the kernel's packed
// struct uhid_event, in host byte order.

import (
	"encoding/binary"
	"fmt"
	"os"
	"slices"

	"golang.org/x/sys/unix"
)

const (
	uhidDestroy        = 1
	uhidStart          = 2
	uhidStop           = 3
	uhidOpen           = 4
	uhidClose          = 5
	uhidOutput         = 6
	uhidGetReport      = 9
	uhidGetReportReply = 10
	uhidCreate2        = 11
	uhidInput2         = 12
	uhidSetReport      = 13
	uhidSetReportReply = 14

	// the report types in uhid's requests
	uhidFeatureReport = 0
	uhidOutputReport  = 1
	uhidInputReport   = 2

	uhidDataMax   = 4096          // UHID_DATA_MAX, and HID_MAX_DESCRIPTOR_SIZE too
	uhidEventSize = 4 + 4372      // struct uhid_event, as large as its uhid_create2_req
	uhidCreate2At = 4 + 128 + 128 // where rd_size is, past name, phys and uniq

	busBluetooth = 0x05
)

// uhidDevice is a HID device created through /dev/uhid. Closing it destroys
// the device.
type uhidDevice struct {
	f *os.File
}

type uhidDeviceInfo struct {
	name, phys, uniq         string
	descriptor               []byte
	vendor, product, version uint32
	country                  uint32
}

// openUHID is uhidCreate, indirected through a var so tests can stand a
// socket in for /dev/uhid.
var openUHID = uhidCreate

func uhidCreate(d uhidDeviceInfo) (*uhidDevice, error) {
	ev, err := uhidCreate2Event(d)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/dev/uhid", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	dev := &uhidDevice{f: os.NewFile(uintptr(fd), "uhid")}
	if _, err := dev.f.Write(ev); err != nil {
		_ = dev.f.Close()
		return nil, err
	}
	return dev, nil
}

// uhidCreate2Event encodes the CREATE2 event, up to the end of the
// descriptor: uhid zeroes what is not written.
func uhidCreate2Event(d uhidDeviceInfo) ([]byte, error) {
	if len(d.descriptor) == 0 || len(d.descriptor) > uhidDataMax {
		return nil, fmt.Errorf("report descriptor is %d bytes long", len(d.descriptor))
	}
	ev := make([]byte, uhidCreate2At+20+len(d.descriptor))
	ne := binary.NativeEndian
	ne.PutUint32(ev, uhidCreate2)
	copy(ev[4:4+127], d.name)
	copy(ev[4+128:4+128+63], d.phys)
	copy(ev[4+192:4+192+63], d.uniq)
	ne.PutUint16(ev[uhidCreate2At:], uint16(len(d.descriptor)))
	ne.PutUint16(ev[uhidCreate2At+2:], busBluetooth)
	ne.PutUint32(ev[uhidCreate2At+4:], d.vendor)
	ne.PutUint32(ev[uhidCreate2At+8:], d.product)
	ne.PutUint32(ev[uhidCreate2At+12:], d.version)
	ne.PutUint32(ev[uhidCreate2At+16:], d.country)
	copy(ev[uhidCreate2At+20:], d.descriptor)
	return ev, nil
}

func (d *uhidDevice) Close() error {
	return d.f.Close()
}

// input passes a report from the keyboard to the kernel.
func (d *uhidDevice) input(report []byte) error {
	ev := make([]byte, 6, 6+len(report))
	binary.NativeEndian.PutUint32(ev, uhidInput2)
	binary.NativeEndian.PutUint16(ev[4:], uint16(len(report)))
	_, err := d.f.Write(append(ev, report...))
	return err
}

// uhidEvent is a request from the kernel.
type uhidEvent struct {
	typ   uint32
	id    uint32 // of a GET_REPORT or SET_REPORT, which its reply repeats
	rnum  uint8  // the report number a GET_REPORT or SET_REPORT is for
	rtype uint8
	data  []byte
}

func (d *uhidDevice) readEvent() (uhidEvent, error) {
	buf := make([]byte, uhidEventSize)
	n, err := d.f.Read(buf)
	if err != nil {
		return uhidEvent{}, err
	}
	return parseUHIDEvent(buf[:n])
}

func parseUHIDEvent(b []byte) (uhidEvent, error) {
	ne := binary.NativeEndian
	if len(b) < 4 {
		return uhidEvent{}, fmt.Errorf("uhid event is %d bytes long", len(b))
	}
	ev := uhidEvent{typ: ne.Uint32(b)}
	b = b[4:]
	switch ev.typ {
	case uhidOutput:
		// struct uhid_output_req: data, size, rtype
		if len(b) < uhidDataMax+3 {
			return uhidEvent{}, fmt.Errorf("uhid output event is truncated")
		}
		size := int(ne.Uint16(b[uhidDataMax:]))
		if size > uhidDataMax {
			return uhidEvent{}, fmt.Errorf("uhid output event is malformed")
		}
		ev.data = slices.Clone(b[:size])
		ev.rtype = b[uhidDataMax+2]
	case uhidGetReport:
		// struct uhid_get_report_req: id, rnum, rtype
		if len(b) < 6 {
			return uhidEvent{}, fmt.Errorf("uhid get report event is truncated")
		}
		ev.id, ev.rnum, ev.rtype = ne.Uint32(b), b[4], b[5]
	case uhidSetReport:
		// struct uhid_set_report_req: id, rnum, rtype, size, data
		if len(b) < 8 {
			return uhidEvent{}, fmt.Errorf("uhid set report event is truncated")
		}
		ev.id, ev.rnum, ev.rtype = ne.Uint32(b), b[4], b[5]
		size := int(ne.Uint16(b[6:]))
		if 8+size > len(b) {
			return uhidEvent{}, fmt.Errorf("uhid set report event is malformed")
		}
		ev.data = slices.Clone(b[8 : 8+size])
	}
	return ev, nil
}

// getReportReply answers a GET_REPORT, with the report or with an errno.
func (d *uhidDevice) getReportReply(id uint32, errno unix.Errno, report []byte) error {
	ev := make([]byte, 12, 12+len(report))
	ne := binary.NativeEndian
	ne.PutUint32(ev, uhidGetReportReply)
	ne.PutUint32(ev[4:], id)
	ne.PutUint16(ev[8:], uint16(errno))
	ne.PutUint16(ev[10:], uint16(len(report)))
	_, err := d.f.Write(append(ev, report...))
	return err
}

// setReportReply answers a SET_REPORT.
func (d *uhidDevice) setReportReply(id uint32, errno unix.Errno) error {
	ev := make([]byte, 10)
	ne := binary.NativeEndian
	ne.PutUint32(ev, uhidSetReportReply)
	ne.PutUint32(ev[4:], id)
	ne.PutUint16(ev[8:], uint16(errno))
	_, err := d.f.Write(ev)
	return err
}
