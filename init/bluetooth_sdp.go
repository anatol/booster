package main

// bluetooth_sdp.go reads a BR/EDR keyboard's HID record: from the SDP
// records BlueZ cached when the keyboard was paired, or, when there are
// none, from the keyboard's own SDP server. The record carries the report
// descriptor HIDP needs to create the keyboard. SDP is big-endian
// throughout, unlike the rest of Bluetooth.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// the types of SDP data elements
const (
	sdpNil      = 0
	sdpUint     = 1
	sdpInt      = 2
	sdpUUID     = 3
	sdpText     = 4
	sdpBool     = 5
	sdpSequence = 6
	sdpAlt      = 7
	sdpURL      = 8
)

// the attributes of a HID record booster uses
const (
	sdpAttrServiceClassIDList     = 0x0001
	sdpAttrServiceName            = 0x0100 // at the primary language base
	sdpAttrHIDParserVersion       = 0x0201
	sdpAttrHIDDeviceSubclass      = 0x0202
	sdpAttrHIDCountryCode         = 0x0203
	sdpAttrHIDReconnectInitiate   = 0x0205
	sdpAttrHIDDescriptorList      = 0x0206
	sdpAttrHIDNormallyConnectable = 0x020d

	sdpUUIDHID = 0x1124 // the HID service class

	hidDescriptorTypeReport = 0x22
)

// sdpElement is an SDP data element: a value, or for a sequence or an
// alternative, the elements in it.
type sdpElement struct {
	kind  uint8
	value []byte
	items []sdpElement
}

// parseSDPElement parses the data element at the start of b and returns it
// with what follows it.
func parseSDPElement(b []byte) (sdpElement, []byte, error) {
	return parseSDPElementDepth(b, 0)
}

func parseSDPElementDepth(b []byte, depth int) (sdpElement, []byte, error) {
	if depth > 16 {
		return sdpElement{}, nil, fmt.Errorf("SDP data nested too deep")
	}
	if len(b) < 1 {
		return sdpElement{}, nil, fmt.Errorf("SDP data truncated")
	}
	e := sdpElement{kind: b[0] >> 3}
	sizeIndex := b[0] & 7
	b = b[1:]

	var size int
	switch {
	case e.kind == sdpNil:
		size = 0
	case sizeIndex <= 4:
		size = 1 << sizeIndex
	default:
		n := 1 << (sizeIndex - 5) // the size follows in 1, 2 or 4 bytes
		if len(b) < n {
			return sdpElement{}, nil, fmt.Errorf("SDP data truncated")
		}
		for _, c := range b[:n] {
			size = size<<8 | int(c)
		}
		b = b[n:]
	}
	if size > len(b) {
		return sdpElement{}, nil, fmt.Errorf("SDP data truncated")
	}
	e.value, b = b[:size], b[size:]

	if e.kind == sdpSequence || e.kind == sdpAlt {
		for rest := e.value; len(rest) > 0; {
			var item sdpElement
			var err error
			item, rest, err = parseSDPElementDepth(rest, depth+1)
			if err != nil {
				return sdpElement{}, nil, err
			}
			e.items = append(e.items, item)
		}
	}
	return e, b, nil
}

// uint returns the value of an unsigned integer or boolean element.
func (e sdpElement) uint() (uint64, bool) {
	if (e.kind != sdpUint && e.kind != sdpBool) || len(e.value) == 0 || len(e.value) > 8 {
		return 0, false
	}
	var v uint64
	for _, c := range e.value {
		v = v<<8 | uint64(c)
	}
	return v, true
}

// isUUID16 reports whether e is the 16-bit UUID v, in any of the three
// sizes a UUID can be written in.
func (e sdpElement) isUUID16(v uint16) bool {
	if e.kind != sdpUUID {
		return false
	}
	switch len(e.value) {
	case 2:
		return binary.BigEndian.Uint16(e.value) == v
	case 4:
		return binary.BigEndian.Uint32(e.value) == uint32(v)
	case 16:
		// 0000xxxx-0000-1000-8000-00805F9B34FB
		base := []byte{0, 0, 0, 0, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb}
		binary.BigEndian.PutUint16(base[2:], v)
		return bytes.Equal(e.value, base)
	}
	return false
}

// hidRecord is what booster needs from a HID record.
type hidRecord struct {
	name                string
	parserVersion       uint16
	subclass            uint8
	country             uint8
	reconnectInitiate   bool // the keyboard reconnects to the host
	normallyConnectable bool // the keyboard can be connected to while idle
	descriptor          []byte
}

// sdpRecordAttributes parses an SDP record, a sequence of attribute ID and
// value pairs.
func sdpRecordAttributes(rec sdpElement) (map[uint16]sdpElement, error) {
	if rec.kind != sdpSequence || len(rec.items)%2 != 0 {
		return nil, fmt.Errorf("SDP record is not a sequence of attributes")
	}
	attrs := make(map[uint16]sdpElement)
	for i := 0; i < len(rec.items); i += 2 {
		id, ok := rec.items[i].uint()
		if !ok || id > 0xffff {
			return nil, fmt.Errorf("SDP record has an invalid attribute ID")
		}
		attrs[uint16(id)] = rec.items[i+1]
	}
	return attrs, nil
}

// parseHIDRecord returns the HID attributes of an SDP record, or nil when
// the record is not a HID one.
func parseHIDRecord(rec sdpElement) (*hidRecord, error) {
	attrs, err := sdpRecordAttributes(rec)
	if err != nil {
		return nil, err
	}
	isHID := false
	for _, class := range attrs[sdpAttrServiceClassIDList].items {
		isHID = isHID || class.isUUID16(sdpUUIDHID)
	}
	if !isHID {
		return nil, nil
	}

	r := &hidRecord{parserVersion: 0x0100}
	if e, ok := attrs[sdpAttrServiceName]; ok && e.kind == sdpText {
		r.name = string(bytes.TrimRight(e.value, "\x00"))
	}
	if v, ok := attrs[sdpAttrHIDParserVersion].uint(); ok {
		r.parserVersion = uint16(v)
	}
	if v, ok := attrs[sdpAttrHIDDeviceSubclass].uint(); ok {
		r.subclass = uint8(v)
	}
	if v, ok := attrs[sdpAttrHIDCountryCode].uint(); ok {
		r.country = uint8(v)
	}
	if v, ok := attrs[sdpAttrHIDReconnectInitiate].uint(); ok {
		r.reconnectInitiate = v != 0
	}
	if v, ok := attrs[sdpAttrHIDNormallyConnectable].uint(); ok {
		r.normallyConnectable = v != 0
	}
	// a sequence of (descriptor type, descriptor) sequences
	for _, d := range attrs[sdpAttrHIDDescriptorList].items {
		if len(d.items) < 2 {
			continue
		}
		if t, ok := d.items[0].uint(); ok && t == hidDescriptorTypeReport && d.items[1].kind == sdpText {
			r.descriptor = d.items[1].value
			break
		}
	}
	if len(r.descriptor) == 0 {
		return nil, fmt.Errorf("HID record has no report descriptor")
	}
	return r, nil
}

// findHIDRecord returns the HID record among raw SDP records.
func findHIDRecord(records [][]byte) (*hidRecord, error) {
	var firstErr error
	for _, raw := range records {
		rec, _, err := parseSDPElement(raw)
		if err == nil {
			var r *hidRecord
			if r, err = parseHIDRecord(rec); r != nil {
				return r, nil
			}
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("no HID record")
}

const (
	sdpErrorRsp                  = 0x01
	sdpServiceSearchAttributeReq = 0x06
	sdpServiceSearchAttributeRsp = 0x07

	sdpQueryTimeout      = 10 * time.Second
	sdpMaxContinuations  = 64
	sdpMaxAttributeBytes = 0xffff // the most a response may carry before it continues in the next
)

// querySDPHIDRecord asks the keyboard at remote for its HID record, over
// the BR/EDR link the keyboard has up to the controller at local. track
// registers the socket to be closed if booster shuts the stack down
// meanwhile.
func querySDPHIDRecord(local, remote bdaddr, track func(io.Closer) func()) (*hidRecord, error) {
	f, err := l2capSocket(btSecurityLow)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	defer track(f)()
	if err := l2capBind(f, l2capAddr{addr: local}); err != nil {
		return nil, err
	}
	if err := l2capConnect(f, l2capAddr{psm: l2capPSMSDP, addr: remote}, sdpQueryTimeout); err != nil {
		return nil, fmt.Errorf("connecting to its SDP server: %v", err)
	}
	return sdpQueryHIDRecord(f)
}

// sdpQueryHIDRecord asks the SDP server at the other end of f for its HID
// record, with a ServiceSearchAttribute transaction.
func sdpQueryHIDRecord(f *os.File) (*hidRecord, error) {
	if err := f.SetDeadline(time.Now().Add(sdpQueryTimeout)); err != nil {
		return nil, err
	}

	var lists []byte
	continuation := []byte{0}
	buf := make([]byte, 0xffff)
	for tid := uint16(1); ; tid++ {
		if tid > sdpMaxContinuations {
			return nil, fmt.Errorf("SDP response does not end")
		}
		params := []byte{
			0x35, 0x03, 0x19, sdpUUIDHID >> 8, sdpUUIDHID & 0xff, // a sequence of the one UUID
			sdpMaxAttributeBytes >> 8, sdpMaxAttributeBytes & 0xff,
			0x35, 0x05, 0x0a, 0x00, 0x00, 0xff, 0xff, // every attribute, a range as a 32-bit integer
		}
		params = append(params, continuation...)
		req := []byte{sdpServiceSearchAttributeReq}
		req = binary.BigEndian.AppendUint16(req, tid)
		req = binary.BigEndian.AppendUint16(req, uint16(len(params)))
		req = append(req, params...)
		if _, err := f.Write(req); err != nil {
			return nil, err
		}

		n, err := f.Read(buf)
		if err != nil {
			return nil, err
		}
		rsp := buf[:n]
		if len(rsp) < 5 || binary.BigEndian.Uint16(rsp[1:]) != tid {
			return nil, fmt.Errorf("malformed SDP response")
		}
		if rsp[0] == sdpErrorRsp {
			return nil, fmt.Errorf("SDP server returned an error")
		}
		// attribute lists byte count, attribute lists, continuation state
		body := rsp[5:]
		if rsp[0] != sdpServiceSearchAttributeRsp || len(body) < 2 {
			return nil, fmt.Errorf("malformed SDP response")
		}
		count := int(binary.BigEndian.Uint16(body))
		if 2+count+1 > len(body) {
			return nil, fmt.Errorf("malformed SDP response")
		}
		lists = append(lists, body[2:2+count]...)
		continuation = body[2+count:]
		if len(continuation) != 1+int(continuation[0]) {
			return nil, fmt.Errorf("malformed SDP continuation state")
		}
		if continuation[0] == 0 {
			break
		}
		continuation = bytes.Clone(continuation)
	}

	// a sequence of the matching records
	all, _, err := parseSDPElement(lists)
	if err != nil {
		return nil, err
	}
	for _, rec := range all.items {
		if r, err := parseHIDRecord(rec); r != nil || err != nil {
			return r, err
		}
	}
	return nil, errors.New("it has no HID record")
}
