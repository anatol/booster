package main

// bluetooth_hogp.go connects LE keyboards. An LE keyboard speaks HID over
// GATT, HOGP: its reports are characteristics of a HID service, the input
// ones sent as notifications, and its report descriptor is one more
// characteristic, the report map. The kernel has no HOGP driver, so this is
// a small GATT client over the kernel's ATT channel. It creates each HID
// service's device through uhid and passes reports between the two, the way
// bluetoothd's hog plugin does.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	attOpError           = 0x01
	attOpMTUReq          = 0x02
	attOpMTURsp          = 0x03
	attOpFindInfoReq     = 0x04
	attOpFindInfoRsp     = 0x05
	attOpFindByTypeReq   = 0x06
	attOpFindByTypeRsp   = 0x07
	attOpReadByTypeReq   = 0x08
	attOpReadByTypeRsp   = 0x09
	attOpReadReq         = 0x0a
	attOpReadRsp         = 0x0b
	attOpReadBlobReq     = 0x0c
	attOpReadBlobRsp     = 0x0d
	attOpReadMultReq     = 0x0e
	attOpReadMultRsp     = 0x0f
	attOpReadByGroupReq  = 0x10
	attOpReadByGroupRsp  = 0x11
	attOpWriteReq        = 0x12
	attOpWriteRsp        = 0x13
	attOpPrepareWriteReq = 0x16
	attOpPrepareWriteRsp = 0x17
	attOpExecWriteReq    = 0x18
	attOpExecWriteRsp    = 0x19
	attOpNotify          = 0x1b
	attOpIndicate        = 0x1d
	attOpConfirm         = 0x1e
	attOpReadMultVarReq  = 0x20
	attOpReadMultVarRsp  = 0x21
	attOpWriteCmd        = 0x52

	attErrInvalidHandle       = 0x01
	attErrRequestNotSupported = 0x06
	attErrInvalidOffset       = 0x07
	attErrAttributeNotFound   = 0x0a
	attErrAttributeNotLong    = 0x0b

	attDefaultMTU = 23
	attMaxMTU     = 517              // the largest an ATT MTU can be
	attTimeout    = 30 * time.Second // ATT's transaction timeout

	gattPrimaryService   = 0x2800
	gattCharacteristic   = 0x2803
	gattClientCharConfig = 0x2902
	gattReportReference  = 0x2908

	gattServiceHID        = 0x1812
	gattServiceDeviceInfo = 0x180a

	gattCharPnPID          = 0x2a50
	gattCharHIDInformation = 0x2a4a
	gattCharReportMap      = 0x2a4b
	gattCharReport         = 0x2a4d
	gattCharProtocolMode   = 0x2a4e

	gattPropWriteNoRsp = 0x04
	gattPropWrite      = 0x08

	// the report types of a report reference
	hogpReportInput   = 1
	hogpReportOutput  = 2
	hogpReportFeature = 3

	hogpProtocolModeReport = 1

	hogpOpenTimeout = time.Second // for the HID device to be taken up, which takes milliseconds
)

var errNoHIDService = errors.New("it offers no HID service")

type attError struct {
	op     uint8
	handle uint16
	code   uint8
}

func (e attError) Error() string {
	return fmt.Sprintf("ATT error 0x%02x to request 0x%02x on handle 0x%04x", e.code, e.op, e.handle)
}

func isATTError(err error, code uint8) bool {
	var e attError
	return errors.As(err, &e) && e.code == code
}

// attConn is an ATT bearer to a keyboard. Requests go one at a time, as ATT
// requires; their responses, the keyboard's notifications and the keyboard's
// own requests arrive on the same socket, read by readLoop.
type attConn struct {
	f     *os.File
	mtu   atomic.Int32
	wmu   sync.Mutex
	reqMu sync.Mutex
	rsp   chan []byte
	done  chan struct{} // closed when the bearer is gone, with err telling why
	err   error

	nmu     sync.Mutex
	notify  func(handle uint16, value []byte)
	pending [][]byte // handle and value of each notification from before notify was set
}

func newATTConn(f *os.File) *attConn {
	c := &attConn{
		f:    f,
		rsp:  make(chan []byte, 1),
		done: make(chan struct{}),
	}
	c.mtu.Store(attDefaultMTU)
	btGo(c.readLoop)
	return c
}

func (c *attConn) Close() error {
	return c.f.Close()
}

func (c *attConn) write(pdu []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.f.Write(pdu)
	return err
}

func (c *attConn) readLoop() {
	buf := make([]byte, attMaxMTU)
	for {
		n, err := c.f.Read(buf)
		if err != nil {
			c.err = err
			close(c.done)
			return
		}
		if n == 0 {
			continue
		}
		pdu := slices.Clone(buf[:n])
		switch pdu[0] {
		case attOpNotify, attOpIndicate:
			if len(pdu) >= 3 {
				c.handleValue(binary.LittleEndian.Uint16(pdu[1:]), pdu[3:])
			}
			if pdu[0] == attOpIndicate {
				_ = c.write([]byte{attOpConfirm})
			}
		case attOpError, attOpMTURsp, attOpFindInfoRsp, attOpFindByTypeRsp, attOpReadByTypeRsp, attOpReadRsp,
			attOpReadBlobRsp, attOpReadMultRsp, attOpReadByGroupRsp, attOpWriteRsp, attOpPrepareWriteRsp,
			attOpExecWriteRsp, attOpReadMultVarRsp:
			select {
			case c.rsp <- pdu:
			default: // nothing asked for it
			}
		case attOpMTUReq, attOpFindInfoReq, attOpFindByTypeReq, attOpReadByTypeReq, attOpReadReq, attOpReadBlobReq,
			attOpReadMultReq, attOpReadByGroupReq, attOpWriteReq, attOpPrepareWriteReq, attOpExecWriteReq,
			attOpReadMultVarReq:
			c.serve(pdu)
		default:
			// commands, which take no response, and what this client does not know
		}
	}
}

// serve answers a request the keyboard makes of this host's GATT server,
// which is empty: there is no bluetoothd here to fill it.
func (c *attConn) serve(req []byte) {
	var handle uint16
	if len(req) >= 3 {
		handle = binary.LittleEndian.Uint16(req[1:])
	}
	code := byte(attErrRequestNotSupported)
	switch req[0] {
	case attOpMTUReq:
		if len(req) >= 3 {
			c.mtu.Store(int32(max(attDefaultMTU, min(attMaxMTU, int(handle)))))
		}
		_ = c.write(binary.LittleEndian.AppendUint16([]byte{attOpMTURsp}, attMaxMTU))
		return
	case attOpFindInfoReq, attOpFindByTypeReq, attOpReadByTypeReq, attOpReadByGroupReq:
		code = attErrAttributeNotFound // the start of the range
	case attOpReadReq, attOpReadBlobReq, attOpWriteReq, attOpPrepareWriteReq:
		code = attErrInvalidHandle
	default:
		handle = 0
	}
	rsp := []byte{attOpError, req[0]}
	rsp = binary.LittleEndian.AppendUint16(rsp, handle)
	_ = c.write(append(rsp, code))
}

func (c *attConn) handleValue(handle uint16, value []byte) {
	c.nmu.Lock()
	defer c.nmu.Unlock()
	if c.notify == nil {
		// A bonded keyboard remembers which notifications it was asked
		// for, and may send the key press that woke it before the HID
		// device is up. Keep it for then.
		if len(c.pending) < 64 {
			c.pending = append(c.pending, append(binary.LittleEndian.AppendUint16(nil, handle), value...))
		}
		return
	}
	c.notify(handle, value)
}

// setNotify sets where the keyboard's notifications go, starting with those
// that arrived before.
func (c *attConn) setNotify(fn func(handle uint16, value []byte)) {
	c.nmu.Lock()
	defer c.nmu.Unlock()
	c.notify = fn
	for _, p := range c.pending {
		fn(binary.LittleEndian.Uint16(p), p[2:])
	}
	c.pending = nil
}

// request sends a request and returns the parameters of its response.
func (c *attConn) request(req []byte, rspOp uint8) ([]byte, error) {
	c.reqMu.Lock()
	defer c.reqMu.Unlock()

	if err := c.write(req); err != nil {
		return nil, err
	}
	t := time.NewTimer(attTimeout)
	defer t.Stop()
	select {
	case rsp := <-c.rsp:
		if rsp[0] == attOpError {
			if len(rsp) < 5 {
				return nil, fmt.Errorf("malformed ATT error response")
			}
			return nil, attError{op: rsp[1], handle: binary.LittleEndian.Uint16(rsp[2:]), code: rsp[4]}
		}
		if rsp[0] != rspOp {
			return nil, fmt.Errorf("ATT response 0x%02x to request 0x%02x", rsp[0], req[0])
		}
		return rsp[1:], nil
	case <-t.C:
		// ATT allows nothing more on a bearer once a request timed out
		_ = c.Close()
		return nil, fmt.Errorf("ATT request 0x%02x timed out", req[0])
	case <-c.done:
		return nil, c.err
	}
}

func attPDU(op uint8, handles ...uint16) []byte {
	pdu := []byte{op}
	for _, h := range handles {
		pdu = binary.LittleEndian.AppendUint16(pdu, h)
	}
	return pdu
}

func (c *attConn) exchangeMTU() {
	rsp, err := c.request(attPDU(attOpMTUReq, attMaxMTU), attOpMTURsp)
	if err != nil || len(rsp) < 2 {
		debug("bluetooth: exchanging the ATT MTU: %v", err)
		return
	}
	c.mtu.Store(int32(max(attDefaultMTU, min(attMaxMTU, int(binary.LittleEndian.Uint16(rsp))))))
}

// attUUID16 returns the 16-bit UUID of an ATT UUID, which is 16 bits long or
// a 128-bit one that may be the Bluetooth base UUID with 16 bits in it. It
// returns 0 for any other 128-bit UUID.
func attUUID16(b []byte) uint16 {
	switch len(b) {
	case 2:
		return binary.LittleEndian.Uint16(b)
	case 16:
		// 0000xxxx-0000-1000-8000-00805F9B34FB, little-endian
		base := []byte{0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00}
		if bytes.Equal(b[:12], base) && b[14] == 0 && b[15] == 0 {
			return binary.LittleEndian.Uint16(b[12:])
		}
	}
	return 0
}

type gattService struct {
	start, end uint16
	uuid       uint16
}

type gattChar struct {
	decl, value uint16
	end         uint16 // the last handle of its descriptors
	props       uint8
	uuid        uint16
}

type gattDescriptor struct {
	handle uint16
	uuid   uint16
}

// readRange runs a Read By Type or Read By Group Type over start..end,
// continuing past the last handle each response gets to, and returns the
// entries. Each entry starts with its handle; the group type responses'
// entries continue with the group's end.
func (c *attConn) readRange(op, rspOp uint8, start, end, uuid uint16, groups bool) ([][]byte, error) {
	var entries [][]byte
	for start <= end && start != 0 {
		rsp, err := c.request(attPDU(op, start, end, uuid), rspOp)
		if isATTError(err, attErrAttributeNotFound) {
			break
		} else if err != nil {
			return nil, err
		}
		if len(rsp) < 1 || rsp[0] < 4 || (len(rsp)-1)%int(rsp[0]) != 0 || len(rsp) == 1 {
			return nil, fmt.Errorf("malformed ATT response")
		}
		size := int(rsp[0])
		var last uint16
		for e := rsp[1:]; len(e) > 0; e = e[size:] {
			entries = append(entries, e[:size])
			last = binary.LittleEndian.Uint16(e)
			if groups {
				last = binary.LittleEndian.Uint16(e[2:])
			}
		}
		if last < start || last == 0xffff {
			break
		}
		start = last + 1
	}
	return entries, nil
}

func (c *attConn) primaryServices() ([]gattService, error) {
	entries, err := c.readRange(attOpReadByGroupReq, attOpReadByGroupRsp, 0x0001, 0xffff, gattPrimaryService, true)
	if err != nil {
		return nil, err
	}
	var services []gattService
	for _, e := range entries {
		if len(e) < 6 {
			return nil, fmt.Errorf("malformed service declaration")
		}
		services = append(services, gattService{
			start: binary.LittleEndian.Uint16(e),
			end:   binary.LittleEndian.Uint16(e[2:]),
			uuid:  attUUID16(e[4:]),
		})
	}
	return services, nil
}

func (c *attConn) characteristics(svc gattService) ([]gattChar, error) {
	entries, err := c.readRange(attOpReadByTypeReq, attOpReadByTypeRsp, svc.start, svc.end, gattCharacteristic, false)
	if err != nil {
		return nil, err
	}
	var chars []gattChar
	for _, e := range entries {
		// handle, then the declaration: properties, value handle, UUID
		if len(e) < 7 {
			return nil, fmt.Errorf("malformed characteristic declaration")
		}
		chars = append(chars, gattChar{
			decl:  binary.LittleEndian.Uint16(e),
			props: e[2],
			value: binary.LittleEndian.Uint16(e[3:]),
			uuid:  attUUID16(e[5:]),
		})
	}
	// a characteristic's descriptors run up to the next declaration
	for i := range chars {
		chars[i].end = svc.end
		if i+1 < len(chars) {
			chars[i].end = chars[i+1].decl - 1
		}
	}
	return chars, nil
}

func (c *attConn) descriptors(ch gattChar) ([]gattDescriptor, error) {
	var descs []gattDescriptor
	for start := ch.value + 1; start <= ch.end && start != 0; {
		rsp, err := c.request(attPDU(attOpFindInfoReq, start, ch.end), attOpFindInfoRsp)
		if isATTError(err, attErrAttributeNotFound) {
			break
		} else if err != nil {
			return nil, err
		}
		size := 0
		if len(rsp) > 0 && rsp[0] == 1 {
			size = 4 // handles with 16-bit UUIDs
		} else if len(rsp) > 0 && rsp[0] == 2 {
			size = 18 // with 128-bit ones
		}
		if size == 0 || len(rsp) == 1 || (len(rsp)-1)%size != 0 {
			return nil, fmt.Errorf("malformed ATT response")
		}
		var last uint16
		for e := rsp[1:]; len(e) > 0; e = e[size:] {
			last = binary.LittleEndian.Uint16(e)
			descs = append(descs, gattDescriptor{handle: last, uuid: attUUID16(e[2:size])})
		}
		if last < start || last == 0xffff {
			break
		}
		start = last + 1
	}
	return descs, nil
}

func (c *attConn) read(handle uint16) ([]byte, error) {
	return c.request(attPDU(attOpReadReq, handle), attOpReadRsp)
}

// readLong reads a value that may not fit in one response.
func (c *attConn) readLong(handle uint16) ([]byte, error) {
	value, err := c.read(handle)
	if err != nil {
		return nil, err
	}
	for part := value; len(part) == int(c.mtu.Load())-1 && len(value) < uhidDataMax; {
		part, err = c.request(attPDU(attOpReadBlobReq, handle, uint16(len(value))), attOpReadBlobRsp)
		if isATTError(err, attErrAttributeNotLong) || isATTError(err, attErrInvalidOffset) {
			break // it ended right at the end of the last part
		} else if err != nil {
			return nil, err
		}
		value = append(value, part...)
	}
	return value, nil
}

func (c *attConn) writeRequest(handle uint16, value []byte) error {
	_, err := c.request(append(attPDU(attOpWriteReq, handle), value...), attOpWriteRsp)
	return err
}

func (c *attConn) writeCommand(handle uint16, value []byte) error {
	return c.write(append(attPDU(attOpWriteCmd, handle), value...))
}

// hogpService is a HID service of a keyboard. A keyboard can have more than
// one, each a HID device of its own.
type hogpService struct {
	reportMap         []byte
	numbered          bool // the report map has report IDs, so uhid's reports start with theirs
	country           uint8
	protocolMode      uint16 // the protocol mode characteristic, 0 when there is none
	protocolModeProps uint8
	reports           []hogpReport
}

type hogpReport struct {
	handle uint16
	props  uint8
	ccc    uint16 // the client characteristic configuration, 0 when there is none
	id     uint8
	kind   uint8 // input, output or feature
}

type pnpID struct {
	vendor, product, version uint16
}

// discoverHOGP finds the keyboard's HID services, and its PnP ID if it has
// a Device Information service.
func discoverHOGP(c *attConn) ([]*hogpService, *pnpID, error) {
	services, err := c.primaryServices()
	if err != nil {
		return nil, nil, fmt.Errorf("discovering services: %v", err)
	}
	var hids []*hogpService
	var pnp *pnpID
	for _, svc := range services {
		switch svc.uuid {
		case gattServiceHID:
			h, err := discoverHIDService(c, svc)
			if err != nil {
				return nil, nil, err
			}
			hids = append(hids, h)
		case gattServiceDeviceInfo:
			pnp = readPnPID(c, svc)
		}
	}
	return hids, pnp, nil
}

func discoverHIDService(c *attConn, svc gattService) (*hogpService, error) {
	chars, err := c.characteristics(svc)
	if err != nil {
		return nil, fmt.Errorf("discovering the HID service: %v", err)
	}
	h := &hogpService{}
	for _, ch := range chars {
		switch ch.uuid {
		case gattCharReportMap:
			if h.reportMap, err = c.readLong(ch.value); err != nil {
				return nil, fmt.Errorf("reading the report map: %v", err)
			}
		case gattCharHIDInformation:
			// bcdHID, bCountryCode, flags
			if v, err := c.read(ch.value); err == nil && len(v) >= 3 {
				h.country = v[2]
			}
		case gattCharProtocolMode:
			h.protocolMode, h.protocolModeProps = ch.value, ch.props
		case gattCharReport:
			r := hogpReport{handle: ch.value, props: ch.props}
			descs, err := c.descriptors(ch)
			if err != nil {
				return nil, fmt.Errorf("discovering a report: %v", err)
			}
			for _, d := range descs {
				switch d.uuid {
				case gattClientCharConfig:
					r.ccc = d.handle
				case gattReportReference:
					// the report ID and type
					v, err := c.read(d.handle)
					if err != nil || len(v) < 2 {
						return nil, fmt.Errorf("reading a report reference: %v", err)
					}
					r.id, r.kind = v[0], v[1]
				}
			}
			if r.kind == 0 {
				debug("bluetooth: ignoring report 0x%04x, which has no report reference", r.handle)
				continue
			}
			h.reports = append(h.reports, r)
		}
	}
	if len(h.reportMap) == 0 {
		return nil, fmt.Errorf("the HID service has no report map")
	}
	h.numbered = hidReportMapNumbered(h.reportMap)
	return h, nil
}

func readPnPID(c *attConn, svc gattService) *pnpID {
	chars, err := c.characteristics(svc)
	if err != nil {
		return nil
	}
	for _, ch := range chars {
		if ch.uuid != gattCharPnPID {
			continue
		}
		// vendor ID source, vendor ID, product ID, product version
		v, err := c.read(ch.value)
		if err != nil || len(v) < 7 {
			return nil
		}
		return &pnpID{
			vendor:  binary.LittleEndian.Uint16(v[1:]),
			product: binary.LittleEndian.Uint16(v[3:]),
			version: binary.LittleEndian.Uint16(v[5:]),
		}
	}
	return nil
}

// hidReportMapNumbered reports whether a HID report descriptor declares
// report IDs.
func hidReportMapNumbered(desc []byte) bool {
	for i := 0; i < len(desc); {
		prefix := desc[i]
		if prefix == 0xfe {
			// a long item: data size, tag, data
			if i+1 >= len(desc) {
				return false
			}
			i += 3 + int(desc[i+1])
			continue
		}
		if prefix&0xfc == 0x84 { // the Report ID global item
			return true
		}
		size := int(prefix & 3)
		if size == 3 {
			size = 4
		}
		i += 1 + size
	}
	return false
}

func (k *btLE) run(local bdaddr) {
	for !k.stack.isClosed() {
		started := time.Now()
		err := k.connectAndServe(local)
		switch {
		case k.stack.isClosed():
			return
		case errors.Is(err, errNoHIDService):
			warning("bluetooth: %s: %v", k, err)
			return
		case (errors.Is(err, unix.ETIMEDOUT) || errors.Is(err, unix.EHOSTDOWN)) && time.Since(started) > time.Second:
			// it did not advertise while the kernel looked for it, or it went
			// out of range; look again right away
			continue
		}
		k.stack.sleep(time.Second)
	}
}

func (k *btLE) connectAndServe(local bdaddr) error {
	f, err := l2capSocket(btSecurityMedium)
	if err != nil {
		return err
	}
	defer f.Close()
	defer k.stack.track(f)()

	if err := k.connect(f, local); err != nil {
		debug("bluetooth: connecting to %s: %v", k, err)
		return err
	}
	info("bluetooth: %s connected", k)
	err = k.serve(f, local)
	if !errors.Is(err, errNoHIDService) && !k.stack.isClosed() {
		info("bluetooth: %s disconnected: %v", k, err)
	}
	return err
}

// connect waits for the keyboard to come in range and connects to its ATT
// channel. The kernel scans for the keyboard, resolving its private address
// with the identity resolving key, and encrypts the link with the long term
// key before the connection completes, so that a device that does not have
// the key cannot pass for the keyboard.
func (k *btLE) connect(f *os.File, local bdaddr) error {
	if err := l2capBind(f, l2capAddr{cid: l2capCIDATT, addr: local, addrType: mgmtAddrLEPublic}); err != nil {
		return err
	}
	return l2capConnect(f, l2capAddr{cid: l2capCIDATT, addr: k.addr, addrType: k.addrType}, 0)
}

// serve runs the keyboard's HID devices for as long as it stays connected.
func (k *btLE) serve(f *os.File, local bdaddr) error {
	c := newATTConn(f)
	defer c.Close()
	c.exchangeMTU()

	if k.services == nil {
		services, pnp, err := discoverHOGP(c)
		if err != nil {
			return err
		}
		if len(services) == 0 {
			return errNoHIDService
		}
		k.services = services
		if k.vendor == 0 && k.product == 0 && pnp != nil {
			k.vendor, k.product, k.version = pnp.vendor, pnp.product, pnp.version
		}
	}

	name := k.name
	if name == "" {
		name = "Bluetooth keyboard " + k.addr.String()
	}
	var hids []*hogpHID
	defer func() {
		for _, h := range hids {
			h.untrack()
			_ = h.dev.Close()
		}
	}()
	inputs := make(map[uint16]*hogpInput)
	for _, svc := range k.services {
		dev, err := openUHID(uhidDeviceInfo{
			name:       name,
			phys:       local.String(),
			uniq:       k.addr.String(),
			descriptor: svc.reportMap,
			vendor:     uint32(k.vendor),
			product:    uint32(k.product),
			version:    uint32(k.version),
			country:    uint32(svc.country),
		})
		if err != nil {
			return fmt.Errorf("creating the HID device: %v", err)
		}
		h := &hogpHID{svc: svc, dev: dev, conn: c, untrack: k.stack.track(dev), opened: make(chan struct{})}
		hids = append(hids, h)
		btGo(h.handleEvents)
		for _, r := range svc.reports {
			if r.kind == hogpReportInput {
				inputs[r.handle] = &hogpInput{hid: h, id: r.id}
			}
		}
	}
	// The HID core drops reports until a driver has bound the device and
	// the console has opened its input device; the reports that came
	// before then wait for that.
	timeout := time.NewTimer(hogpOpenTimeout)
	defer timeout.Stop()
wait:
	for _, h := range hids {
		select {
		case <-h.opened:
		case <-timeout.C:
			debug("bluetooth: %s: nothing opened the HID device", k)
			break wait
		case <-c.done:
			return c.err
		}
	}
	c.setNotify(func(handle uint16, value []byte) {
		if in := inputs[handle]; in != nil {
			in.hid.input(in.id, value)
		}
	})

	for _, h := range hids {
		if h.svc.protocolMode != 0 && h.svc.protocolModeProps&gattPropWriteNoRsp != 0 {
			if err := c.writeCommand(h.svc.protocolMode, []byte{hogpProtocolModeReport}); err != nil {
				return err
			}
		}
		for _, r := range h.svc.reports {
			if r.kind != hogpReportInput || r.ccc == 0 {
				continue
			}
			if err := c.writeRequest(r.ccc, []byte{0x01, 0x00}); err != nil { // notifications on
				return fmt.Errorf("asking for its reports: %v", err)
			}
		}
	}

	<-c.done
	return c.err
}

// hogpHID is the uhid device of a HID service.
type hogpHID struct {
	svc     *hogpService
	dev     *uhidDevice
	conn    *attConn
	untrack func()
	opened  chan struct{} // closed once something opens the device's input
	once    sync.Once
}

type hogpInput struct {
	hid *hogpHID
	id  uint8
}

func (h *hogpHID) input(id uint8, value []byte) {
	if h.svc.numbered {
		value = append([]byte{id}, value...)
	}
	if err := h.dev.input(value); err != nil {
		debug("bluetooth: passing a report on: %v", err)
	}
}

// handleEvents answers the kernel's requests to the keyboard until the
// device is closed.
func (h *hogpHID) handleEvents() {
	for {
		ev, err := h.dev.readEvent()
		if err != nil {
			return
		}
		switch ev.typ {
		case uhidOpen:
			if h.opened != nil {
				h.once.Do(func() { close(h.opened) })
			}
		case uhidOutput:
			// output reports, the keyboard's LEDs, come with the ID in front when numbered
			var id uint8
			if h.svc.numbered && len(ev.data) > 0 {
				id = ev.data[0]
			}
			if err := h.setReport(ev.rtype, id, ev.data); err != nil {
				debug("bluetooth: passing an output report on: %v", err)
			}
		case uhidGetReport:
			report, err := h.getReport(ev.rtype, ev.rnum)
			errno := unix.Errno(0)
			if err != nil {
				debug("bluetooth: reading report %d: %v", ev.rnum, err)
				errno = unix.EIO
			}
			_ = h.dev.getReportReply(ev.id, errno, report)
		case uhidSetReport:
			errno := unix.Errno(0)
			if err := h.setReport(ev.rtype, ev.rnum, ev.data); err != nil {
				debug("bluetooth: writing report %d: %v", ev.rnum, err)
				errno = unix.EIO
			}
			_ = h.dev.setReportReply(ev.id, errno)
		}
	}
}

// report returns the report characteristic of a uhid report type and ID.
func (h *hogpHID) report(rtype, id uint8) (*hogpReport, error) {
	kind := map[uint8]uint8{
		uhidFeatureReport: hogpReportFeature,
		uhidOutputReport:  hogpReportOutput,
		uhidInputReport:   hogpReportInput,
	}[rtype]
	if !h.svc.numbered {
		id = 0
	}
	for i := range h.svc.reports {
		if r := &h.svc.reports[i]; r.kind == kind && r.id == id {
			return r, nil
		}
	}
	return nil, fmt.Errorf("the keyboard has no report %d of type %d", id, rtype)
}

func (h *hogpHID) getReport(rtype, id uint8) ([]byte, error) {
	r, err := h.report(rtype, id)
	if err != nil {
		return nil, err
	}
	value, err := h.conn.readLong(r.handle)
	if err != nil {
		return nil, err
	}
	if h.svc.numbered {
		value = append([]byte{r.id}, value...)
	}
	return value, nil
}

func (h *hogpHID) setReport(rtype, id uint8, data []byte) error {
	r, err := h.report(rtype, id)
	if err != nil {
		return err
	}
	if h.svc.numbered && len(data) > 0 {
		data = data[1:]
	}
	switch {
	case r.props&gattPropWrite != 0:
		return h.conn.writeRequest(r.handle, data)
	case r.props&gattPropWriteNoRsp != 0:
		return h.conn.writeCommand(r.handle, data)
	}
	return fmt.Errorf("report %d of type %d cannot be written", id, rtype)
}
