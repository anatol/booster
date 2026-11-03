package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type fakeAttr struct {
	handle uint16
	typ    []byte // a 16-bit or 128-bit UUID, little-endian
	value  []byte
}

func uuid16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }

// a vendor's 128-bit UUID
var vendorUUID = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

// hogpKeyboardDB is the GATT database of an LE keyboard.
func hogpKeyboardDB() []fakeAttr {
	decl := func(props uint8, value uint16, uuid []byte) []byte {
		return append(binary.LittleEndian.AppendUint16([]byte{props}, value), uuid...)
	}
	svc := func(uuid []byte) []byte { return uuid }
	return []fakeAttr{
		{0x0001, uuid16(gattPrimaryService), svc(uuid16(0x1800))},
		{0x0002, uuid16(gattCharacteristic), decl(0x02, 0x0003, uuid16(0x2a00))},
		{0x0003, uuid16(0x2a00), []byte("Example LE Keyboard")},
		{0x0010, uuid16(gattPrimaryService), svc(uuid16(gattServiceDeviceInfo))},
		{0x0011, uuid16(gattCharacteristic), decl(0x02, 0x0012, uuid16(gattCharPnPID))},
		{0x0012, uuid16(gattCharPnPID), []byte{0x02, 0x34, 0x12, 0xbc, 0x9a, 0x12, 0x00}},
		{0x0018, uuid16(gattPrimaryService), svc(vendorUUID)},
		{0x0019, uuid16(gattCharacteristic), decl(0x02, 0x001a, vendorUUID)},
		{0x001a, vendorUUID, []byte{0x42}},
		{0x0020, uuid16(gattPrimaryService), svc(uuid16(gattServiceHID))},
		{0x0021, uuid16(gattCharacteristic), decl(0x02, 0x0022, uuid16(gattCharHIDInformation))},
		{0x0022, uuid16(gattCharHIDInformation), []byte{0x11, 0x01, 0x21, 0x02}},
		{0x0023, uuid16(gattCharacteristic), decl(0x02, 0x0024, uuid16(gattCharReportMap))},
		{0x0024, uuid16(gattCharReportMap), testReportMap},
		{0x0025, uuid16(gattCharacteristic), decl(0x06, 0x0026, uuid16(gattCharProtocolMode))},
		{0x0026, uuid16(gattCharProtocolMode), []byte{0x01}},
		{0x0027, uuid16(gattCharacteristic), decl(0x1a, 0x0028, uuid16(gattCharReport))},
		{0x0028, uuid16(gattCharReport), []byte{0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{0x0029, uuid16(gattClientCharConfig), []byte{0x00, 0x00}},
		{0x002a, uuid16(gattReportReference), []byte{0x01, hogpReportInput}},
		{0x002b, uuid16(gattCharacteristic), decl(0x0e, 0x002c, uuid16(gattCharReport))},
		{0x002c, uuid16(gattCharReport), []byte{0x00}},
		{0x002d, uuid16(gattReportReference), []byte{0x01, hogpReportOutput}},
	}
}

// fakeGATT is a keyboard's GATT server at the far end of a socket pair. It
// answers like a real one: as many entries per response as fit, all of one
// length.
type fakeGATT struct {
	f      *os.File
	mtu    int
	attrs  []fakeAttr
	writes chan []byte // each write: opcode, handle, value
}

func newFakeGATT(t *testing.T, f *os.File, mtu int, attrs []fakeAttr) *fakeGATT {
	g := &fakeGATT{f: f, mtu: mtu, attrs: attrs, writes: make(chan []byte, 16)}
	go g.serve()
	return g
}

func (g *fakeGATT) attr(handle uint16) *fakeAttr {
	for i := range g.attrs {
		if g.attrs[i].handle == handle {
			return &g.attrs[i]
		}
	}
	return nil
}

func (g *fakeGATT) send(pdu []byte) { _, _ = g.f.Write(pdu) }

func (g *fakeGATT) fail(op uint8, handle uint16, code uint8) {
	g.send(append(binary.LittleEndian.AppendUint16([]byte{attOpError, op}, handle), code))
}

func (g *fakeGATT) notify(handle uint16, value []byte) {
	g.send(append(binary.LittleEndian.AppendUint16([]byte{attOpNotify}, handle), value...))
}

// entries answers a read by type or group type, or a find information,
// with as many entries as fit, all of the first one's length. The response
// starts with lead, given that length.
func (g *fakeGATT) entries(op, rspOp uint8, start uint16, list [][]byte, lead func(size int) byte) {
	var body []byte
	size := 0
	for _, e := range list {
		if size == 0 {
			size = len(e)
		}
		if len(e) != size || len(body)+size > g.mtu-2 {
			break
		}
		body = append(body, e...)
	}
	if len(body) == 0 {
		g.fail(op, start, attErrAttributeNotFound)
		return
	}
	g.send(append([]byte{rspOp, lead(size)}, body...))
}

func (g *fakeGATT) serve() {
	buf := make([]byte, 600)
	for {
		n, err := g.f.Read(buf)
		if err != nil {
			return
		}
		req := buf[:n]
		le := binary.LittleEndian
		switch req[0] {
		case attOpMTUReq:
			g.send(le.AppendUint16([]byte{attOpMTURsp}, uint16(g.mtu)))
		case attOpReadByGroupReq, attOpReadByTypeReq:
			start, end, typ := le.Uint16(req[1:]), le.Uint16(req[3:]), req[5:]
			var list [][]byte
			for i, a := range g.attrs {
				if a.handle < start || a.handle > end || !bytes.Equal(a.typ, typ) {
					continue
				}
				e := le.AppendUint16(nil, a.handle)
				if req[0] == attOpReadByGroupReq {
					groupEnd := uint16(0xffff)
					for _, b := range g.attrs[i+1:] {
						if bytes.Equal(b.typ, uuid16(gattPrimaryService)) {
							groupEnd = b.handle - 1
							break
						}
					}
					e = le.AppendUint16(e, groupEnd)
				}
				list = append(list, append(e, a.value...))
			}
			g.entries(req[0], req[0]+1, start, list, func(size int) byte { return byte(size) })
		case attOpFindInfoReq:
			start, end := le.Uint16(req[1:]), le.Uint16(req[3:])
			var list [][]byte
			for _, a := range g.attrs {
				if a.handle >= start && a.handle <= end {
					list = append(list, append(le.AppendUint16(nil, a.handle), a.typ...))
				}
			}
			g.entries(req[0], attOpFindInfoRsp, start, list, func(size int) byte {
				if size == 4 {
					return 1 // handles with 16-bit UUIDs
				}
				return 2 // with 128-bit ones
			})
		case attOpReadReq:
			if a := g.attr(le.Uint16(req[1:])); a != nil {
				g.send(append([]byte{attOpReadRsp}, a.value[:min(len(a.value), g.mtu-1)]...))
			} else {
				g.fail(req[0], le.Uint16(req[1:]), attErrInvalidHandle)
			}
		case attOpReadBlobReq:
			a, offset := g.attr(le.Uint16(req[1:])), int(le.Uint16(req[3:]))
			switch {
			case a == nil:
				g.fail(req[0], le.Uint16(req[1:]), attErrInvalidHandle)
			case len(a.value) <= g.mtu-1:
				g.fail(req[0], a.handle, attErrAttributeNotLong)
			case offset > len(a.value):
				g.fail(req[0], a.handle, attErrInvalidOffset)
			default:
				part := a.value[offset:]
				g.send(append([]byte{attOpReadBlobRsp}, part[:min(len(part), g.mtu-1)]...))
			}
		case attOpWriteReq:
			g.writes <- append([]byte(nil), req...)
			g.send([]byte{attOpWriteRsp})
		case attOpWriteCmd:
			g.writes <- append([]byte(nil), req...)
		}
	}
}

func TestDiscoverHOGP(t *testing.T) {
	t.Parallel()

	stackEnd, keyboard := seqpacketPair(t)
	newFakeGATT(t, keyboard, 23, hogpKeyboardDB())
	c := newATTConn(stackEnd)

	c.exchangeMTU()
	require.EqualValues(t, 23, c.mtu.Load())
	hids, pnp, err := discoverHOGP(c)
	require.NoError(t, err)
	require.Equal(t, &pnpID{vendor: 0x1234, product: 0x9abc, version: 0x0012}, pnp)
	require.Equal(t, []*hogpService{{
		reportMap:         testReportMap, // longer than one response, so read in parts
		numbered:          true,
		country:           0x21,
		protocolMode:      0x0026,
		protocolModeProps: 0x06,
		reports: []hogpReport{
			{handle: 0x0028, props: 0x1a, ccc: 0x0029, id: 1, kind: hogpReportInput},
			{handle: 0x002c, props: 0x0e, id: 1, kind: hogpReportOutput},
		},
	}}, hids)
}

func TestDiscoverHOGPWithoutHID(t *testing.T) {
	t.Parallel()

	stackEnd, keyboard := seqpacketPair(t)
	newFakeGATT(t, keyboard, 64, hogpKeyboardDB()[:9]) // GAP, Device Information and the vendor's
	hids, pnp, err := discoverHOGP(newATTConn(stackEnd))
	require.NoError(t, err)
	require.Empty(t, hids)
	require.NotNil(t, pnp)
}

func TestHOGPReports(t *testing.T) {
	t.Parallel()

	stackEnd, keyboard := seqpacketPair(t)
	g := newFakeGATT(t, keyboard, 64, hogpKeyboardDB())
	c := newATTConn(stackEnd)
	hids, _, err := discoverHOGP(c)
	require.NoError(t, err)

	uhidEnd, kernel := seqpacketPair(t)
	h := &hogpHID{svc: hids[0], dev: &uhidDevice{f: uhidEnd}, conn: c, opened: make(chan struct{})}

	// the key press that woke the keyboard waits until the device is up
	g.notify(0x0028, []byte{0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00})
	require.Eventually(t, func() bool {
		c.nmu.Lock()
		defer c.nmu.Unlock()
		return len(c.pending) == 1
	}, 5*time.Second, time.Millisecond)
	c.setNotify(func(handle uint16, value []byte) {
		if handle == 0x0028 {
			h.input(1, value)
		}
	})
	// and reaches uhid with the report ID in front, since the map has IDs
	ne := binary.NativeEndian
	ev := readPacket(t, kernel)
	require.Equal(t, uint32(uhidInput2), ne.Uint32(ev))
	require.Equal(t, uint16(9), ne.Uint16(ev[4:]))
	require.Equal(t, []byte{0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}, ev[6:])

	btGo(h.handleEvents)

	// the console opening the input device is what reports wait for
	_, err = kernel.Write(ne.AppendUint32(nil, uhidOpen))
	require.NoError(t, err)
	select {
	case <-h.opened:
	case <-time.After(5 * time.Second):
		t.Fatal("UHID_OPEN went unnoticed")
	}

	// Caps Lock's LED goes to the output report, without the ID
	out := make([]byte, 4+uhidDataMax+3)
	ne.PutUint32(out, uhidOutput)
	copy(out[4:], []byte{0x01, 0x02})
	ne.PutUint16(out[4+uhidDataMax:], 2)
	out[4+uhidDataMax+2] = uhidOutputReport
	_, err = kernel.Write(out)
	require.NoError(t, err)
	select {
	case w := <-g.writes:
		require.Equal(t, []byte{attOpWriteReq, 0x2c, 0x00, 0x02}, w)
	case <-time.After(5 * time.Second):
		t.Fatal("the output report was not written")
	}

	getReport := func(id uint32, rnum, rtype uint8) []byte {
		req := ne.AppendUint32(nil, uhidGetReport)
		req = ne.AppendUint32(req, id)
		_, err := kernel.Write(append(req, rnum, rtype))
		require.NoError(t, err)
		return readPacket(t, kernel)
	}
	rsp := getReport(7, 1, uhidInputReport)
	require.Equal(t, uint32(uhidGetReportReply), ne.Uint32(rsp))
	require.Equal(t, uint32(7), ne.Uint32(rsp[4:]))
	require.Equal(t, uint16(0), ne.Uint16(rsp[8:]))
	require.Equal(t, uint16(9), ne.Uint16(rsp[10:]))
	require.Equal(t, []byte{0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}, rsp[12:])

	rsp = getReport(8, 5, uhidFeatureReport) // one the keyboard does not have
	require.Equal(t, uint32(8), ne.Uint32(rsp[4:]))
	require.Equal(t, uint16(unix.EIO), ne.Uint16(rsp[8:]))
	require.Equal(t, uint16(0), ne.Uint16(rsp[10:]))

	// SET_REPORT on the output report goes the same way as an output event
	req := ne.AppendUint32(nil, uhidSetReport)
	req = ne.AppendUint32(req, 9)
	req = append(req, 1, uhidOutputReport)
	req = ne.AppendUint16(req, 2)
	_, err = kernel.Write(append(req, 0x01, 0x05))
	require.NoError(t, err)
	select {
	case w := <-g.writes:
		require.Equal(t, []byte{attOpWriteReq, 0x2c, 0x00, 0x05}, w)
	case <-time.After(5 * time.Second):
		t.Fatal("the report was not written")
	}
	rsp = readPacket(t, kernel)
	require.Equal(t, uint32(uhidSetReportReply), ne.Uint32(rsp))
	require.Equal(t, uint32(9), ne.Uint32(rsp[4:]))
	require.Equal(t, uint16(0), ne.Uint16(rsp[8:]))
}

func TestATTServesAnEmptyServer(t *testing.T) {
	t.Parallel()

	stackEnd, keyboard := seqpacketPair(t)
	c := newATTConn(stackEnd)
	ask := func(req []byte) []byte {
		_, err := keyboard.Write(req)
		require.NoError(t, err)
		return readPacket(t, keyboard)
	}

	require.Equal(t, []byte{attOpMTURsp, 0x05, 0x02}, ask([]byte{attOpMTUReq, 0x40, 0x00}))
	require.EqualValues(t, 64, c.mtu.Load())
	require.Equal(t, []byte{attOpError, attOpReadByGroupReq, 0x01, 0x00, attErrAttributeNotFound},
		ask(attPDU(attOpReadByGroupReq, 0x0001, 0xffff, gattPrimaryService)))
	require.Equal(t, []byte{attOpError, attOpReadReq, 0x03, 0x00, attErrInvalidHandle}, ask(attPDU(attOpReadReq, 0x0003)))
	require.Equal(t, []byte{attOpError, attOpExecWriteReq, 0x00, 0x00, attErrRequestNotSupported}, ask([]byte{attOpExecWriteReq, 0x01}))
	require.Equal(t, []byte{attOpConfirm}, ask([]byte{attOpIndicate, 0x28, 0x00, 0x01}))

	// a command gets no answer, so the next answer is to the next request
	_, err := keyboard.Write([]byte{attOpWriteCmd, 0x28, 0x00, 0x01})
	require.NoError(t, err)
	require.Equal(t, []byte{attOpError, attOpWriteReq, 0x04, 0x00, attErrInvalidHandle}, ask(attPDU(attOpWriteReq, 0x0004)))

	// and an error to a request of the stack's comes back as one
	go func() {
		if _, err := readMessage(keyboard); err == nil {
			_, _ = keyboard.Write([]byte{attOpError, attOpReadReq, 0x28, 0x00, 0x05})
		}
	}()
	_, err = c.read(0x0028)
	require.True(t, isATTError(err, 0x05), "%v", err)

	// the bearer going away ends what waits on it
	require.NoError(t, keyboard.Close())
	_, err = c.read(0x0028)
	require.Error(t, err)
	<-c.done
}

func TestHIDReportMapNumbered(t *testing.T) {
	t.Parallel()

	require.True(t, hidReportMapNumbered(testReportMap))
	unnumbered := append(append([]byte(nil), testReportMap[:6]...), testReportMap[8:]...)
	require.False(t, hidReportMapNumbered(unnumbered))
	// a Report ID inside a long item's data is not one
	require.False(t, hidReportMapNumbered([]byte{0xfe, 0x02, 0x10, 0x85, 0x01, 0x05, 0x01}))
	require.True(t, hidReportMapNumbered([]byte{0xfe, 0x00, 0x10, 0x85, 0x01}))
	require.False(t, hidReportMapNumbered([]byte{0xfe}))
	require.False(t, hidReportMapNumbered(nil))
}

func TestAttUUID16(t *testing.T) {
	t.Parallel()

	require.Equal(t, uint16(0x1812), attUUID16([]byte{0x12, 0x18}))
	base := []byte{0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x12, 0x18, 0x00, 0x00}
	require.Equal(t, uint16(0x1812), attUUID16(base))
	require.Equal(t, uint16(0), attUUID16(vendorUUID))
	require.Equal(t, uint16(0), attUUID16([]byte{0x12}))
}

func TestHOGPServe(t *testing.T) {
	// not parallel: it replaces openUHID
	kernels := make(chan *os.File, 1)
	defer func(orig func(uhidDeviceInfo) (*uhidDevice, error)) { openUHID = orig }(openUHID)
	openUHID = func(d uhidDeviceInfo) (*uhidDevice, error) {
		ev, err := uhidCreate2Event(d)
		if err != nil {
			return nil, err
		}
		devEnd, kernel := seqpacketPair(t)
		if _, err := devEnd.Write(ev); err != nil {
			return nil, err
		}
		kernels <- kernel
		return &uhidDevice{f: devEnd}, nil
	}

	s := newBtStack(testBluetoothConfig())
	k := s.adapters[0].le[0]
	stackEnd, keyboard := seqpacketPair(t)
	g := newFakeGATT(t, keyboard, 64, hogpKeyboardDB())
	served := make(chan error, 1)
	go func() { served <- k.serve(stackEnd, s.adapters[0].addr) }()

	kernel := <-kernels
	ne := binary.NativeEndian
	ev := readPacket(t, kernel)
	require.Equal(t, uint32(uhidCreate2), ne.Uint32(ev))
	require.Equal(t, "Example LE Keyboard\x00", string(ev[4:24]))
	require.Equal(t, uint32(0x1234), ne.Uint32(ev[264:]), "the vendor from the PnP ID, as BlueZ had none")
	require.Equal(t, testReportMap, ev[280:])

	// a key press before the console has opened the device is held back
	report := []byte{0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
	g.notify(0x0028, report)
	require.NoError(t, kernel.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, err := kernel.Read(make([]byte, 16))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	_, err = kernel.Write(ne.AppendUint32(nil, uhidOpen))
	require.NoError(t, err)
	ev = readPacket(t, kernel)
	require.Equal(t, uint32(uhidInput2), ne.Uint32(ev))
	require.Equal(t, append([]byte{0x01}, report...), ev[6:])

	// then the keyboard is put in report mode and asked for its input reports
	for _, want := range [][]byte{
		{attOpWriteCmd, 0x26, 0x00, hogpProtocolModeReport},
		{attOpWriteReq, 0x29, 0x00, 0x01, 0x00},
	} {
		select {
		case w := <-g.writes:
			require.Equal(t, want, w)
		case <-time.After(5 * time.Second):
			t.Fatalf("% x was not written", want)
		}
	}

	g.notify(0x0028, []byte{0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00})
	ev = readPacket(t, kernel)
	require.Equal(t, []byte{0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00}, ev[6:])

	// the keyboard going away ends serve and destroys the device
	require.NoError(t, keyboard.Close())
	select {
	case err := <-served:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return")
	}
	_, err = readMessage(kernel)
	require.Error(t, err, "the device is closed")
	require.NotNil(t, k.services, "what was discovered is kept for the next connection")
}
