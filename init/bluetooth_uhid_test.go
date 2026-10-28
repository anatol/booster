package main

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestUHIDCreate2Event(t *testing.T) {
	t.Parallel()

	ev, err := uhidCreate2Event(uhidDeviceInfo{
		name:       "Example LE Keyboard",
		phys:       "00:1A:7D:DA:71:13",
		uniq:       "F1:2A:3B:4C:5D:6E",
		descriptor: testReportMap,
		vendor:     0x1234,
		product:    0x9abc,
		version:    0x0012,
		country:    0x21,
	})
	require.NoError(t, err)

	// struct uhid_event { type; struct uhid_create2_req { name[128],
	// phys[64], uniq[64], rd_size, bus, vendor, product, version, country,
	// rd_data[] } }
	ne := binary.NativeEndian
	require.Equal(t, uint32(uhidCreate2), ne.Uint32(ev))
	require.Equal(t, "Example LE Keyboard\x00", string(ev[4:24]))
	require.Equal(t, "00:1A:7D:DA:71:13\x00", string(ev[132:150]))
	require.Equal(t, "F1:2A:3B:4C:5D:6E\x00", string(ev[196:214]))
	require.Equal(t, uint16(len(testReportMap)), ne.Uint16(ev[260:]))
	require.Equal(t, uint16(busBluetooth), ne.Uint16(ev[262:]))
	require.Equal(t, uint32(0x1234), ne.Uint32(ev[264:]))
	require.Equal(t, uint32(0x9abc), ne.Uint32(ev[268:]))
	require.Equal(t, uint32(0x0012), ne.Uint32(ev[272:]))
	require.Equal(t, uint32(0x21), ne.Uint32(ev[276:]))
	require.Equal(t, testReportMap, ev[280:])

	// names are cut to leave the terminating NUL
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'x'
	}
	ev, err = uhidCreate2Event(uhidDeviceInfo{name: string(long), descriptor: testReportMap})
	require.NoError(t, err)
	require.Equal(t, byte(0), ev[4+127])

	_, err = uhidCreate2Event(uhidDeviceInfo{})
	require.Error(t, err)
	_, err = uhidCreate2Event(uhidDeviceInfo{descriptor: make([]byte, uhidDataMax+1)})
	require.Error(t, err)
}

func TestParseUHIDEvent(t *testing.T) {
	t.Parallel()

	ne := binary.NativeEndian

	out := make([]byte, uhidEventSize)
	ne.PutUint32(out, uhidOutput)
	copy(out[4:], []byte{0x01, 0x02})
	ne.PutUint16(out[4+uhidDataMax:], 2)
	out[4+uhidDataMax+2] = uhidOutputReport
	ev, err := parseUHIDEvent(out)
	require.NoError(t, err)
	require.Equal(t, uhidEvent{typ: uhidOutput, rtype: uhidOutputReport, data: []byte{0x01, 0x02}}, ev)

	get := ne.AppendUint32(nil, uhidGetReport)
	get = ne.AppendUint32(get, 42)
	ev, err = parseUHIDEvent(append(get, 3, uhidFeatureReport))
	require.NoError(t, err)
	require.Equal(t, uhidEvent{typ: uhidGetReport, id: 42, rnum: 3, rtype: uhidFeatureReport}, ev)

	set := ne.AppendUint32(nil, uhidSetReport)
	set = ne.AppendUint32(set, 43)
	set = append(set, 1, uhidOutputReport)
	set = ne.AppendUint16(set, 2)
	ev, err = parseUHIDEvent(append(set, 0x01, 0x04))
	require.NoError(t, err)
	require.Equal(t, uhidEvent{typ: uhidSetReport, id: 43, rnum: 1, rtype: uhidOutputReport, data: []byte{0x01, 0x04}}, ev)

	ev, err = parseUHIDEvent(ne.AppendUint32(nil, uhidStart))
	require.NoError(t, err)
	require.Equal(t, uint32(uhidStart), ev.typ)

	for _, bad := range [][]byte{
		{0x01},
		ne.AppendUint32(nil, uhidOutput),
		append(ne.AppendUint32(nil, uhidGetReport), 0x01),
		ne.AppendUint16(append(append(ne.AppendUint32(nil, uhidSetReport), 0, 0, 0, 0), 1, 0), 5), // longer than it is
	} {
		_, err := parseUHIDEvent(bad)
		require.Error(t, err, "% x", bad)
	}
}

func TestUHIDReplies(t *testing.T) {
	t.Parallel()

	devEnd, kernel := seqpacketPair(t)
	dev := &uhidDevice{f: devEnd}
	ne := binary.NativeEndian

	require.NoError(t, dev.getReportReply(7, 0, []byte{0x01, 0x02}))
	ev := readPacket(t, kernel)
	require.Equal(t, uint32(uhidGetReportReply), ne.Uint32(ev))
	require.Equal(t, uint32(7), ne.Uint32(ev[4:]))
	require.Equal(t, uint16(0), ne.Uint16(ev[8:]))
	require.Equal(t, uint16(2), ne.Uint16(ev[10:]))
	require.Equal(t, []byte{0x01, 0x02}, ev[12:])

	require.NoError(t, dev.setReportReply(8, unix.EIO))
	ev = readPacket(t, kernel)
	require.Equal(t, uint32(uhidSetReportReply), ne.Uint32(ev))
	require.Equal(t, uint32(8), ne.Uint32(ev[4:]))
	require.Equal(t, uint16(unix.EIO), ne.Uint16(ev[8:]))

	require.NoError(t, dev.input([]byte{0x01, 0x00, 0x04}))
	ev = readPacket(t, kernel)
	require.Equal(t, uint32(uhidInput2), ne.Uint32(ev))
	require.Equal(t, uint16(3), ne.Uint16(ev[4:]))
	require.Equal(t, []byte{0x01, 0x00, 0x04}, ev[6:])
}
