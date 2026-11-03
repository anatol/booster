package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// SDP data elements, for building records.
func sdpSeq(items ...[]byte) []byte {
	body := bytes.Join(items, nil)
	if len(body) < 0x100 {
		return append([]byte{0x35, byte(len(body))}, body...)
	}
	return append(binary.BigEndian.AppendUint16([]byte{0x36}, uint16(len(body))), body...)
}
func sdpUint8(v uint8) []byte    { return []byte{0x08, v} }
func sdpUint16(v uint16) []byte  { return binary.BigEndian.AppendUint16([]byte{0x09}, v) }
func sdpUint32(v uint32) []byte  { return binary.BigEndian.AppendUint32([]byte{0x0a}, v) }
func sdpUUID16v(v uint16) []byte { return binary.BigEndian.AppendUint16([]byte{0x19}, v) }
func sdpBoolv(v bool) []byte {
	if v {
		return []byte{0x28, 1}
	}
	return []byte{0x28, 0}
}

func sdpTextv(s []byte) []byte {
	if len(s) < 0x100 {
		return append([]byte{0x25, byte(len(s))}, s...)
	}
	return append(binary.BigEndian.AppendUint16([]byte{0x26}, uint16(len(s))), s...)
}

// a keyboard's report descriptor, the boot keyboard's with a report ID
var testReportMap = []byte{
	0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00,
	0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05,
	0x75, 0x01, 0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01,
	0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00,
	0xc0,
}

func testHIDRecord(classID []byte, reconnectInitiate, normallyConnectable bool) []byte {
	return sdpSeq(
		sdpUint16(0x0000), sdpUint32(0x00010001),
		sdpUint16(sdpAttrServiceClassIDList), sdpSeq(classID),
		sdpUint16(sdpAttrServiceName), sdpTextv([]byte("Example Keyboard\x00")),
		sdpUint16(sdpAttrHIDParserVersion), sdpUint16(0x0111),
		sdpUint16(sdpAttrHIDDeviceSubclass), sdpUint8(0x40),
		sdpUint16(sdpAttrHIDCountryCode), sdpUint8(0x21),
		sdpUint16(sdpAttrHIDReconnectInitiate), sdpBoolv(reconnectInitiate),
		sdpUint16(sdpAttrHIDDescriptorList), sdpSeq(
			sdpSeq(sdpUint8(0x23), sdpTextv([]byte{1, 2, 3})), // a physical descriptor, skipped
			sdpSeq(sdpUint8(hidDescriptorTypeReport), sdpTextv(testReportMap)),
		),
		sdpUint16(sdpAttrHIDNormallyConnectable), sdpBoolv(normallyConnectable),
	)
}

// the record of the PnP Information service, which every keyboard also has
var testPnPRecord = sdpSeq(
	sdpUint16(0x0000), sdpUint32(0x00010002),
	sdpUint16(sdpAttrServiceClassIDList), sdpSeq(sdpUUID16v(0x1200)),
	sdpUint16(0x0201), sdpUint16(0x1234),
)

func TestParseSDPElement(t *testing.T) {
	t.Parallel()

	e, rest, err := parseSDPElement([]byte{0x09, 0x12, 0x34, 0xff})
	require.NoError(t, err)
	require.Equal(t, []byte{0xff}, rest)
	v, ok := e.uint()
	require.True(t, ok)
	require.Equal(t, uint64(0x1234), v)

	// sizes in 1, 2 and 4 bytes after the descriptor
	long := bytes.Repeat([]byte{'x'}, 300)
	for _, enc := range [][]byte{
		sdpTextv([]byte("short")),
		sdpTextv(long),
		append(binary.BigEndian.AppendUint32([]byte{0x27}, 300), long...),
	} {
		e, rest, err := parseSDPElement(enc)
		require.NoError(t, err)
		require.Empty(t, rest)
		require.Equal(t, uint8(sdpText), e.kind)
	}

	// nil has no size whatever its size index says
	e, rest, err = parseSDPElement([]byte{0x00, 0x09})
	require.NoError(t, err)
	require.Equal(t, uint8(sdpNil), e.kind)
	require.Equal(t, []byte{0x09}, rest)

	// a 128-bit UUID can be a 16-bit one
	e, _, err = parseSDPElement(append([]byte{0x1c},
		0x00, 0x00, 0x11, 0x24, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb))
	require.NoError(t, err)
	require.True(t, e.isUUID16(sdpUUIDHID))
	require.False(t, e.isUUID16(0x1200))
	e, _, err = parseSDPElement([]byte{0x1a, 0x00, 0x00, 0x11, 0x24})
	require.NoError(t, err)
	require.True(t, e.isUUID16(sdpUUIDHID))

	for _, bad := range [][]byte{
		{},
		{0x09, 0x12},       // a 16-bit integer cut short
		{0x25, 0x05, 'a'},  // text longer than what is there
		{0x26, 0x00},       // its size cut short
		{0x35, 0x02, 0x09}, // a sequence whose element is cut short
		{0x35},             // a sequence without its size
	} {
		_, _, err := parseSDPElement(bad)
		require.Error(t, err, "% x", bad)
	}

	// sequences nested deep enough to exhaust the stack are refused
	nested := []byte{0x08, 0x00}
	for range 32 {
		nested = sdpSeq(nested)
	}
	_, _, err = parseSDPElement(nested)
	require.ErrorContains(t, err, "nested too deep")
}

func TestParseHIDRecord(t *testing.T) {
	t.Parallel()

	rec, _, err := parseSDPElement(testHIDRecord(sdpUUID16v(sdpUUIDHID), true, false))
	require.NoError(t, err)
	r, err := parseHIDRecord(rec)
	require.NoError(t, err)
	require.Equal(t, &hidRecord{
		name:              "Example Keyboard",
		parserVersion:     0x0111,
		subclass:          0x40,
		country:           0x21,
		reconnectInitiate: true,
		descriptor:        testReportMap,
	}, r)

	rec, _, err = parseSDPElement(testPnPRecord)
	require.NoError(t, err)
	r, err = parseHIDRecord(rec)
	require.NoError(t, err)
	require.Nil(t, r, "not a HID record")

	rec, _, err = parseSDPElement(sdpSeq(sdpUint16(sdpAttrServiceClassIDList), sdpSeq(sdpUUID16v(sdpUUIDHID))))
	require.NoError(t, err)
	_, err = parseHIDRecord(rec)
	require.ErrorContains(t, err, "no report descriptor")

	rec, _, err = parseSDPElement(sdpSeq(sdpUint16(sdpAttrServiceClassIDList)))
	require.NoError(t, err)
	_, err = parseHIDRecord(rec)
	require.Error(t, err, "attribute without a value")
}

func TestFindHIDRecord(t *testing.T) {
	t.Parallel()

	r, err := findHIDRecord([][]byte{testPnPRecord, {0x35}, testHIDRecord(sdpUUID16v(sdpUUIDHID), false, true)})
	require.NoError(t, err)
	require.Equal(t, testReportMap, r.descriptor)

	_, err = findHIDRecord([][]byte{testPnPRecord})
	require.EqualError(t, err, "no HID record")
	_, err = findHIDRecord([][]byte{{0x35}})
	require.ErrorContains(t, err, "truncated")
}

func TestHostReconnects(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		reconnectInitiate, normallyConnectable, hostReconnects bool
	}{
		{true, false, false}, // most keyboards: they connect to the host
		{true, true, false},
		{false, true, true},
		{false, false, false}, // nobody reconnects
	} {
		rec, _, err := parseSDPElement(testHIDRecord(sdpUUID16v(sdpUUIDHID), tc.reconnectInitiate, tc.normallyConnectable))
		require.NoError(t, err)
		r, err := parseHIDRecord(rec)
		require.NoError(t, err)
		k := &btClassic{record: r}
		require.Equal(t, tc.hostReconnects, k.hostReconnects(), "%+v", tc)
	}
}

func TestSDPQueryHIDRecord(t *testing.T) {
	t.Parallel()

	stackEnd, keyboard := seqpacketPair(t)
	lists := sdpSeq(testHIDRecord(sdpUUID16v(sdpUUIDHID), true, false))
	half := len(lists) / 2

	// the keyboard's SDP server answers in two parts, and the request for the
	// second carries the continuation state the first ended with
	server := make(chan error, 1)
	go func() {
		server <- func() error {
			for _, part := range []struct{ lists, continuation, expect []byte }{
				{lists[:half], []byte{0x02, 0xab, 0xcd}, []byte{0x00}},
				{lists[half:], []byte{0x00}, []byte{0x02, 0xab, 0xcd}},
			} {
				req, err := readMessage(keyboard)
				if err != nil {
					return err
				}
				if req[0] != sdpServiceSearchAttributeReq || !bytes.HasSuffix(req, part.expect) {
					return fmt.Errorf("unexpected request % x", req)
				}
				params := binary.BigEndian.AppendUint16(nil, uint16(len(part.lists)))
				params = append(append(params, part.lists...), part.continuation...)
				rsp := append([]byte{sdpServiceSearchAttributeRsp}, req[1:3]...) // the same transaction
				rsp = binary.BigEndian.AppendUint16(rsp, uint16(len(params)))
				if _, err := keyboard.Write(append(rsp, params...)); err != nil {
					return err
				}
			}
			return nil
		}()
	}()

	r, err := sdpQueryHIDRecord(stackEnd)
	require.NoError(t, err)
	require.Equal(t, testReportMap, r.descriptor)
	require.NoError(t, <-server)
}

func TestSDPQueryErrors(t *testing.T) {
	t.Parallel()

	for _, rsp := range [][]byte{
		{sdpErrorRsp, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03},                  // the server's error
		{sdpServiceSearchAttributeRsp, 0x00, 0x07, 0x00, 0x03, 0x00, 0x10}, // a transaction it was not asked
		{sdpServiceSearchAttributeRsp, 0x00, 0x01, 0x00, 0x03, 0x00, 0x10}, // lists longer than the response
	} {
		stackEnd, keyboard := seqpacketPair(t)
		go func() {
			if _, err := readMessage(keyboard); err == nil {
				_, _ = keyboard.Write(rsp)
			}
		}()
		_, err := sdpQueryHIDRecord(stackEnd)
		require.Error(t, err, "% x", rsp)
	}
}
