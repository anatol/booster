package main

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

type hidpCall struct {
	req        uintptr
	connadd    hidpConnaddReq
	descriptor []byte
	conndel    hidpConndelReq
}

func TestClassicSession(t *testing.T) {
	// not parallel: it replaces hidpRequest
	calls := make(chan hidpCall, 4)
	defer func(orig func(uintptr, unsafe.Pointer) error) { hidpRequest = orig }(hidpRequest)
	hidpRequest = func(req uintptr, arg unsafe.Pointer) error {
		c := hidpCall{req: req}
		switch req {
		case hidpConnAdd:
			c.connadd = *(*hidpConnaddReq)(arg)
			c.descriptor = bytes.Clone(unsafe.Slice(c.connadd.rdData, c.connadd.rdSize))
		case hidpConnDel:
			c.conndel = *(*hidpConndelReq)(arg)
		}
		calls <- c
		return nil
	}

	cfg := testBluetoothConfig()
	cfg.Adapters[0].Devices[0].Classic.SDPRecords = []string{
		hex.EncodeToString(testPnPRecord),
		hex.EncodeToString(testHIDRecord(sdpUUID16v(sdpUUIDHID), true, false)),
	}
	s := newBtStack(cfg)
	m, _ := newFakeKernel(t)
	s.mgmt = m
	k := s.adapters[0].classic[0]
	local := s.adapters[0].addr
	require.NotNil(t, k.record, "the HID record comes from BlueZ's cache")

	// an interrupt channel without a control channel before it is turned down
	lone, lonePeer := seqpacketPair(t)
	k.channelUp(l2capPSMHIDInterrupt, lone, local)
	_, err := readMessage(lonePeer)
	require.Error(t, err)

	ctrl, ctrlPeer := seqpacketPair(t)
	intr, intrPeer := seqpacketPair(t)
	k.channelUp(l2capPSMHIDControl, ctrl, local)
	k.channelUp(l2capPSMHIDInterrupt, intr, local)
	var c hidpCall
	select {
	case c = <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("HIDP was not given the channels")
	}
	require.Equal(t, uintptr(hidpConnAdd), c.req)
	require.Equal(t, testReportMap, c.descriptor)
	require.Equal(t, uint16(0x0111), c.connadd.parser)
	require.Equal(t, uint8(0x40), c.connadd.subclass)
	require.Equal(t, uint8(0x21), c.connadd.country)
	require.Equal(t, "Example Keyboard", string(bytes.TrimRight(c.connadd.name[:], "\x00")))
	require.NotEqual(t, c.connadd.ctrlSock, c.connadd.intrSock)
	require.Zero(t, c.connadd.flags)
	require.Eventually(t, func() bool {
		k.mu.Lock()
		defer k.mu.Unlock()
		return k.connected
	}, 5*time.Second, time.Millisecond)

	// HIDP holds its own references; booster's descriptors are closed
	_, err = readMessage(ctrlPeer)
	require.Error(t, err)
	_, err = readMessage(intrPeer)
	require.Error(t, err)

	// shutting down ends the session, without unplugging the virtual
	// cable, which would have the keyboard forget its bond
	s.close()
	select {
	case c = <-calls:
	case <-time.After(5 * time.Second):
		t.Fatal("the session was not ended")
	}
	require.Equal(t, uintptr(hidpConnDel), c.req)
	require.Equal(t, k.addr.wire(), c.conndel.bdaddr)
	require.Zero(t, c.conndel.flags)
}

func TestHIDPStructs(t *testing.T) {
	t.Parallel()

	// struct hidp_connadd_req has a pointer in the middle
	if unsafe.Sizeof(uintptr(0)) == 8 {
		require.Equal(t, uintptr(168), unsafe.Sizeof(hidpConnaddReq{}))
		require.Equal(t, uintptr(40), unsafe.Offsetof(hidpConnaddReq{}.name))
	} else {
		require.Equal(t, uintptr(160), unsafe.Sizeof(hidpConnaddReq{}))
		require.Equal(t, uintptr(32), unsafe.Offsetof(hidpConnaddReq{}.name))
	}
	require.Equal(t, uintptr(12), unsafe.Sizeof(hidpConndelReq{}))

	// _IOW('H', nr, int) in asm-generic/ioctl.h's encoding
	iow := func(nr uintptr) uintptr { return 1<<30 | 4<<16 | 'H'<<8 | nr }
	require.Equal(t, iow(200), uintptr(hidpConnAdd))
	require.Equal(t, iow(201), uintptr(hidpConnDel))
}
