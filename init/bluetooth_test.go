package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// seqpacketPair returns the two ends of a SOCK_SEQPACKET socket pair, which
// keeps message boundaries the way the kernel's Bluetooth sockets do. The
// first end is set up like the stack's own sockets.
func seqpacketPair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	a, b := os.NewFile(uintptr(fds[0]), "stack"), os.NewFile(uintptr(fds[1]), "peer")
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

// readMessage reads one message from the peer end of a socket pair, giving
// up after a while. Fakes running on goroutines of their own use it.
func readMessage(f *os.File) ([]byte, error) {
	if err := f.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return nil, err
	}
	buf := make([]byte, 0x10000)
	n, err := f.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// readPacket reads one message from the peer end, failing the test if none
// arrives in time.
func readPacket(t *testing.T, f *os.File) []byte {
	t.Helper()
	b, err := readMessage(f)
	require.NoError(t, err)
	return b
}

func TestBdaddr(t *testing.T) {
	t.Parallel()

	a, err := parseBdaddr("00:1A:7d:DA:71:13")
	require.NoError(t, err)
	require.Equal(t, bdaddr{0x00, 0x1a, 0x7d, 0xda, 0x71, 0x13}, a)
	require.Equal(t, "00:1A:7D:DA:71:13", a.String())
	require.Equal(t, [6]byte{0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00}, a.wire())
	w := a.wire()
	require.Equal(t, a, bdaddrFromWire(w[:]))

	for _, s := range []string{"", "00:1A:7D:DA:71", "00-1A-7D-DA-71-13", "00:1A:7D:DA:71:1G"} {
		_, err := parseBdaddr(s)
		require.Error(t, err, s)
	}
}

const testKey = "00112233445566778899AABBCCDDEEFF"

func testBluetoothConfig() *InitBluetoothConfig {
	return &InitBluetoothConfig{Adapters: []BluetoothAdapter{{
		Address: "00:1A:7D:DA:71:13",
		Devices: []BluetoothDevice{
			{
				Address: "12:34:56:78:9A:BC",
				Name:    "Example Keyboard",
				Classic: &BluetoothClassic{LinkKey: testKey, LinkKeyType: 4, PINLength: 0},
			},
			{
				Address: "F1:2A:3B:4C:5D:6E",
				Name:    "Example LE Keyboard",
				LE: &BluetoothLE{
					AddressType: "static", LongTermKey: testKey, Authenticated: 2, EncSize: 16,
					IdentityResolvingKey: "8E1D2A9C4B3F5E6D7A8B9C0D1E2F3A4B",
				},
			},
			{Address: "11:11:11:11:11:11"}, // no bond
			{Address: "22:22:22:22:22:22", Classic: &BluetoothClassic{LinkKey: "00112233"}},
			{Address: "33:33:33:33:33:33", LE: &BluetoothLE{AddressType: "resolvable", LongTermKey: testKey}},
		},
	}, {
		Address: "AA:BB:CC:DD:EE:FF",
		Devices: []BluetoothDevice{{Address: "44:44:44:44:44:44"}}, // nothing usable left
	}}}
}

func TestNewBtStack(t *testing.T) {
	t.Parallel()

	s := newBtStack(testBluetoothConfig())
	require.NotNil(t, s)
	require.Len(t, s.adapters, 1)
	ad := s.adapters[0]
	require.Equal(t, "00:1A:7D:DA:71:13", ad.addr.String())

	require.Len(t, ad.classic, 1)
	k := ad.classic[0]
	require.Equal(t, `"Example Keyboard" (12:34:56:78:9A:BC)`, k.String())
	require.Equal(t, uint8(4), k.linkKeyType)

	require.Len(t, ad.le, 1)
	le := ad.le[0]
	require.Equal(t, uint8(mgmtAddrLERandom), le.addrType)
	require.Equal(t, uint8(2), le.ltkType)
	require.NotNil(t, le.irk)

	require.Nil(t, newBtStack(&InitBluetoothConfig{}))
}

func TestMgmtKeyEncoding(t *testing.T) {
	t.Parallel()

	s := newBtStack(testBluetoothConfig())
	ad := s.adapters[0]
	ad.le[0].ediv, ad.le[0].rand = 0x1234, 0x0102030405060708

	key, _ := hex.DecodeString(testKey)
	irk, _ := hex.DecodeString("8E1D2A9C4B3F5E6D7A8B9C0D1E2F3A4B")
	cat := func(parts ...[]byte) (b []byte) {
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}

	// debug keys off, one key: address, BR/EDR, key type, key, PIN length
	require.Equal(t, cat(
		[]byte{0x00, 0x01, 0x00},
		[]byte{0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, mgmtAddrBREDR, 0x04}, key, []byte{0x00},
	), mgmtLinkKeys(ad.classic))

	// one key: address, LE random, type, initiator, size, ediv, rand, key
	require.Equal(t, cat(
		[]byte{0x01, 0x00},
		[]byte{0x6e, 0x5d, 0x4c, 0x3b, 0x2a, 0xf1, mgmtAddrLERandom, 0x02, 0x01, 0x10},
		[]byte{0x34, 0x12}, []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}, key,
	), mgmtLongTermKeys(ad.le))

	require.Equal(t, cat(
		[]byte{0x01, 0x00},
		[]byte{0x6e, 0x5d, 0x4c, 0x3b, 0x2a, 0xf1, mgmtAddrLERandom}, irk,
	), mgmtIRKs(ad.le))

	ad.le[0].irk = nil
	require.Equal(t, []byte{0x00, 0x00}, mgmtIRKs(ad.le))
}

// fakeKernel answers the management commands the stack sends on the other
// end of a socket pair, the way the kernel does.
type fakeKernel struct {
	t    *testing.T
	f    *os.File
	mu   sync.Mutex
	cmds []mgmtPacket
	got  chan mgmtPacket

	info   []byte           // READ_INFO's result
	status map[uint16]uint8 // opcodes to fail, with the status
}

func newFakeKernel(t *testing.T) (*mgmtConn, *fakeKernel) {
	stackEnd, kernelEnd := seqpacketPair(t)
	k := &fakeKernel{t: t, f: kernelEnd, got: make(chan mgmtPacket, 64), status: make(map[uint16]uint8)}
	m := newMgmtConn(stackEnd)
	t.Cleanup(func() { _ = m.Close() })
	go k.serve()
	return m, k
}

func (k *fakeKernel) serve() {
	buf := make([]byte, 0x10006)
	for {
		n, err := k.f.Read(buf)
		if err != nil || n < 6 {
			return
		}
		p := mgmtPacket{
			code:  binary.LittleEndian.Uint16(buf),
			index: binary.LittleEndian.Uint16(buf[2:]),
			data:  append([]byte(nil), buf[6:n]...),
		}
		k.mu.Lock()
		k.cmds = append(k.cmds, p)
		status := k.status[p.code]
		info := k.info
		k.mu.Unlock()
		k.got <- p

		var result []byte
		if p.code == mgmtOpReadInfo {
			result = info
		}
		reply := binary.LittleEndian.AppendUint16(nil, p.code)
		reply = append(reply, status)
		if status == 0 {
			reply = append(reply, result...)
		}
		k.event(mgmtEvCmdComplete, p.index, reply)
	}
}

func (k *fakeKernel) event(code, index uint16, data []byte) {
	pkt := binary.LittleEndian.AppendUint16(nil, code)
	pkt = binary.LittleEndian.AppendUint16(pkt, index)
	pkt = binary.LittleEndian.AppendUint16(pkt, uint16(len(data)))
	_, err := k.f.Write(append(pkt, data...))
	require.NoError(k.t, err)
}

func (k *fakeKernel) opcodes() []uint16 {
	k.mu.Lock()
	defer k.mu.Unlock()
	var ops []uint16
	for _, c := range k.cmds {
		ops = append(ops, c.code)
	}
	return ops
}

func (k *fakeKernel) command(op uint16) mgmtPacket {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, c := range k.cmds {
		if c.code == op {
			return c
		}
	}
	k.t.Fatalf("no command 0x%04x was sent", op)
	return mgmtPacket{}
}

func controllerInfo(addr string, supported uint32) []byte {
	a, _ := parseBdaddr(addr)
	w := a.wire()
	b := append(w[:], 0x0a)                         // version
	b = binary.LittleEndian.AppendUint16(b, 0x0002) // manufacturer
	b = binary.LittleEndian.AppendUint32(b, supported)
	b = binary.LittleEndian.AppendUint32(b, 0)
	return append(b, make([]byte, 3+249+11)...)
}

func TestMgmtCommand(t *testing.T) {
	t.Parallel()

	stackEnd, kernelEnd := seqpacketPair(t)
	m := newMgmtConn(stackEnd)
	defer m.Close()

	type result struct {
		rsp []byte
		err error
	}
	run := func(op uint16, params []byte) chan result {
		ch := make(chan result, 1)
		go func() {
			rsp, err := m.commandTimeout(0, op, params, 2*time.Second)
			ch <- result{rsp, err}
		}()
		return ch
	}
	reply := func(code, index, op uint16, status byte, params ...byte) {
		data := append(binary.LittleEndian.AppendUint16(nil, op), status)
		pkt := binary.LittleEndian.AppendUint16(nil, code)
		pkt = binary.LittleEndian.AppendUint16(pkt, index)
		pkt = binary.LittleEndian.AppendUint16(pkt, uint16(len(data)+len(params)))
		_, err := kernelEnd.Write(append(append(pkt, data...), params...))
		require.NoError(t, err)
	}

	ch := run(mgmtOpSetPowered, []byte{1})
	require.Equal(t, []byte{0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01}, readPacket(t, kernelEnd))
	reply(mgmtEvCmdComplete, 0, mgmtOpSetLE, 0)                     // the late reply to another command
	reply(mgmtEvCmdComplete, 1, mgmtOpSetPowered, 0)                // to another controller
	reply(mgmtEvCmdStatus, 0, mgmtOpSetPowered, 0)                  // accepted, result to follow
	reply(mgmtEvCmdComplete, 0, mgmtOpSetPowered, 0, 0x01, 0, 0, 0) // the settings
	r := <-ch
	require.NoError(t, r.err)
	require.Equal(t, []byte{0x01, 0, 0, 0}, r.rsp)

	ch = run(mgmtOpSetPowered, []byte{1})
	readPacket(t, kernelEnd)
	reply(mgmtEvCmdStatus, 0, mgmtOpSetPowered, mgmtStatusRFKilled)
	r = <-ch
	require.ErrorIs(t, r.err, mgmtError(mgmtStatusRFKilled))
	require.EqualError(t, r.err, "blocked by rfkill")

	// an event in between goes to the event loop, not to the command
	ch = run(mgmtOpReadInfo, nil)
	readPacket(t, kernelEnd)
	reply(mgmtEvAuthFailed, 0, 0x5634, 0x12)
	reply(mgmtEvCmdComplete, 0, mgmtOpReadInfo, 0, 0xaa)
	r = <-ch
	require.NoError(t, r.err)
	require.Equal(t, []byte{0xaa}, r.rsp)
	ev := <-m.events
	require.Equal(t, uint16(mgmtEvAuthFailed), ev.code)

	_, err := m.commandTimeout(0, mgmtOpSetLE, []byte{1}, 50*time.Millisecond)
	require.ErrorContains(t, err, "no reply")
	readPacket(t, kernelEnd)

	ch = run(mgmtOpSetLE, []byte{1})
	readPacket(t, kernelEnd)
	require.NoError(t, m.Close())
	r = <-ch
	require.ErrorIs(t, r.err, os.ErrClosed)
	_, ok := <-m.events
	require.False(t, ok, "the event channel closes with the socket")
}

func TestConfigureController(t *testing.T) {
	t.Parallel()

	s := newBtStack(testBluetoothConfig())
	m, kernel := newFakeKernel(t)
	s.mgmt = m
	kernel.info = controllerInfo("00:1A:7D:DA:71:13",
		mgmtSettingPowered|mgmtSettingSSP|mgmtSettingBREDR|mgmtSettingLE|mgmtSettingSecureConn)

	ad := s.configureController(0)
	require.Equal(t, s.adapters[0], ad)
	require.Equal(t, []uint16{
		mgmtOpReadInfo,
		mgmtOpSetBondable, mgmtOpSetBREDR, mgmtOpSetSSP, mgmtOpSetLE, mgmtOpSetSecureConn,
		mgmtOpLoadLinkKeys, mgmtOpLoadLongTermKeys, mgmtOpLoadIRKs,
		mgmtOpSetPowered,
		mgmtOpAddDevice,
	}, kernel.opcodes())
	require.Equal(t, []byte{0}, kernel.command(mgmtOpSetBondable).data, "nothing pairs at boot")
	require.Equal(t, []byte{1}, kernel.command(mgmtOpSetPowered).data)
	require.Equal(t, mgmtLinkKeys(ad.classic), kernel.command(mgmtOpLoadLinkKeys).data)
	require.Equal(t, mgmtLongTermKeys(ad.le), kernel.command(mgmtOpLoadLongTermKeys).data)
	require.Equal(t, mgmtIRKs(ad.le), kernel.command(mgmtOpLoadIRKs).data)
	require.Equal(t, []byte{0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, mgmtAddrBREDR, mgmtActionAllowIncoming},
		kernel.command(mgmtOpAddDevice).data)

	// a controller is set up once, even when it is listed and announced
	require.Nil(t, s.configureController(0))

	// and one the keyboards are not bonded to is left alone
	kernel.info = controllerInfo("AA:BB:CC:DD:EE:00", mgmtSettingBREDR|mgmtSettingLE)
	n := len(kernel.opcodes())
	require.Nil(t, s.configureController(1))
	require.Equal(t, []uint16{mgmtOpReadInfo}, kernel.opcodes()[n:])

	// shutting down powers off what the stack powered on
	s.close()
	require.Equal(t, uint16(mgmtOpSetPowered), kernel.opcodes()[len(kernel.opcodes())-1])
	require.Equal(t, []byte{0}, kernel.cmds[len(kernel.cmds)-1].data)
	require.Nil(t, s.configureController(2))
}

func TestConfigureControllerWithoutLE(t *testing.T) {
	t.Parallel()

	cfg := testBluetoothConfig()
	cfg.Adapters[0].Devices = cfg.Adapters[0].Devices[:1] // the BR/EDR keyboard only
	s := newBtStack(cfg)
	m, kernel := newFakeKernel(t)
	s.mgmt = m
	kernel.info = controllerInfo("00:1A:7D:DA:71:13", mgmtSettingBREDR|mgmtSettingSSP)
	kernel.status[mgmtOpSetPowered] = mgmtStatusRFKilled

	// rfkill leaves the keyboards unreachable, and is not retried
	require.Nil(t, s.configureController(0))
	require.Equal(t, []uint16{
		mgmtOpReadInfo, mgmtOpSetBondable, mgmtOpSetBREDR, mgmtOpSetSSP, mgmtOpLoadLinkKeys, mgmtOpSetPowered,
	}, kernel.opcodes())
}

func TestPairingIsTurnedDown(t *testing.T) {
	t.Parallel()

	s := newBtStack(testBluetoothConfig())
	m, kernel := newFakeKernel(t)
	s.mgmt = m
	btGo(s.eventLoop)

	addr := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, mgmtAddrBREDR}
	for _, tc := range []struct {
		event, reply uint16
		params       []byte
	}{
		{mgmtEvUserConfirmRequest, mgmtOpUserConfirmNegReply, []byte{0x01, 0x40, 0xe2, 0x01, 0x00}},
		{mgmtEvPinCodeRequest, mgmtOpPinCodeNegReply, []byte{0x00}},
		{mgmtEvUserPasskeyRequest, mgmtOpUserPasskeyNegReply, nil},
	} {
		kernel.event(tc.event, 0, append(append([]byte(nil), addr...), tc.params...))
		select {
		case p := <-kernel.got:
			require.Equal(t, tc.reply, p.code)
			require.Equal(t, addr, p.data)
		case <-time.After(5 * time.Second):
			t.Fatalf("event 0x%04x was not answered", tc.event)
		}
	}
}

func TestTrackClosesOnShutdown(t *testing.T) {
	t.Parallel()

	s := newBtStack(testBluetoothConfig())
	m, _ := newFakeKernel(t)
	s.mgmt = m

	a, _ := seqpacketPair(t)
	b, _ := seqpacketPair(t)
	untrack := s.track(a)
	_ = s.track(b)
	untrack()
	s.close()

	_, err := a.Write([]byte{1})
	require.NoError(t, err, "an untracked file stays open")
	_, err = b.Write([]byte{1})
	require.True(t, errors.Is(err, os.ErrClosed))

	c, _ := seqpacketPair(t)
	s.track(c)
	_, err = c.Write([]byte{1})
	require.True(t, errors.Is(err, os.ErrClosed), "a file tracked after shutdown is closed at once")

	start := time.Now()
	s.sleep(time.Minute)
	require.Less(t, time.Since(start), time.Second)
}

func TestBtGoRecovers(t *testing.T) {
	t.Parallel()

	done := make(chan struct{})
	btGo(func() {
		defer close(done)
		var m map[string]int
		m["panics"]++
	})
	<-done // and the test binary is still running
}
