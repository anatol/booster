package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	plymouthSocket = "\x00/org/freedesktop/plymouthd"
	plymouthACK    = '\x06'
	plymouthAnswer = '\x02'
)

func plymouthDial() (net.Conn, error) {
	return net.Dial("unix", plymouthSocket)
}

// plymouthSendRecv sends a raw frame and reads a 1-byte response.
func plymouthSendRecv(frame []byte) (byte, error) {
	conn, err := plymouthDial()
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	if _, err := conn.Write(frame); err != nil {
		return 0, err
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return 0, err
	}
	return resp[0], nil
}

// plymouthCmd sends a command with a NUL-terminated argument and expects ACK.
// Always encodes the argument — even an empty string — so plymouthd receives
// a non-NULL argument pointer. Callers that want a genuinely no-argument frame
// (e.g. ping, show-splash) should use plymouthSendRecv directly.
func plymouthCmd(typ byte, arg string) error {
	data := append([]byte(arg), 0) // NUL-terminate; "" becomes ['\0']
	if len(data) > 255 {
		data = data[:255]
	}
	frame := append([]byte{typ, 2, byte(len(data))}, data...)
	resp, err := plymouthSendRecv(frame)
	if err != nil {
		debug("plymouth: cmd %c failed: %v", rune(typ), err)
		return err
	}
	if resp != plymouthACK {
		debug("plymouth: cmd %c got NAK", rune(typ))
		return fmt.Errorf("plymouth NAK for %c", rune(typ))
	}
	return nil
}

// plymouthPingOnce attempts a single ping. Returns true on ACK.
func plymouthPingOnce() bool {
	resp, err := plymouthSendRecv([]byte{'P', 0})
	return err == nil && resp == plymouthACK
}

// plymouthAskPasswordSocket sends a password request and blocks until the user
// submits a password or ctx is cancelled. On cancellation the connection is
// closed; the goroutine returns cleanly either way. plymouthd builds whose
// connection-hangup handler tears down pending prompts also dismiss the
// on-screen UI on close — older builds release server-side state but leave
// the prompt UI visible until the splash is otherwise cleared.
func plymouthAskPasswordSocket(ctx context.Context, prompt string) ([]byte, error) {
	conn, err := plymouthDial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Close the connection when ctx fires so plymouthd observes the hangup.
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	// Guard against a cancelled context between dial and write — avoids sending
	// the frame (and flashing a prompt on screen) when the volume is already
	// being unlocked by another goroutine.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	data := append([]byte(prompt), 0)
	if len(data) > 255 {
		data = data[:255]
	}
	frame := append([]byte{'*', 2, byte(len(data))}, data...)
	if _, err := conn.Write(frame); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}

	var hdr [1]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if hdr[0] != plymouthAnswer {
		return nil, fmt.Errorf("plymouth: ask-password unexpected response %#x", hdr[0])
	}

	// Response: [uint32 length, little-endian][password bytes, not NUL-terminated]
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	size := binary.LittleEndian.Uint32(sizeBuf[:])
	if size > 4096 {
		return nil, fmt.Errorf("plymouth: ask-password response size too large: %d", size)
	}
	buf := make([]byte, size)
	if size > 0 {
		if _, err := io.ReadFull(conn, buf); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
	}
	return buf, nil
}
