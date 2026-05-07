package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Direct IPC client for plymouthd's abstract Unix socket.
//
// Plymouth is the graphical boot splash daemon used to render password
// prompts and progress messages during early boot:
// https://gitlab.freedesktop.org/plymouth/plymouth
//
// The wire protocol verbs and reply byte constants are defined upstream in
// src/libply-splash-core/ply-boot-protocol.h.
//
// Frame format for client → server commands:
//
//	[verb byte] [version = 2] [argLen byte] [argLen bytes, NUL-terminated]
//
// The server replies with a single byte for most verbs: 0x06 (ACK) on
// success, 0x15 (NAK) on failure. The ask-password verb '*' is the
// exception: the server replies with 0x02 (Answer) followed by
// [uint32 length, little-endian][password bytes, not NUL-terminated].
// plymouthAskPasswordSocket implements the answer-shaped exchange;
// plymouthCmd handles the ACK/NAK shape used by ping, message, quit, etc.
//
// Verb reference (full set from ply-boot-protocol.h; only the first six are
// exercised by booster — the rest are listed so future callers don't have
// to cross-reference upstream):
//
//	IMPLEMENTED
//	  P   PING                 plymouthPingOnce — readiness probe
//	  $   SHOW_SPLASH          shown once plymouthd is up
//	  *   PASSWORD             plymouthAskPasswordSocket (Answer reply)
//	  M   SHOW_MESSAGE         plymouthMessage — status text under the prompt
//	  Q   QUIT                 sent with retain-splash=1 at switchroot handoff
//	  R   NEWROOT              advertises the new root path to plymouthd
//
//	UNUSED (defined upstream, no booster caller)
//	  U   UPDATE               progress-bar percent
//	  C   CHANGE_MODE          boot/shutdown/updates/firmware-upgrade/etc
//	  u   SYSTEM_UPDATE        system-upgrade DM message
//	  S   SYSTEM_INITIALIZED   "userspace is up" signal
//	  D   DEACTIVATE           hand display ownership off (e.g. to systemd)
//	  r   REACTIVATE           reclaim display ownership
//	  l   RELOAD               re-read theme after handoff
//	  c   CACHED_PASSWORD      replay a previously-collected password
//	  W   QUESTION             free-form prompt (Answer-shaped reply)
//	  m   HIDE_MESSAGE         clear a message previously shown via M
//	  K   KEYSTROKE            subscribe to one keystroke
//	  L   KEYSTROKE_REMOVE     unsubscribe
//	  A   PROGRESS_PAUSE       freeze the throbber/progress-bar animation
//	  a   PROGRESS_UNPAUSE     resume it
//	  H   HIDE_SPLASH          (we use Q with retain=1 instead)
//	  V   HAS_ACTIVE_VT        boolean reply about VT ownership
//	  !   ERROR                push an error string into the splash
//
// Server response bytes:
//
//	0x06 ACK              success for command-shape verbs
//	0x15 NAK              failure for command-shape verbs
//	0x02 Answer           single answer (password/question reply)
//	0x09 Multiple-Answers answer list (rare; multi-line questions)
//	0x05 No-Answer        user dismissed the prompt without entering one

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
