package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

// sshHandshakeTimeout bounds how long a peer may hold a TCP connection open
// before completing the SSH handshake. Without it a slow-loris client can
// tie up goroutines until kernel TCP timeouts fire.
const sshHandshakeTimeout = 15 * time.Second

// sshMaxPromptAttempts caps wrong-passphrase tries per authenticated session.
// Bounds online brute-force against LUKS keyslots if the operator's private
// key has leaked. 10 is enough for human typos and well above what the unit
// tests submit (1 empty + 1 wrong + 1 correct in the retry case).
const sshMaxPromptAttempts = 10

var (
	sshState struct {
		sync.Mutex
		listener net.Listener
		conns    []net.Conn
		shutdown bool
	}
)

// sshRun parses keys, starts the SSH listener, and accepts connections until
// sshShutdown is called. Intended to be invoked as a goroutine.
func sshRun(cfg *InitNetworkConfig) {
	addr := cfg.SshListen
	if addr == "" {
		addr = ":22"
	}

	hostSigner, err := gossh.ParsePrivateKey([]byte(cfg.SshHostKey))
	if err != nil {
		warning("ssh: invalid host key: %v", err)
		return
	}

	authKeys, err := parseAuthorizedKeys([]byte(cfg.SshAuthorizedKeys))
	if err != nil {
		warning("ssh: %v", err)
		return
	}
	if len(authKeys) == 0 {
		warning("ssh: no valid authorized keys, not starting server")
		return
	}

	serverCfg := &gossh.ServerConfig{
		// Cap auth attempts per connection (matches gossh's default but
		// pinned explicitly so a future library change can't relax it
		// silently). Total online brute-force = MaxAuthTries * reconnects.
		MaxAuthTries: 6,
		// Don't leak the Go toolchain in the SSH banner — default is
		// "SSH-2.0-Go" which narrows targeting.
		ServerVersion: "SSH-2.0-booster",
		PublicKeyCallback: func(c gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			for _, k := range authKeys {
				if bytes.Equal(k.Marshal(), key.Marshal()) {
					info("ssh: %s authenticated as %q", c.RemoteAddr(), c.User())
					return nil, nil
				}
			}
			return nil, fmt.Errorf("unknown public key")
		},
	}
	serverCfg.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		warning("ssh: listen %s: %v", addr, err)
		return
	}

	sshState.Lock()
	if sshState.shutdown {
		sshState.Unlock()
		_ = listener.Close()
		return
	}
	sshState.listener = listener
	sshState.Unlock()

	info("ssh: listening on %s", addr)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				warning("ssh: accept: %v", err)
			}
			return
		}
		go sshHandleConn(conn, serverCfg)
	}
}

// sshShutdown closes the listener and all live connections. Safe to call when
// the server was never started.
func sshShutdown() {
	sshState.Lock()
	sshState.shutdown = true
	listener := sshState.listener
	conns := sshState.conns
	sshState.listener = nil
	sshState.conns = nil
	sshState.Unlock()

	if listener != nil {
		_ = listener.Close()
	}
	for _, c := range conns {
		_ = c.Close()
	}
}

func sshTrackConn(c net.Conn) bool {
	sshState.Lock()
	defer sshState.Unlock()
	if sshState.shutdown {
		return false
	}
	sshState.conns = append(sshState.conns, c)
	return true
}

func sshHandleConn(rawConn net.Conn, cfg *gossh.ServerConfig) {
	if !sshTrackConn(rawConn) {
		_ = rawConn.Close()
		return
	}
	defer rawConn.Close()

	// Slow-loris guard: drop the connection if the handshake doesn't
	// complete in sshHandshakeTimeout. Cleared on success so a live
	// session is bound only by the per-session prompt cap and natural
	// client disconnects.
	_ = rawConn.SetDeadline(time.Now().Add(sshHandshakeTimeout))
	conn, chans, reqs, err := gossh.NewServerConn(rawConn, cfg)
	if err != nil {
		debug("ssh: handshake from %s failed: %v", rawConn.RemoteAddr(), err)
		return
	}
	_ = rawConn.SetDeadline(time.Time{})
	defer conn.Close()
	go gossh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(gossh.UnknownChannelType, "only session channels supported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			debug("ssh: accept channel: %v", err)
			continue
		}
		go sshHandleSession(ch, chReqs, conn.RemoteAddr())
	}
}

// sshHandleSession waits for the client to send a shell, pty-req, or exec
// request, then drives the passphrase prompt. Any other request type is
// declined so the session is functionally restricted to the unlock flow.
func sshHandleSession(ch gossh.Channel, reqs <-chan *gossh.Request, remote net.Addr) {
	defer ch.Close()

	started := false
	for req := range reqs {
		switch req.Type {
		case "pty-req", "env":
			_ = req.Reply(true, nil)
		case "shell", "exec":
			if started {
				_ = req.Reply(false, nil)
				continue
			}
			started = true
			_ = req.Reply(true, nil)
			sshPromptLoop(ch, remote)
			// Inform the client we're done, then drain remaining requests.
			_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{0}))
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// sshPromptLoop reads passphrases from the client and submits them against
// every LUKS device currently waiting for unlock. The loop keeps running
// until pendingPrompts drains (every device unlocked), the client
// disconnects, or sshMaxPromptAttempts non-empty wrong submissions have
// been made — so a single SSH session can serve multiple devices with
// distinct passphrases instead of forcing a reconnect after each unlock.
func sshPromptLoop(ch gossh.Channel, remote net.Addr) {
	attempts := 0
	for {
		if attempts >= sshMaxPromptAttempts {
			_, _ = io.WriteString(ch, "Too many attempts, disconnecting.\r\n")
			return
		}
		names := pendingDeviceNames()
		if len(names) == 0 {
			_, _ = io.WriteString(ch, "All devices unlocked.\r\n")
			return
		}
		_, err := io.WriteString(ch, "Enter passphrase for "+strings.Join(names, ", ")+": ")
		if err != nil {
			return
		}
		pass, err := sshReadLine(ch)
		if err != nil {
			return
		}
		if len(pass) == 0 {
			continue
		}
		attempts++

		// Pre-render a status message before the KDF starts so it's visible
		// for the duration of the unlock attempt — the post-success message
		// otherwise only renders for ~100ms before clearSplashStatusSync
		// wipes it at switchRoot.
		statusMessage("Unlocking via SSH...")
		unlocked := trySubmitPassphraseToPending(pass)
		if len(unlocked) > 0 {
			for _, name := range unlocked {
				info("ssh: %s unlocked %s", remote, name)
				fmt.Fprintf(ch, "Unlocked: %s\r\n", name)
				statusMessage(name + " unlocked via SSH")
			}
			continue
		}
		statusMessage("")
		_, _ = io.WriteString(ch, "Passphrase did not unlock any device. Try again or disconnect.\r\n")
	}
}

// sshReadLine reads one line of input from the SSH channel without echoing,
// driving the same inputScanner FSM as the local console prompt
// (init/console_input.go). Sharing the scanner keeps both unlock paths
// byte-for-byte consistent: CSI/SS3/OSC/DCS escape sequences and
// bracketed-paste markers are stripped, multi-byte UTF-8 codepoints are
// reassembled across reads, and the line-editing keys (BS/DEL, Ctrl+U,
// Ctrl+W) behave identically to typing at the local console.
//
// Two intentional differences from the console reader, both because SSH
// is a different kind of connection than a local keyboard:
//   - No echo: the console prints an asterisk per character as you type;
//     over SSH we show nothing, so Tab (which toggles that masking on the
//     console) does nothing here.
//   - Ctrl+C: at the console the kernel turns Ctrl+C into a cancel signal
//     before our code ever sees the key, so the console reader never has
//     to handle it. SSH has no such kernel handling, so we watch for the
//     Ctrl+C byte (0x03) ourselves and abort. The exception is pasted
//     text: a 0x03 that arrives inside a paste is real content, not a
//     cancel, so we leave it alone there.
func sshReadLine(ch gossh.Channel) ([]byte, error) {
	var buf []byte
	var scanner inputScanner
	one := make([]byte, 1)
	for {
		n, err := ch.Read(one)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		b := one[0]
		if b == 0x03 && !scanner.inPaste { // Ctrl-C outside a paste aborts
			return nil, errors.New("interrupted")
		}
		ev, chars := scanner.Feed(b)
		switch ev {
		case keyEnter:
			_, _ = io.WriteString(ch, "\r\n")
			return buf, nil
		case keyEOF: // Ctrl-D: EOF on empty buffer, submit otherwise
			if len(buf) == 0 {
				return nil, errors.New("eof")
			}
			_, _ = io.WriteString(ch, "\r\n")
			return buf, nil
		case keyChar:
			buf = append(buf, chars...)
		case keyBackspace:
			buf = trimLastCodepoint(buf)
		case keyKillLine:
			buf = buf[:0]
		case keyKillWord:
			buf, _ = killWord(buf)
		case keyTab, keyNone:
			// keyTab: mask toggle is a console-only affordance (no SSH echo).
			// keyNone: byte consumed mid-sequence — nothing to emit.
		}
	}
}

// parseAuthorizedKeys parses an authorized_keys-format buffer into a slice of
// public keys, skipping blank lines and comments. Invalid lines abort with an
// error so misconfiguration is loud rather than silently weakening auth.
func parseAuthorizedKeys(data []byte) ([]gossh.PublicKey, error) {
	var keys []gossh.PublicKey
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		key, _, _, next, err := gossh.ParseAuthorizedKey(rest)
		if err != nil {
			return nil, fmt.Errorf("authorized_keys: %v", err)
		}
		keys = append(keys, key)
		rest = next
	}
	return keys, nil
}
