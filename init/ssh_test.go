package main

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/anatol/luks.go"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

// fakeChannel is a minimal gossh.Channel backed by an in-memory reader for
// client input and a buffer capturing what the server writes back. Only the
// methods sshReadLine touches are functional.
type fakeChannel struct {
	in  io.Reader
	out bytes.Buffer
}

func (c *fakeChannel) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *fakeChannel) Write(p []byte) (int, error) { return c.out.Write(p) }
func (c *fakeChannel) Close() error                { return nil }
func (c *fakeChannel) CloseWrite() error           { return nil }
func (c *fakeChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (c *fakeChannel) Stderr() io.ReadWriter { return &bytes.Buffer{} }

// TestSshReadLineSharesScanner pins the payoff of routing SSH bytes through
// the same inputScanner as the console: pasted escape/control bytes can't
// corrupt a passphrase, edit keys work, and the two documented divergences
// (Ctrl-C handling, paste-literal control bytes) behave as commented.
func TestSshReadLineSharesScanner(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"plain line", "secret\r", "secret", false},
		{"LF terminator", "secret\n", "secret", false},
		{"arrow key stripped", "se\x1b[Dcret\r", "secret", false},
		{"OSC sequence stripped", "se\x1b]0;title\x07cret\r", "secret", false},
		{"backspace edits buffer", "sx\x7f\x7fecret\r", "ecret", false},
		// User mistypes, backspaces to fix, finishes the correct passphrase:
		// the submitted buffer must equal the real passphrase so it unlocks.
		{"backspace corrects a typo (DEL)", "secX\x7fret\r", "secret", false},
		{"backspace corrects a typo (BS 0x08)", "secX\x08ret\r", "secret", false},
		{"backspace on empty buffer is harmless", "\x7f\x7fsecret\r", "secret", false},
		{"ctrl-u kills line", "junk\x15secret\r", "secret", false},
		{"utf-8 multibyte preserved", "café\r", "café", false},
		{"bracketed paste keeps literal ctrl byte", "\x1b[200~pa\x03ss\x1b[201~\r", "pa\x03ss", false},
		{"pasted passphrase then enter", "\x1b[200~Tr0ub4dor&3\x1b[201~\r", "Tr0ub4dor&3", false},
		{"ctrl-c outside paste aborts", "abc\x03", "", true},
		{"ctrl-d on empty aborts", "\x04", "", true},
		{"ctrl-d with buffer submits", "secret\x04", "secret", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ch := &fakeChannel{in: bytes.NewReader([]byte(tc.input))}
			got, err := sshReadLine(ch)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, string(got))
		})
	}
}

var _ gossh.Channel = (*fakeChannel)(nil)

func TestParseAuthorizedKeys(t *testing.T) {
	t.Parallel()

	// A valid ssh-ed25519 line for use across cases (public key only).
	const validKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIaELDfV8WnFiKK9XyXkk3RYHpx9Lv2nGtPYGcEC91YE test@example"

	for _, tc := range []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{"empty", "", 0, false},
		{"whitespace only", "   \n\n  \t\n", 0, false},
		{"single key with newline", validKey + "\n", 1, false},
		{"single key no trailing newline", validKey, 1, false},
		{"CRLF line endings", validKey + "\r\n" + validKey + "\r\n", 2, false},
		{"two keys with comment between", validKey + "\n# comment\n" + validKey + "\n", 2, false},
		{"trailing whitespace around key", "  " + validKey + "  \n", 1, false},
		{"garbage line", "this is not a key\n", 0, true},
		{"unknown key type", "ssh-unknown AAAAB3NzaC1yc2E= test\n", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keys, err := parseAuthorizedKeys([]byte(tc.input))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, len(keys), "expected %d key(s), got %d", tc.want, len(keys))
		})
	}
}

func TestParseAuthorizedKeysSkipsGarbageBetweenValidKeys(t *testing.T) {
	// gossh.ParseAuthorizedKey follows sshd(8) and silently skips
	// unparseable lines once at least one valid key has been seen. Pin
	// that behavior so a stray bad line doesn't lock the user out.
	t.Parallel()

	const validKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIaELDfV8WnFiKK9XyXkk3RYHpx9Lv2nGtPYGcEC91YE test@example"
	input := validKey + "\nthis is garbage\n" + validKey + "\n"
	keys, err := parseAuthorizedKeys([]byte(input))
	require.NoError(t, err)
	require.Equal(t, 2, len(keys))
}

// TestSshPromptLoopDisconnectsAfterMaxAttempts pins the per-session
// brute-force bound. Without this cap, an authenticated peer can submit
// arbitrarily many wrong passphrases over a single SSH session — an
// online oracle against LUKS keyslots whenever the operator's private
// key has leaked.
//
// Setup: register one fake device whose UnsealVolume always reports
// "passphrase does not match", feed sshMaxPromptAttempts+5 non-empty
// wrong submissions, and assert exactly sshMaxPromptAttempts prompts
// are emitted (one per attempt the loop processed) and the final output
// is the "Too many attempts" disconnect line.
func TestSshPromptLoopDisconnectsAfterMaxAttempts(t *testing.T) {
	withPendingPrompts(t)

	fake := &fenceFakeLuksDevice{
		unseal: func(int, []byte) (*luks.Volume, error) {
			return nil, luks.ErrPassphraseDoesNotMatch
		},
	}
	reg := &promptRegistration{
		ctx:         context.Background(),
		cancel:      func() {},
		volumes:     make(chan *luks.Volume, 1), // never sent on for this test
		d:           fake,
		checkSlots:  []int{0},
		mappingName: "cap-test",
	}
	registerPendingPrompt(reg)

	var input bytes.Buffer
	for range sshMaxPromptAttempts + 5 {
		input.WriteString("wrong\r")
	}
	ch := &fakeChannel{in: &input}

	addr := &fakeAddr{}
	sshPromptLoop(ch, addr)

	got := ch.out.String()
	gotPrompts := bytes.Count([]byte(got), []byte("Enter passphrase for cap-test: "))
	require.Equal(t, sshMaxPromptAttempts, gotPrompts,
		"expected exactly sshMaxPromptAttempts prompts, got %d", gotPrompts)
	require.Contains(t, got, "Too many attempts, disconnecting.",
		"loop should print the cap-reached message and return")
}

// fakeAddr satisfies net.Addr for sshPromptLoop's logging side-effects.
type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "127.0.0.1:0" }
