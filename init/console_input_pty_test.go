package main

// PTY-harness tests for readPasswordOn — the testable core of
// readPasswordLocked. These exercise the headline behavior of K
// (raw-mode reader respecting ctx cancellation) end-to-end:
//
//   - actual termios setup on a real tty (the pty slave)
//   - Poll(100ms) loop reading bytes typed via the pty master
//   - ctx cancellation interrupts the loop within ~100ms
//   - termios state restored after return
//
// These tests run on Linux only — pty(7) is the kernel's
// implementation. booster is Linux-only so this is fine.

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// openPTY allocates a Linux pseudoterminal pair and returns (master, slave).
// Caller must close both.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	require.NoError(t, err, "open /dev/ptmx")

	// Unlock the slave (TIOCSPTLCK with int 0).
	require.NoError(t, unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0),
		"unlock pty slave")

	// Get slave number.
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	require.NoError(t, err, "get pty slave number")

	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	require.NoError(t, err, "open pty slave")

	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	return master, slave
}

// snapshotTermios returns the current termios settings of fd.
func snapshotTermios(t *testing.T, fd int) *unix.Termios {
	t.Helper()
	tio, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	require.NoError(t, err)
	return tio
}

// TestReadPasswordOnCtxCancelReturnsPromptly is the headline test for K:
// ctx.Done() interrupts a blocked readPasswordOn within ~100ms (the Poll
// timeout), the goroutine returns ctx.Err(), and termios is restored to its
// pre-call state.
func TestReadPasswordOnCtxCancelReturnsPromptly(t *testing.T) {
	master, slave := openPTY(t)

	preTermios := snapshotTermios(t, int(slave.Fd()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		password []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		password, err := readPasswordOn(ctx, slave, "Enter passphrase: ", "")
		done <- result{password, err}
	}()

	// Let the reader fully enter its Poll loop with raw-mode termios applied.
	// Without this small delay, a fast cancel can race with the termios setup
	// and the test asserts on a state that wasn't actually exercised.
	time.Sleep(50 * time.Millisecond)

	// Cancel the context — the reader should return within one Poll cycle (100ms).
	cancelStart := time.Now()
	cancel()

	select {
	case res := <-done:
		elapsed := time.Since(cancelStart)
		require.ErrorIs(t, res.err, context.Canceled,
			"reader must return ctx.Err() after cancellation")
		require.Empty(t, res.password,
			"no bytes were typed; password must be empty")
		require.Less(t, elapsed, 250*time.Millisecond,
			"reader must return within ~100ms (one Poll cycle); took %v", elapsed)
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not return within 2s of cancellation — Poll cycle is not honoring ctx")
	}

	// Termios must be restored to its pre-call state.
	postTermios := snapshotTermios(t, int(slave.Fd()))
	require.Equal(t, preTermios.Lflag, postTermios.Lflag,
		"termios Lflag must be restored after readPasswordOn returns")
	require.Equal(t, preTermios.Iflag, postTermios.Iflag,
		"termios Iflag must be restored after readPasswordOn returns")

	// Silence "unused" warning for the master end — it stays open via t.Cleanup.
	_ = master
}

// TestReadPasswordOnReadsTypedBytes verifies the read path actually receives
// bytes written to the master end of the pty, then returns the assembled
// password on Enter.
func TestReadPasswordOnReadsTypedBytes(t *testing.T) {
	master, slave := openPTY(t)

	ctx := t.Context()

	type result struct {
		password []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		password, err := readPasswordOn(ctx, slave, "Enter passphrase: ", "")
		done <- result{password, err}
	}()

	// Wait for the reader to install raw termios before we start "typing".
	time.Sleep(50 * time.Millisecond)

	// Type "secret" then press Enter.
	_, err := master.Write([]byte("secret\n"))
	require.NoError(t, err)

	select {
	case res := <-done:
		require.NoError(t, res.err)
		require.Equal(t, []byte("secret"), res.password)
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not return after typing 'secret\\n'")
	}
}

// TestReadPasswordOnBackspaceDeletesCodepoint verifies that one Backspace
// removes one full UTF-8 codepoint, not one byte. A regression that deletes
// only the trailing continuation byte would corrupt the password buffer
// silently — the user would type a multi-byte char, hit BS, and submit a
// password ending in an invalid byte sequence.
func TestReadPasswordOnBackspaceDeletesCodepoint(t *testing.T) {
	master, slave := openPTY(t)

	ctx := t.Context()

	type result struct {
		password []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		password, err := readPasswordOn(ctx, slave, "Enter passphrase: ", "")
		done <- result{password, err}
	}()

	time.Sleep(50 * time.Millisecond)

	// Type "héllo" (h=1B, é=2B, l=1B, l=1B, o=1B = 6 bytes / 5 codepoints),
	// then Backspace (deletes 'o'), then Enter. Expected: "héll" = 5 bytes.
	_, err := master.Write([]byte("héllo\b\n"))
	require.NoError(t, err)

	select {
	case res := <-done:
		require.NoError(t, res.err)
		require.Equal(t, []byte("héll"), res.password,
			"Backspace must remove one codepoint, not one byte")
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not return after typing 'héllo<BS>\\n'")
	}
}

// TestReadPasswordOnEmptyPassword verifies that pressing Enter on an empty
// prompt returns an empty password and no error. Booster uses this as the
// "skip" signal for PIN prompts, so the empty-vs-nil distinction matters.
func TestReadPasswordOnEmptyPassword(t *testing.T) {
	master, slave := openPTY(t)

	ctx := t.Context()

	type result struct {
		password []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		password, err := readPasswordOn(ctx, slave, "Enter passphrase: ", "")
		done <- result{password, err}
	}()

	time.Sleep(50 * time.Millisecond)

	// Just press Enter.
	_, err := master.Write([]byte("\n"))
	require.NoError(t, err)

	select {
	case res := <-done:
		require.NoError(t, res.err)
		require.Empty(t, res.password, "Enter on empty prompt must return empty password")
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not return after typing '\\n'")
	}
}

// TestReadPasswordOnEOFMidRead verifies that closing the master end mid-input
// breaks the read loop and returns whatever was typed so far without error.
// This mirrors what happens if the controlling terminal goes away mid-prompt.
func TestReadPasswordOnEOFMidRead(t *testing.T) {
	master, slave := openPTY(t)

	ctx := t.Context()

	type result struct {
		password []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		password, err := readPasswordOn(ctx, slave, "Enter passphrase: ", "")
		done <- result{password, err}
	}()

	time.Sleep(50 * time.Millisecond)

	// Type a few bytes, then close the master to trigger EOF on the slave.
	_, err := master.Write([]byte("abc"))
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)
	require.NoError(t, master.Close())

	select {
	case res := <-done:
		require.NoError(t, res.err, "EOF must not produce an error")
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not return within 2s of EOF on master")
	}
}

// TestReadPasswordOnCancelAfterPartialInput verifies the case where bytes have
// been typed but Enter has not been pressed: cancellation discards the partial
// input and returns ctx.Err() — the partial buffer is NOT returned as a
// password.
func TestReadPasswordOnCancelAfterPartialInput(t *testing.T) {
	master, slave := openPTY(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type result struct {
		password []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		password, err := readPasswordOn(ctx, slave, "Enter passphrase: ", "")
		done <- result{password, err}
	}()

	time.Sleep(50 * time.Millisecond)

	// Type partial input (no Enter).
	_, err := master.Write([]byte("partial"))
	require.NoError(t, err)

	// Give the reader time to consume the bytes.
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case res := <-done:
		require.ErrorIs(t, res.err, context.Canceled,
			"partial-input cancellation must return ctx.Err()")
		require.Empty(t, res.password,
			"partial input must not be returned as a password on cancellation")
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not return within 2s of cancellation")
	}
}
