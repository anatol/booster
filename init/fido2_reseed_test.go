package main

// Tests for reseedTouchlessFido2 — the gate-and-send helper that implements
// touch-anytime FIDO2 retry (project plan item N).
//
// When a touchless FIDO2 device returns a non-fatal error, the goroutine
// re-seeds the device back into its own listener channel so the recover
// loop tries again. The user can then touch the token at any point during
// boot — including while a passphrase prompt is showing — and the unlock
// succeeds without further intervention.
//
// Three gates protect against misuse:
//   1. !pinRequired   — PIN tokens have engaged the user via prompt; silent
//                        re-seed would be confusing.
//   2. elapsed > 1s   — bounds hot-loops on fast-fail libfido2 errors.
//   3. ctx not done   — sibling-token win cancels parent ctx; don't keep
//                        re-seeding into a doomed channel.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReseedHappyPath(t *testing.T) {
	// Touchless device, slow assertion (>1s elapsed), live ctx → re-seeds:
	// listener receives devName and seen[devName] is cleared.
	ctx := context.Background()
	listener := make(chan string, 1)
	seen := set{"hidraw0": true}

	err := reseedTouchlessFido2(ctx, listener, "hidraw0", seen, false, 2*time.Second)
	require.NoError(t, err)

	select {
	case got := <-listener:
		require.Equal(t, "hidraw0", got)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("re-seed should have delivered to listener")
	}
	require.False(t, seen["hidraw0"], "re-seed must clear seen[devName] so the outer loop accepts the redelivery")
}

func TestReseedSkippedForPinRequired(t *testing.T) {
	// PIN tokens drive their own user interaction via prompts; silent re-seed
	// behind their back would confuse the prompt state machine. Gate skips.
	ctx := context.Background()
	listener := make(chan string, 1)
	seen := set{"hidraw0": true}

	err := reseedTouchlessFido2(ctx, listener, "hidraw0", seen, true, 5*time.Second)
	require.NoError(t, err)

	select {
	case got := <-listener:
		t.Fatalf("PIN-required tokens must not re-seed; got %q", got)
	case <-time.After(50 * time.Millisecond):
		// expected — gate skipped
	}
	require.True(t, seen["hidraw0"], "seen must NOT be cleared when re-seed is skipped")
}

func TestReseedSkippedOnFastFail(t *testing.T) {
	// Fast-fail errors (immediate libfido2 rejections) return in microseconds.
	// Without the elapsed-time gate, re-seed would hot-loop the device back
	// into the listener channel and burn CPU.
	ctx := context.Background()
	listener := make(chan string, 1)
	seen := set{"hidraw0": true}

	err := reseedTouchlessFido2(ctx, listener, "hidraw0", seen, false, 100*time.Millisecond)
	require.NoError(t, err)

	select {
	case got := <-listener:
		t.Fatalf("fast-fail must not re-seed; got %q", got)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
	require.True(t, seen["hidraw0"], "seen must NOT be cleared on fast-fail skip")
}

func TestReseedSkippedAtGateBoundary(t *testing.T) {
	// Boundary: elapsed == 1s exactly is treated as fast-fail (gate uses
	// strict >, not >=). Pinned to keep the gate semantics explicit.
	ctx := context.Background()
	listener := make(chan string, 1)
	seen := set{"hidraw0": true}

	err := reseedTouchlessFido2(ctx, listener, "hidraw0", seen, false, time.Second)
	require.NoError(t, err)

	select {
	case got := <-listener:
		t.Fatalf("elapsed==1s must not re-seed (gate is strict >); got %q", got)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

func TestReseedReturnsCtxErrWhenCancelledBeforeCall(t *testing.T) {
	// Sibling token wins → ctx cancelled. Helper observes and returns ctx.Err
	// without sending. Caller (recoverSystemdFido2Password) propagates by
	// returning early.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	listener := make(chan string, 1)
	seen := set{"hidraw0": true}

	err := reseedTouchlessFido2(ctx, listener, "hidraw0", seen, false, 2*time.Second)
	require.ErrorIs(t, err, context.Canceled)

	select {
	case got := <-listener:
		t.Fatalf("cancelled ctx must not send; got %q", got)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
	require.True(t, seen["hidraw0"], "seen must NOT be cleared when ctx already cancelled")
}

func TestReseedReturnsCtxErrWhenCancelledDuringSend(t *testing.T) {
	// Listener buffer is full; send blocks. ctx cancellation must unblock
	// the helper and return ctx.Err. Without the select, the goroutine
	// would deadlock holding fido2Mu.
	ctx, cancel := context.WithCancel(context.Background())
	listener := make(chan string, 1)
	listener <- "filler" // saturate the buffer
	seen := set{"hidraw0": true}

	done := make(chan error, 1)
	go func() {
		done <- reseedTouchlessFido2(ctx, listener, "hidraw0", seen, false, 2*time.Second)
	}()

	// Briefly let the helper enter the select{}, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("helper did not return after ctx cancel — likely deadlocked")
	}

	// Note: seen[devName] WAS cleared (the gate passed before ctx cancel),
	// but the device wasn't re-seeded into the channel. This is benign —
	// the goroutine returns ctx.Err immediately after, so the cleared map
	// is discarded.
	require.False(t, seen["hidraw0"], "seen is cleared before the send attempt — caller exits via ctx.Err so the asymmetry is benign")
}
