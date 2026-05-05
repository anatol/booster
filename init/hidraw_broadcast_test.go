package main

// Tests for the hidraw listener broadcast registry in init/luks.go.
//
// hidrawDevices used to be a single global channel shared across every FIDO2
// goroutine. A udev `add hidraw` event was a single push — the first goroutine
// to read won the device and siblings starved. This caused the "touchless
// FIDO2 never blinks unless first found" bug: with one PIN-required FIDO2 and
// one touchless FIDO2 against the same physical device, only one of the two
// recoverSystemdFido2Password goroutines ever saw the device.
//
// The fix replaces the global channel with a registry of per-goroutine
// listeners; udev events are broadcast to every registered listener so each
// FIDO2 token's recover loop sees every device-add independently.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The TestHidrawBroadcast* tests share the global hidrawListeners registry,
// so they cannot run in parallel — listeners registered by one test would
// receive broadcasts from another.

func TestHidrawBroadcastDeliversToAllListeners(t *testing.T) {
	a, dropA := registerHidrawListener()
	defer dropA()
	b, dropB := registerHidrawListener()
	defer dropB()

	broadcastHidrawDevice("hidraw0")

	select {
	case got := <-a:
		require.Equal(t, "hidraw0", got)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("listener A never received the broadcast")
	}
	select {
	case got := <-b:
		require.Equal(t, "hidraw0", got)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("listener B never received the broadcast")
	}
}

func TestHidrawBroadcastDoesNotBlockOnSlowListener(t *testing.T) {
	// A listener whose buffer fills up must not stall broadcasts to siblings.
	a, dropA := registerHidrawListener()
	defer dropA()
	for range cap(a) {
		a <- "filler"
	}
	b, dropB := registerHidrawListener()
	defer dropB()

	done := make(chan struct{})
	go func() {
		broadcastHidrawDevice("hidraw1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("broadcast blocked on a full listener buffer")
	}

	select {
	case got := <-b:
		require.Equal(t, "hidraw1", got)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("sibling listener never received the broadcast despite A being full")
	}
}

func TestHidrawBroadcastIgnoresDroppedListener(t *testing.T) {
	a, dropA := registerHidrawListener()
	dropA() // drop immediately

	broadcastHidrawDevice("hidraw2")
	select {
	case got := <-a:
		t.Fatalf("dropped listener should not receive broadcasts; got %q", got)
	case <-time.After(100 * time.Millisecond):
		// expected — no delivery
	}
}

func TestHidrawBroadcastDeliversMultipleEvents(t *testing.T) {
	// A listener receives every broadcast in order, not just the first one.
	a, dropA := registerHidrawListener()
	defer dropA()

	for _, name := range []string{"hidraw0", "hidraw1", "hidraw2"} {
		broadcastHidrawDevice(name)
	}

	for _, want := range []string{"hidraw0", "hidraw1", "hidraw2"} {
		select {
		case got := <-a:
			require.Equal(t, want, got)
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("listener never received %q", want)
		}
	}
}

func TestHidrawBroadcastEmptyRegistryIsNoop(t *testing.T) {
	// Broadcast with zero registered listeners must not panic or block.
	// Realistic for the brief window after init starts and before any FIDO2
	// goroutine has registered.
	done := make(chan struct{})
	go func() {
		broadcastHidrawDevice("hidraw3")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("broadcast to empty registry blocked")
	}
}
