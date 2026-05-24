package main

import (
	"context"
	"testing"
	"time"
)

func TestWaitForUsbhidRespectsCtxCancel(t *testing.T) {
	// Reset package state so the test is order-independent.
	usbhidReady = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForUsbhid(ctx); err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestAcquireFido2LockRespectsCtxCancel(t *testing.T) {
	// Drain to a known-empty state, then pre-fill so the next acquire must wait.
	select {
	case <-fido2Sem:
	default:
	}
	fido2Sem <- struct{}{}
	t.Cleanup(func() { <-fido2Sem })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := acquireFido2Lock(ctx); err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestWaitForUsbhidReturnsOnSignal(t *testing.T) {
	usbhidReady = make(chan struct{})

	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- waitForUsbhid(ctx) }()

	time.AfterFunc(10*time.Millisecond, func() { close(usbhidReady) })

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waitForUsbhid did not return after signal")
	}
}

func TestAcquireFido2LockReturnsOnRelease(t *testing.T) {
	// Drain then pre-fill so the next acquire must wait.
	select {
	case <-fido2Sem:
	default:
	}
	fido2Sem <- struct{}{}

	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- acquireFido2Lock(ctx) }()

	time.AfterFunc(10*time.Millisecond, releaseFido2Lock)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		t.Cleanup(releaseFido2Lock) // drain the slot the test left filled.
	case <-time.After(time.Second):
		t.Fatal("acquireFido2Lock did not return after release")
	}
}
