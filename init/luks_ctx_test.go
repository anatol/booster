package main

import (
	"context"
	"testing"
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
