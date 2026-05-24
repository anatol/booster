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
