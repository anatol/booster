package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAcquireKeyboardCanceledPreservesHolder(t *testing.T) {
	releaseHolder, ok := acquireKeyboard(context.Background())
	require.True(t, ok)
	t.Cleanup(func() {
		select {
		case <-keyboardSem:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	started := make(chan struct{})
	type acquisition struct {
		release func()
		ok      bool
	}
	done := make(chan acquisition, 1)
	go func() {
		close(started)
		release, ok := acquireKeyboard(ctx)
		done <- acquisition{release, ok}
	}()
	<-started
	cancel()
	var canceled acquisition
	select {
	case canceled = <-done:
	case <-time.After(time.Second):
		t.Fatal("keyboard acquisition did not return after cancellation")
	}
	require.False(t, canceled.ok)
	require.Len(t, keyboardSem, 1, "cancellation must preserve the current holder")

	canceled.release()
	canceled.release()
	require.Len(t, keyboardSem, 1, "releasing a failed acquisition must preserve the current holder")

	releaseHolder()
	require.Empty(t, keyboardSem)
}

func TestAcquireKeyboardReleasePreservesNextHolder(t *testing.T) {
	releaseFirst, ok := acquireKeyboard(context.Background())
	require.True(t, ok)
	t.Cleanup(func() {
		select {
		case <-keyboardSem:
		default:
		}
	})
	releaseFirst()
	require.Empty(t, keyboardSem)

	releaseNext, ok := acquireKeyboard(context.Background())
	require.True(t, ok, "release must allow the next keyboard acquisition")
	releaseFirst()
	require.Len(t, keyboardSem, 1, "repeated release must not steal the next holder's permit")

	releaseNext()
	require.Empty(t, keyboardSem)
}
