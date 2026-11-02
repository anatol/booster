package main

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func TestSshPromptLoopUnlocksSequentialZfsRoots(t *testing.T) {
	withPendingPrompts(t)
	resetZfsHarness(t)
	setZfsUnlockDiscovery(true)

	execZfsLoadKey = func(ctx context.Context, dataset string, password []byte) (bool, error) {
		return string(password) == dataset+"-key", nil
	}
	askKeyboardPassword = func(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ch := &fakeChannel{in: bytes.NewBufferString("tank/first-key\rtank/second-key\r")}
	reqs := make(chan *gossh.Request)
	sshDone := make(chan struct{})
	go func() {
		defer close(sshDone)
		sshPromptLoop(ch, reqs, &fakeAddr{})
	}()
	var loaders sync.WaitGroup
	t.Cleanup(func() {
		close(reqs)
		setZfsUnlockDiscovery(false)
		pendingPrompts.Lock()
		for reg := range pendingPrompts.entries {
			reg.cancel()
		}
		pendingPrompts.Unlock()
		loaders.Wait()
		<-sshDone
	})

	waitForDiscovery := func() {
		t.Helper()
		// The unbuffered request can only be received while the loop is waiting
		// with no pending prompt, proving it survives each discovery gap.
		select {
		case reqs <- &gossh.Request{WantReply: false}:
		case <-sshDone:
			t.Fatal("SSH session ended before ZFS discovery completed")
		case <-time.After(time.Second):
			t.Fatal("SSH session did not wait for ZFS discovery")
		}
	}

	waitForDiscovery()
	for _, dataset := range []string{"tank/first", "tank/second"} {
		loaded := make(chan error, 1)
		loaders.Go(func() { loaded <- loadZfsKey(dataset) })
		select {
		case err := <-loaded:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatalf("SSH did not unlock %s", dataset)
		}
		waitForDiscovery()
	}
	setZfsUnlockDiscovery(false)
	select {
	case <-sshDone:
	case <-time.After(time.Second):
		t.Fatal("SSH session did not finish after ZFS discovery")
	}

	for _, dataset := range []string{"tank/first", "tank/second"} {
		require.Contains(t, ch.out.String(), "Enter passphrase for "+dataset+": ")
		require.Contains(t, ch.out.String(), "Unlocked: "+dataset+"\r\n")
	}
	require.Contains(t, ch.out.String(), "All devices unlocked.\r\n")
	require.NotContains(t, ch.out.String(), "Passphrase did not unlock any device")
}

func TestSshPromptLoopDisconnectsDuringZfsDiscovery(t *testing.T) {
	withPendingPrompts(t)
	setZfsUnlockDiscovery(true)
	t.Cleanup(func() { setZfsUnlockDiscovery(false) })

	ch := &fakeChannel{in: &bytes.Buffer{}}
	reqs := make(chan *gossh.Request)
	sshDone := make(chan struct{})
	go func() {
		defer close(sshDone)
		sshPromptLoop(ch, reqs, &fakeAddr{})
	}()
	close(reqs)
	select {
	case <-sshDone:
	case <-time.After(time.Second):
		t.Fatal("SSH session did not exit when its channel closed")
	}
	require.NotContains(t, ch.out.String(), "All devices unlocked")
}
