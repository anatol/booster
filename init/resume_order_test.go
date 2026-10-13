package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestResumeOrderingWaitsForAttemptToFinish(t *testing.T) {
	r := newResumeAttempt()
	attemptStarted := make(chan struct{})
	finishAttempt := make(chan struct{})
	rootAllowed := make(chan error, 1)
	go func() { rootAllowed <- r.wait() }()

	// Root becoming ready before the resume device must not bypass the wait.
	select {
	case <-rootAllowed:
		t.Fatal("root was allowed before the resume device appeared")
	case <-time.After(20 * time.Millisecond):
	}

	go r.run(func() error {
		close(attemptStarted)
		<-finishAttempt
		return nil
	})
	<-attemptStarted
	select {
	case <-rootAllowed:
		t.Fatal("root was allowed while resume was still in progress")
	case <-time.After(20 * time.Millisecond):
	}

	close(finishAttempt)
	select {
	case err := <-rootAllowed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("root stayed blocked after the resume check returned")
	}
	// This also covers resume and root referring to the same device: the
	// resume call finishes first, and a subsequent wait must return at once.
	if err := r.wait(); err != nil {
		t.Fatal(err)
	}
}

func TestResumeOrderingRejectsRootOnAttemptError(t *testing.T) {
	r := newResumeAttempt()
	want := errors.New("resume device could not be checked")
	if err := r.run(func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("attempt returned %v, want %v", err, want)
	}
	if err := r.wait(); !errors.Is(err, want) {
		t.Fatalf("root wait returned %v, want %v", err, want)
	}
}

func TestResumeOrderingDoesNotRepeatForConcurrentEvents(t *testing.T) {
	r := newResumeAttempt()
	var calls atomic.Int32
	want := errors.New("first attempt result")
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.run(func() error {
				calls.Add(1)
				return want
			}); !errors.Is(err, want) {
				t.Errorf("duplicate event returned %v, want %v", err, want)
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 1 {
		t.Fatalf("resume attempted %d times, want once", got)
	}
}
