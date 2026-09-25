package main

import "sync"

// A successful restore never returns to this initramfs. If no image exists,
// the attempt returns normally and root mounting may proceed. A missing
// resume device keeps root mounting blocked; a configured mount timeout still applies.
type resumeAttempt struct {
	once sync.Once
	done chan struct{}
	err  error
}

func newResumeAttempt() *resumeAttempt {
	return &resumeAttempt{done: make(chan struct{})}
}

var bootResume = newResumeAttempt()

func (r *resumeAttempt) run(attempt func() error) error {
	// Duplicate discovery events must not start another resume after root mount.
	r.once.Do(func() {
		r.err = attempt()
		close(r.done)
	})
	return r.err
}

func (r *resumeAttempt) wait() error {
	<-r.done
	return r.err
}
