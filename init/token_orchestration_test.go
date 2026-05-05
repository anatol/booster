package main

// Tests for the PIN-token classifier and serial-dispatch loop in luksOpen.
//
// The production loop is mirrored here as runPinTokens so it can be exercised
// without setting up real LUKS devices, swtpm, or hardware tokens. Cancellation
// uses a chan struct{} matching luksOpen's `done` channel.

import (
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/anatol/luks.go"
	"github.com/stretchr/testify/require"
)

// ── tokenNeedsPin ─────────────────────────────────────────────────────────────

func TestTokenNeedsPin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token luks.Token
		want  bool
	}{
		// systemd-tpm2 — only PIN when tpm2-pin == true
		{"tpm2 with PIN", luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-pin":true}`)}, true},
		{"tpm2 without PIN", luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-pin":false}`)}, false},
		{"tpm2 missing pin field", luks.Token{Type: "systemd-tpm2", Payload: []byte(`{}`)}, false},
		{"tpm2 malformed JSON", luks.Token{Type: "systemd-tpm2", Payload: []byte(`{not json`)}, false},
		{"tpm2 empty payload", luks.Token{Type: "systemd-tpm2", Payload: nil}, false},
		{"tpm2 with extra fields", luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-pin":true,"tpm2-pcrs":[7]}`)}, true},

		// systemd-fido2 — only PIN when fido2-clientPin-required == true
		{"fido2 with PIN required", luks.Token{Type: "systemd-fido2", Payload: []byte(`{"fido2-clientPin-required":true}`)}, true},
		{"fido2 touchless", luks.Token{Type: "systemd-fido2", Payload: []byte(`{"fido2-clientPin-required":false}`)}, false},
		{"fido2 missing field", luks.Token{Type: "systemd-fido2", Payload: []byte(`{}`)}, false},
		{"fido2 malformed JSON", luks.Token{Type: "systemd-fido2", Payload: []byte(`bad`)}, false},

		// non-PIN token types
		{"clevis", luks.Token{Type: "clevis", Payload: []byte(`{}`)}, false},
		{"systemd-recovery", luks.Token{Type: "systemd-recovery", Payload: []byte(`{}`)}, false},
		{"unknown type", luks.Token{Type: "weird-token", Payload: []byte(`{"tpm2-pin":true}`)}, false},
		{"empty type", luks.Token{Type: "", Payload: []byte(`{"tpm2-pin":true}`)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, tokenNeedsPin(tt.token), "token: %+v", tt.token)
		})
	}
}

// ── PIN-token serial loop ─────────────────────────────────────────────────────

// pinTokenSpec describes one token for runPinTokens. recoverFn is invoked when
// the token's iteration starts (PIN) or its parallel goroutine starts (non-PIN).
// It must observe done — production helpers (recoverSystemd*Password,
// plymouthAskPassword, readPassword) check done to return early on cancellation.
type pinTokenSpec struct {
	id        int
	pin       bool
	recoverFn func(done <-chan struct{}) bool
}

// orchestrationEvent records what happened to a token during a runPinTokens
// invocation. Order across distinct tokens reflects real concurrency; order
// within a single token's events is preserved.
type orchestrationEvent struct {
	id    int
	event string // "started", "completed", "skipped-done"
}

// runPinTokens mirrors the dispatch in luksOpen: non-PIN tokens fan out in
// parallel, PIN tokens are walked sequentially in slice order by one goroutine.
// Returns the recorded events.
func runPinTokens(specs []pinTokenSpec) []orchestrationEvent {
	var events []orchestrationEvent
	var mu sync.Mutex
	record := func(id int, ev string) {
		mu.Lock()
		events = append(events, orchestrationEvent{id, ev})
		mu.Unlock()
	}

	done := make(chan struct{})
	var closeDone sync.Once
	closeFn := func() { closeDone.Do(func() { close(done) }) }
	isDone := func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
	var senderWg sync.WaitGroup

	var pinSpecs []pinTokenSpec
	for _, t := range specs {
		if t.pin {
			pinSpecs = append(pinSpecs, t)
			continue
		}
		t := t
		senderWg.Add(1)
		go func() {
			defer senderWg.Done()
			if isDone() {
				record(t.id, "skipped-done")
				return
			}
			record(t.id, "started")
			ok := t.recoverFn(done)
			record(t.id, "completed")
			if ok {
				closeFn()
			}
		}()
	}

	if len(pinSpecs) > 0 {
		senderWg.Add(1)
		go func() {
			defer senderWg.Done()
			for _, t := range pinSpecs {
				if isDone() {
					record(t.id, "skipped-done")
					continue
				}
				record(t.id, "started")
				ok := t.recoverFn(done)
				record(t.id, "completed")
				if ok {
					closeFn()
					return
				}
			}
		}()
	}

	senderWg.Wait()
	return events
}

// orderOf returns each token id in the order its first event was recorded.
func orderOf(events []orchestrationEvent) []int {
	seen := make(map[int]bool)
	var out []int
	for _, e := range events {
		if !seen[e.id] {
			seen[e.id] = true
			out = append(out, e.id)
		}
	}
	return out
}

// eventOf returns the (first) event kind recorded for token id, or "" if none.
func eventOf(events []orchestrationEvent, id int) string {
	for _, e := range events {
		if e.id == id {
			return e.event
		}
	}
	return ""
}

// lastEventOf returns the most recent event kind recorded for token id, or ""
// if none. Use this to assert a token reached "completed" rather than just
// "started".
func lastEventOf(events []orchestrationEvent, id int) string {
	last := ""
	for _, e := range events {
		if e.id == id {
			last = e.event
		}
	}
	return last
}

func returns(success bool) func(<-chan struct{}) bool {
	return func(<-chan struct{}) bool { return success }
}

// ── PIN-loop ordering & sequencing ───────────────────────────────────────────

func TestPinTokensAllFailRunInOrder(t *testing.T) {
	t.Parallel()
	// Both PIN tokens fail (return false). The loop must run them in slice
	// order: token 1 fully completes before token 2 starts.
	events := runPinTokens([]pinTokenSpec{
		{id: 1, pin: true, recoverFn: returns(false)},
		{id: 2, pin: true, recoverFn: returns(false)},
	})
	require.Equal(t, []int{1, 2}, orderOf(events), "tokens must run in slice order")
	require.Equal(t, orchestrationEvent{1, "started"}, events[0])
	require.Equal(t, orchestrationEvent{1, "completed"}, events[1])
	require.Equal(t, orchestrationEvent{2, "started"}, events[2])
	require.Equal(t, orchestrationEvent{2, "completed"}, events[3])
}

func TestPinTokensFirstSuccessShortCircuitsRest(t *testing.T) {
	t.Parallel()
	// Token 1 succeeds → done closes → loop returns. Tokens 2 and 3 never
	// have their recoverFn invoked.
	events := runPinTokens([]pinTokenSpec{
		{id: 1, pin: true, recoverFn: returns(true)},
		{id: 2, pin: true, recoverFn: returns(false)},
		{id: 3, pin: true, recoverFn: returns(false)},
	})
	require.Equal(t, []int{1}, orderOf(events), "only token 1 must run")
	require.Equal(t, "completed", lastEventOf(events, 1))
}

func TestPinTokensMiddleSuccessShortCircuitsTrailingTokens(t *testing.T) {
	t.Parallel()
	// Token 1 fails → token 2 succeeds → token 3 must NOT run. Realistic
	// "tried TPM2-PIN, gave up, then FIDO2-PIN worked" scenario.
	events := runPinTokens([]pinTokenSpec{
		{id: 1, pin: true, recoverFn: returns(false)},
		{id: 2, pin: true, recoverFn: returns(true)},
		{id: 3, pin: true, recoverFn: returns(false)},
	})
	require.Equal(t, []int{1, 2}, orderOf(events))
	require.Equal(t, "", eventOf(events, 3), "token 3 must not have any event")
}

// ── non-PIN parallelism ──────────────────────────────────────────────────────

func TestNonPinTokensRunInParallelWithPinLoop(t *testing.T) {
	t.Parallel()
	// Non-PIN tokens (touchless FIDO2, clevis, auto TPM2) must NOT wait for
	// the PIN loop. A blocking PIN token must not delay a non-PIN token.
	nonPinDone := make(chan struct{})
	pinCanRelease := make(chan struct{})

	specs := []pinTokenSpec{
		{id: 1, pin: true, recoverFn: func(done <-chan struct{}) bool {
			<-pinCanRelease // block until test releases
			return false
		}},
		{id: 2, pin: false, recoverFn: func(done <-chan struct{}) bool {
			close(nonPinDone)
			return false
		}},
	}

	resultCh := make(chan []orchestrationEvent, 1)
	go func() { resultCh <- runPinTokens(specs) }()

	select {
	case <-nonPinDone:
	case <-time.After(2 * time.Second):
		t.Fatal("non-PIN token blocked by PIN loop — orchestration is wrong")
	}

	close(pinCanRelease)
	<-resultCh
}

func TestNonPinSuccessCancelsPinLoop(t *testing.T) {
	t.Parallel()
	// A non-PIN token (touchless FIDO2 / clevis / auto-TPM2) succeeding mid-
	// boot must close done so the still-running PIN goroutine exits without
	// dispatching the next prompt. The currently-running PIN token observes
	// done and returns false; subsequent PIN tokens skip via the done check.
	pinStarted := make(chan struct{})
	specs := []pinTokenSpec{
		{id: 1, pin: true, recoverFn: func(done <-chan struct{}) bool {
			close(pinStarted)
			<-done // production helpers observe done and return early
			return false
		}},
		{id: 2, pin: true, recoverFn: returns(false)},
		{id: 3, pin: false, recoverFn: func(done <-chan struct{}) bool {
			<-pinStarted // ensure PIN loop is in token 1's recoverFn
			return true  // non-PIN unlock wins
		}},
	}
	events := runPinTokens(specs)
	require.Equal(t, "completed", lastEventOf(events, 3), "non-PIN must complete with success")
	require.Equal(t, "completed", lastEventOf(events, 1), "PIN token 1 must have observed done and returned")
	require.Equal(t, "skipped-done", eventOf(events, 2), "PIN token 2 must skip after done")
}

// ── PIN-loop advance on skip / fallback errors ───────────────────────────────
//
// recoverTokenPassword (init/luks.go) maps errTPM2Skipped and
// errFido2FallbackToKeyboard to "false" returns, which must let the next PIN
// token in the loop run. This test verifies the loop does not short-circuit
// on a returns-false token regardless of the underlying reason.

func TestPinSkipReleasesNextPinToken(t *testing.T) {
	t.Parallel()
	// Token 1 = TPM2-PIN that user skips (returns false via errTPM2Skipped path).
	// Token 2 = FIDO2-PIN that succeeds. The loop must advance.
	events := runPinTokens([]pinTokenSpec{
		{id: 1, pin: true, recoverFn: returns(false)}, // simulates errTPM2Skipped
		{id: 2, pin: true, recoverFn: returns(true)},  // FIDO2 unlocks
	})
	require.Equal(t, []int{1, 2}, orderOf(events))
	require.Equal(t, "completed", lastEventOf(events, 2), "FIDO2 must run after TPM2 skip")
}

// ── sort-order determinism ────────────────────────────────────────────────────

func TestPinTokensProcessSortedInputInIDOrder(t *testing.T) {
	t.Parallel()
	// Tokens arrive in random map-iteration order [3,1,0,2,4] and are sorted
	// by ID before dispatch (the sort.Slice in luksOpen). The loop runs them
	// in ascending ID order [0,1,2,3,4].
	specs := []pinTokenSpec{
		{id: 3, pin: true, recoverFn: returns(false)},
		{id: 1, pin: true, recoverFn: returns(false)},
		{id: 0, pin: true, recoverFn: returns(false)},
		{id: 2, pin: true, recoverFn: returns(false)},
		{id: 4, pin: true, recoverFn: returns(false)},
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].id < specs[j].id })
	events := runPinTokens(specs)
	require.Equal(t, []int{0, 1, 2, 3, 4}, orderOf(events),
		"after sort, tokens must run in ascending ID order")
}

func TestPinTokensPreserveInputSliceOrderWhenUnsorted(t *testing.T) {
	t.Parallel()
	// runPinTokens itself does NOT sort — sorting is luksOpen's
	// responsibility (the sort.Slice before dispatch). This pins down that
	// split-of-concerns: given an unsorted slice, the loop processes it in
	// slice order without re-sorting.
	specs := []pinTokenSpec{
		{id: 3, pin: true, recoverFn: returns(false)},
		{id: 1, pin: true, recoverFn: returns(false)},
		{id: 0, pin: true, recoverFn: returns(false)},
		{id: 2, pin: true, recoverFn: returns(false)},
		{id: 4, pin: true, recoverFn: returns(false)},
	}
	events := runPinTokens(specs)
	require.Equal(t, []int{3, 1, 0, 2, 4}, orderOf(events),
		"without sort, loop must run tokens in input-slice order")
}
