package main

// Tests for the PIN-token classifier and serial-dispatch loop in luksOpen.
//
// The production loop is mirrored here as runPinTokens so it can be exercised
// without setting up real LUKS devices, swtpm, or hardware tokens. Cancellation
// uses context.Context matching luksOpen's `ctx`.

import (
	"context"
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
// It must observe ctx — production helpers (recoverSystemd*Password,
// plymouthAskPassword, readPassword) check ctx to return early on cancellation.
type pinTokenSpec struct {
	id        int
	pin       bool
	recoverFn func(ctx context.Context) bool
}

// orchestrationEvent records what happened to a token during a runPinTokens
// invocation. Order across distinct tokens reflects real concurrency; order
// within a single token's events is preserved.
type orchestrationEvent struct {
	id    int
	event string // "started", "completed", "skipped-done"
}

// runPinTokens mirrors the dispatch in luksOpen with serialize_tokens off:
// non-PIN tokens fan out in parallel, PIN tokens are walked sequentially in
// slice order by one goroutine.
func runPinTokens(specs []pinTokenSpec) []orchestrationEvent {
	return runTokens(specs, false)
}

// runTokens mirrors the token dispatch in luksOpen. When serialize is false,
// non-PIN tokens fan out in parallel and only PIN tokens serialize. When
// serialize is true, every token serializes (the serialize_tokens opt-out of
// booster's token concurrency) — matching the `serialize || tokenNeedsPin(t)`
// gate in luksOpen. Returns the recorded events.
func runTokens(specs []pinTokenSpec, serialize bool) []orchestrationEvent {
	var events []orchestrationEvent
	var mu sync.Mutex
	record := func(id int, ev string) {
		mu.Lock()
		events = append(events, orchestrationEvent{id, ev})
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	isDone := func() bool {
		select {
		case <-ctx.Done():
			return true
		default:
			return false
		}
	}
	var senderWg sync.WaitGroup

	var pinSpecs []pinTokenSpec
	for _, t := range specs {
		if serialize || t.pin {
			pinSpecs = append(pinSpecs, t)
			continue
		}
		t := t
		senderWg.Go(func() {
			if isDone() {
				record(t.id, "skipped-done")
				return
			}
			record(t.id, "started")
			ok := t.recoverFn(ctx)
			record(t.id, "completed")
			if ok {
				cancel()
			}
		})
	}

	if len(pinSpecs) > 0 {
		senderWg.Go(func() {
			for _, t := range pinSpecs {
				if isDone() {
					record(t.id, "skipped-done")
					continue
				}
				record(t.id, "started")
				ok := t.recoverFn(ctx)
				record(t.id, "completed")
				if ok {
					cancel()
					return
				}
			}
		})
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

func returns(success bool) func(context.Context) bool {
	return func(context.Context) bool { return success }
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
	// Token 1 succeeds → ctx cancelled → loop returns. Tokens 2 and 3 never
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
		{id: 1, pin: true, recoverFn: func(ctx context.Context) bool {
			<-pinCanRelease // block until test releases
			return false
		}},
		{id: 2, pin: false, recoverFn: func(ctx context.Context) bool {
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
	// boot must cancel ctx so the still-running PIN goroutine exits without
	// dispatching the next prompt. The currently-running PIN token observes
	// ctx cancellation and returns false; subsequent PIN tokens skip via the
	// ctx check.
	pinStarted := make(chan struct{})
	specs := []pinTokenSpec{
		{id: 1, pin: true, recoverFn: func(ctx context.Context) bool {
			close(pinStarted)
			<-ctx.Done() // production helpers observe ctx and return early
			return false
		}},
		{id: 2, pin: true, recoverFn: returns(false)},
		{id: 3, pin: false, recoverFn: func(ctx context.Context) bool {
			<-pinStarted // ensure PIN loop is in token 1's recoverFn
			return true  // non-PIN unlock wins
		}},
	}
	events := runPinTokens(specs)
	require.Equal(t, "completed", lastEventOf(events, 3), "non-PIN must complete with success")
	require.Equal(t, "completed", lastEventOf(events, 1), "PIN token 1 must have observed ctx cancel and returned")
	require.Equal(t, "skipped-done", eventOf(events, 2), "PIN token 2 must skip after ctx cancel")
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

// ── serialize_tokens opt-out ─────────────────────────────────────────────────
//
// With serialize_tokens set, luksOpen routes every token (including non-PIN
// clevis / touchless-FIDO2 / auto-TPM2) through the single serial loop. These
// tests assert that opt-out: no parallel fan-out, strict slice-order, and the
// short-circuit-on-success behaviour still holds.

func TestSerializeTokensRunsNonPinTokensSerially(t *testing.T) {
	t.Parallel()
	// All three tokens are non-PIN. Without serialize they would fan out in
	// parallel; with serialize each must fully complete before the next starts.
	specs := []pinTokenSpec{
		{id: 1, pin: false, recoverFn: returns(false)},
		{id: 2, pin: false, recoverFn: returns(false)},
		{id: 3, pin: false, recoverFn: returns(false)},
	}
	events := runTokens(specs, true)
	require.Equal(t, []int{1, 2, 3}, orderOf(events), "serialize must run tokens in slice order")
	require.Equal(t, []orchestrationEvent{
		{1, "started"}, {1, "completed"},
		{2, "started"}, {2, "completed"},
		{3, "started"}, {3, "completed"},
	}, events, "serialize must not interleave non-PIN tokens")
}

func TestSerializeTokensNonPinSuccessShortCircuits(t *testing.T) {
	t.Parallel()
	// A non-PIN token succeeding under serialize must cancel the loop so
	// trailing tokens never run — same short-circuit as the PIN loop.
	specs := []pinTokenSpec{
		{id: 1, pin: false, recoverFn: returns(false)},
		{id: 2, pin: false, recoverFn: returns(true)},
		{id: 3, pin: false, recoverFn: returns(false)},
	}
	events := runTokens(specs, true)
	require.Equal(t, []int{1, 2}, orderOf(events))
	require.Equal(t, "", eventOf(events, 3), "token 3 must not run after a serial success")
}

func TestSerializeTokensBlockingTokenDelaysNext(t *testing.T) {
	t.Parallel()
	// Under serialize a blocking non-PIN token (e.g. clevis waiting on the
	// network) must hold up the next token — proving there is no parallel
	// goroutine. This is the deliberate trade-off of opting out of concurrency.
	release := make(chan struct{})
	secondStarted := make(chan struct{})
	specs := []pinTokenSpec{
		{id: 1, pin: false, recoverFn: func(ctx context.Context) bool {
			<-release
			return false
		}},
		{id: 2, pin: false, recoverFn: func(ctx context.Context) bool {
			close(secondStarted)
			return false
		}},
	}
	resultCh := make(chan []orchestrationEvent, 1)
	go func() { resultCh <- runTokens(specs, true) }()

	select {
	case <-secondStarted:
		t.Fatal("token 2 started before token 1 finished — serialize is not serial")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	<-resultCh
}
