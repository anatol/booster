package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/anatol/luks.go"
	"github.com/google/go-tpm/tpmutil"
	"github.com/stretchr/testify/require"
)

func iesysBytes(handle uint32) []byte {
	b := make([]byte, 10)
	binary.BigEndian.PutUint32(b[0:4], 0x69657379) // magic
	binary.BigEndian.PutUint16(b[4:6], 1)          // version
	binary.BigEndian.PutUint32(b[6:10], handle)
	return b
}

func TestExtractSRKHandle(t *testing.T) {
	t.Parallel()

	// Well-formed bytes with standard systemd SRK handle.
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle(iesysBytes(0x81000001)))

	// Well-formed bytes with a non-standard persistent handle.
	require.Equal(t, tpmutil.Handle(0x81000002), extractSRKHandle(iesysBytes(0x81000002)))

	// Wrong magic → falls back to 0x81000001.
	bad := iesysBytes(0x81000099)
	binary.BigEndian.PutUint32(bad[0:4], 0xdeadbeef)
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle(bad))

	// Buffer too short → falls back to 0x81000001.
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle([]byte{0x69, 0x65, 0x73, 0x79}))

	// Empty → falls back to 0x81000001.
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle(nil))

	// Handle field is zero → falls back to 0x81000001.
	require.Equal(t, tpmutil.Handle(0x81000001), extractSRKHandle(iesysBytes(0)))
}

func TestTPM2PINAuthValue(t *testing.T) {
	t.Parallel()

	// No salt: authValue = SHA256_trimmed(pin)
	noSaltAuth := tpm2PINAuthValue([]byte("foo654"), nil)
	noSaltExpected, _ := hex.DecodeString("b45f7ebd746ed390f878184a49b08d17d4fbdeccc27e226675fd81c0a94aea21")
	require.Equal(t, noSaltExpected, noSaltAuth)

	// With salt (systemd v255+ salted PIN): authValue = SHA256_trimmed(base64(PBKDF2-HMAC-SHA256(pin, salt, 10000, 32)))
	// Values from actual systemd-tpm2-withpin.img token, pin = "foo654"
	salt, _ := base64.StdEncoding.DecodeString("8/ysu/pr1gnBowEfpa7sJjtk2Yky5LC2jC7grjOrX3s=")
	saltedAuth := tpm2PINAuthValue([]byte("foo654"), salt)
	saltedExpected, _ := hex.DecodeString("9c1a75519102e847b61bebe79f9052a92cbd754e6cd9903c714614a222741761")
	require.Equal(t, saltedExpected, saltedAuth)
}

func TestParseSystemdTPM2Blob(t *testing.T) {
	t.Parallel()

	private, public, err := parseSystemdTPM2Blob([]byte{
		0x00, 0x03,
		0x01, 0x02, 0x03,
		0x00, 0x02,
		0x04, 0x05,
	})
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02, 0x03}, private)
	require.Equal(t, []byte{0x04, 0x05}, public)
}

func TestParseSystemdTPM2BlobRejectsTruncatedData(t *testing.T) {
	t.Parallel()

	_, _, err := parseSystemdTPM2Blob([]byte{0x00})
	require.Error(t, err)

	_, _, err = parseSystemdTPM2Blob([]byte{0x00, 0x03, 0x01, 0x02})
	require.Error(t, err)

	_, _, err = parseSystemdTPM2Blob([]byte{0x00, 0x01, 0x01, 0x00, 0x02, 0x04})
	require.Error(t, err)
}

// withLuksGlobals saves and restores the package-global cmdRoot and luksMappings
// so each test can mutate them in isolation.
func withLuksGlobals(t *testing.T) {
	t.Helper()
	origRoot := cmdRoot
	origMappings := luksMappings
	t.Cleanup(func() {
		cmdRoot = origRoot
		luksMappings = origMappings
	})
}

// Regular-loop match where cmdRoot identifies the same LUKS partition:
// matchLuksMapping must rewrite cmdRoot to /dev/mapper/<m.name>. This is the
// crypttab-introduced regression scenario — without the rewrite, a crypttab
// entry covering the root LUKS UUID makes `root=UUID=<luks-uuid>` boot fail.
func TestMatchLuksMappingRewritesCmdRootOnRegularLoopMatch(t *testing.T) {
	withLuksGlobals(t)

	uuid, err := parseUUID("ab6d7d78-b816-4495-928d-766d6607035e")
	require.NoError(t, err)

	m := &luksMapping{
		ref:          &deviceRef{format: refFsUUID, data: uuid},
		name:         "cryptroot",
		keySlot:      -1,
		tokenTimeout: 30 * time.Second,
	}
	luksMappings = []*luksMapping{m}
	cmdRoot = &deviceRef{format: refFsUUID, data: uuid}

	blk := &blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid}
	got := matchLuksMapping(blk)
	require.Same(t, m, got)

	require.Equal(t, refPath, cmdRoot.format, "cmdRoot must be rewritten to a path-ref")
	require.Equal(t, "/dev/mapper/cryptroot", cmdRoot.data.(string))
}

// Regular-loop match where cmdRoot points at a *different* device:
// matchLuksMapping must return the matching mapping but leave cmdRoot alone.
// (e.g. swap or data partition unlocked while root lives elsewhere.)
func TestMatchLuksMappingLeavesCmdRootAloneWhenItDoesNotMatch(t *testing.T) {
	withLuksGlobals(t)

	swapUUID, err := parseUUID("ab6d7d78-b816-4495-928d-766d6607035e")
	require.NoError(t, err)
	rootUUID, err := parseUUID("7843d77f-cdd6-4289-a4de-a708c4aacede")
	require.NoError(t, err)

	swap := &luksMapping{
		ref:          &deviceRef{format: refFsUUID, data: swapUUID},
		name:         "cryptswap",
		keySlot:      -1,
		tokenTimeout: 30 * time.Second,
	}
	luksMappings = []*luksMapping{swap}

	rootRef := &deviceRef{format: refFsUUID, data: rootUUID}
	cmdRoot = rootRef

	blk := &blkInfo{path: "/dev/sda3", format: "luks", uuid: swapUUID}
	got := matchLuksMapping(blk)
	require.Same(t, swap, got)

	require.Same(t, rootRef, cmdRoot, "cmdRoot must be untouched when the matched mapping is not the root device")
}

// Synthesis-fallback path: no entry in luksMappings, but cmdRoot points at the
// LUKS partition. matchLuksMapping must synthesise a mapping named "root" and
// rewrite cmdRoot to /dev/mapper/root (autodiscoverable-partition behaviour).
func TestMatchLuksMappingSynthesisFallbackUnchanged(t *testing.T) {
	withLuksGlobals(t)

	uuid, err := parseUUID("7f28c723-fd6b-4640-bc94-9366edd8880d")
	require.NoError(t, err)

	luksMappings = nil
	rootRef := &deviceRef{format: refFsUUID, data: uuid}
	cmdRoot = rootRef

	blk := &blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid}
	got := matchLuksMapping(blk)
	require.NotNil(t, got)
	require.Equal(t, "root", got.name)
	require.Equal(t, -1, got.keySlot)
	require.Equal(t, 30*time.Second, got.tokenTimeout)
	require.Same(t, rootRef, got.ref, "synthesised mapping must keep the original cmdRoot ref")

	require.Equal(t, refPath, cmdRoot.format)
	require.Equal(t, "/dev/mapper/root", cmdRoot.data.(string))
}

// Regression guard for the "user wrote root=/dev/mapper/cryptroot themselves"
// case. blk is the underlying LUKS partition (/dev/sda2); cmdRoot is a path-ref
// to the future mapper node. matchesRef compares paths/symlinks, so it returns
// false — the rewrite branch must not fire, and cmdRoot must be preserved.
func TestMatchLuksMappingPreservesExplicitMapperPath(t *testing.T) {
	withLuksGlobals(t)

	uuid, err := parseUUID("ab6d7d78-b816-4495-928d-766d6607035e")
	require.NoError(t, err)

	m := &luksMapping{
		ref:          &deviceRef{format: refFsUUID, data: uuid},
		name:         "cryptroot",
		keySlot:      -1,
		tokenTimeout: 30 * time.Second,
	}
	luksMappings = []*luksMapping{m}

	mapperRef := &deviceRef{format: refPath, data: "/dev/mapper/cryptroot"}
	cmdRoot = mapperRef

	blk := &blkInfo{path: "/dev/sda2", format: "luks", uuid: uuid}
	got := matchLuksMapping(blk)
	require.Same(t, m, got)
	require.Same(t, mapperRef, cmdRoot, "explicit /dev/mapper/... cmdRoot must not be rewritten")
}

// No mapping and cmdRoot does not match the device: matchLuksMapping returns
// nil and leaves cmdRoot alone (the device is just not ours to unlock).
func TestMatchLuksMappingNoMatchReturnsNil(t *testing.T) {
	withLuksGlobals(t)

	blkUUID, err := parseUUID("ab6d7d78-b816-4495-928d-766d6607035e")
	require.NoError(t, err)
	rootUUID, err := parseUUID("7843d77f-cdd6-4289-a4de-a708c4aacede")
	require.NoError(t, err)

	luksMappings = nil
	rootRef := &deviceRef{format: refFsUUID, data: rootUUID}
	cmdRoot = rootRef

	blk := &blkInfo{path: "/dev/sdb1", format: "luks", uuid: blkUUID}
	require.Nil(t, matchLuksMapping(blk))
	require.Same(t, rootRef, cmdRoot)
}

// unreachableMapperName fires only when cmdRoot is /dev/mapper/<name> and no
// luksMapping covers <name>. Any other shape is silent so we don't spam LVM
// or RAID setups.
func TestUnreachableMapperName(t *testing.T) {
	cases := []struct {
		desc     string
		root     *deviceRef
		mappings []*luksMapping
		wantName string
		wantOK   bool
	}{
		{
			desc:     "root=/dev/mapper/cryptroot with empty luksMappings",
			root:     &deviceRef{format: refPath, data: "/dev/mapper/cryptroot"},
			wantName: "cryptroot",
			wantOK:   true,
		},
		{
			desc:   "no cmdRoot",
			root:   nil,
			wantOK: false,
		},
		{
			desc:   "root=UUID=… is silent",
			root:   &deviceRef{format: refFsUUID, data: UUID{}},
			wantOK: false,
		},
		{
			desc:   "root=/dev/sda1 (non-mapper path) is silent",
			root:   &deviceRef{format: refPath, data: "/dev/sda1"},
			wantOK: false,
		},
		{
			desc:     "root=/dev/mapper/cryptroot WITHOUT covering mapping",
			root:     &deviceRef{format: refPath, data: "/dev/mapper/cryptroot"},
			mappings: []*luksMapping{{name: "swap"}},
			wantName: "cryptroot",
			wantOK:   true,
		},
		{
			desc:     "root=/dev/mapper/cryptroot WITH covering mapping",
			root:     &deviceRef{format: refPath, data: "/dev/mapper/cryptroot"},
			mappings: []*luksMapping{{name: "cryptroot"}},
			wantOK:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			withLuksGlobals(t)
			cmdRoot = tc.root
			luksMappings = tc.mappings
			name, ok := unreachableMapperName()
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantName, name)
		})
	}
}

// withPendingPrompts isolates the pendingPrompts global across tests so a
// failure in one case doesn't leave stale registrations visible to another.
func withPendingPrompts(t *testing.T) {
	t.Helper()
	pendingPrompts.Lock()
	orig := pendingPrompts.entries
	pendingPrompts.entries = nil
	pendingPrompts.Unlock()
	t.Cleanup(func() {
		pendingPrompts.Lock()
		pendingPrompts.entries = orig
		pendingPrompts.Unlock()
	})
}

func TestPendingPromptsRegistry(t *testing.T) {
	withPendingPrompts(t)

	a := &promptRegistration{mappingName: "alpha"}
	b := &promptRegistration{mappingName: "beta"}

	registerPendingPrompt(a)
	registerPendingPrompt(b)

	pendingPrompts.Lock()
	require.Equal(t, 2, len(pendingPrompts.entries))
	pendingPrompts.Unlock()

	unregisterPendingPrompt(a)
	pendingPrompts.Lock()
	_, hasA := pendingPrompts.entries[a]
	_, hasB := pendingPrompts.entries[b]
	pendingPrompts.Unlock()
	require.False(t, hasA, "alpha should have been removed")
	require.True(t, hasB, "beta should remain")

	// unregistering an unknown entry must be a no-op
	unregisterPendingPrompt(&promptRegistration{mappingName: "ghost"})
	pendingPrompts.Lock()
	require.Equal(t, 1, len(pendingPrompts.entries))
	pendingPrompts.Unlock()
}

func TestPendingPromptsConcurrent(t *testing.T) {
	// Hammer the registry from multiple goroutines so -race can flag any
	// missing locking. The registry backs the SSH unlock path, where
	// register/unregister races against trySubmitPassphraseToPending's
	// snapshot are the primary concern.
	withPendingPrompts(t)

	const N = 200
	regs := make([]*promptRegistration, N)
	for i := range regs {
		regs[i] = &promptRegistration{mappingName: "dev"}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for _, r := range regs {
			registerPendingPrompt(r)
		}
	}()
	go func() {
		defer wg.Done()
		for _, r := range regs {
			unregisterPendingPrompt(r)
		}
	}()
	wg.Wait()

	// Drain whatever's left so we don't leak into other tests; the exact
	// residue is non-deterministic (races between register/unregister).
	pendingPrompts.Lock()
	for r := range pendingPrompts.entries {
		delete(pendingPrompts.entries, r)
	}
	pendingPrompts.Unlock()
}

// TestPendingPromptsInflightFence pins the race fence that prevents
// luksOpen's watcher from closing the volumes channel while an SSH
// submission is mid-UnsealVolume.
//
// Without this fence the bug is: senderWg.Wait() returns (all in-band
// senders gave up), watcher calls close(volumes), an SSH goroutine that
// snapshot-grabbed the entry under pendingPrompts.Lock a moment earlier
// then completes its UnsealVolume and reaches tryPassphraseAgainstSlots's
// `case volumes <- v:` — panic "send on closed channel" in pid 1.
//
// The fence is two coordinated mutations:
//   - trySubmitPassphraseToPending Add()s to reg.inflight inside the same
//     critical section that iterates pendingPrompts.entries.
//   - The watcher first removes reg from pendingPrompts.entries (blocking
//     new snapshots from picking us up), then waits on reg.inflight before
//     closing volumes.
//
// This test mirrors both halves directly and asserts the watcher blocks
// for as long as a snapshotted submitter has not yet completed.
func TestPendingPromptsInflightFence(t *testing.T) {
	withPendingPrompts(t)

	reg := &promptRegistration{
		ctx:         context.Background(),
		mappingName: "fence-test",
	}
	registerPendingPrompt(reg)

	// Submitter snapshot — same critical-section shape as
	// trySubmitPassphraseToPending. Add to inflight under the lock so the
	// watcher cannot remove-and-wait while a new submitter is still
	// transitioning from "saw the entry" to "Add(1)".
	pendingPrompts.Lock()
	snapshot := make([]*promptRegistration, 0, len(pendingPrompts.entries))
	for p := range pendingPrompts.entries {
		require.NoError(t, p.ctx.Err())
		p.inflight.Add(1)
		snapshot = append(snapshot, p)
	}
	pendingPrompts.Unlock()
	require.Len(t, snapshot, 1)

	// Watcher role: delete the entry under the lock, then wait for any
	// already-snapshotted submitter to drain. Must block — we haven't
	// called Done yet.
	watcherDone := make(chan struct{})
	go func() {
		pendingPrompts.Lock()
		delete(pendingPrompts.entries, reg)
		pendingPrompts.Unlock()
		reg.inflight.Wait()
		close(watcherDone)
	}()

	select {
	case <-watcherDone:
		t.Fatal("watcher unblocked before submitter's inflight reference released — fence missing")
	case <-time.After(100 * time.Millisecond):
		// expected: watcher must wait
	}

	// The watcher must have removed the entry before waiting so a later
	// submitter cannot snapshot a now-doomed registration.
	pendingPrompts.Lock()
	_, present := pendingPrompts.entries[reg]
	pendingPrompts.Unlock()
	require.False(t, present, "watcher should have removed entry before waiting on inflight")

	// Submitter completes its UnsealVolume + channel send. Watcher must
	// unblock immediately after.
	reg.inflight.Done()

	select {
	case <-watcherDone:
		// expected
	case <-time.After(time.Second):
		t.Fatal("watcher did not unblock after inflight reached zero")
	}
}

// fenceFakeLuksDevice satisfies luks.Device for the production-path fence
// test. Only UnsealVolume is exercised; everything else is a no-op stub.
type fenceFakeLuksDevice struct {
	unseal func(keyslot int, passphrase []byte) (*luks.Volume, error)
}

func (f *fenceFakeLuksDevice) UnsealVolume(keyslot int, passphrase []byte) (*luks.Volume, error) {
	return f.unseal(keyslot, passphrase)
}
func (f *fenceFakeLuksDevice) Close() error                                              { return nil }
func (f *fenceFakeLuksDevice) Version() int                                              { return 2 }
func (f *fenceFakeLuksDevice) Path() string                                              { return "/dev/fake" }
func (f *fenceFakeLuksDevice) UUID() string                                              { return "" }
func (f *fenceFakeLuksDevice) Slots() []int                                              { return []int{0} }
func (f *fenceFakeLuksDevice) Tokens() ([]luks.Token, error)                             { return nil, nil }
func (f *fenceFakeLuksDevice) FlagsGet() []string                                        { return nil }
func (f *fenceFakeLuksDevice) FlagsAdd(flags ...string) error                            { return nil }
func (f *fenceFakeLuksDevice) FlagsClear()                                               {}
func (f *fenceFakeLuksDevice) Unlock(keyslot int, passphrase []byte, dmName string) error {
	return nil
}
func (f *fenceFakeLuksDevice) UnlockAny(passphrase []byte, dmName string) error { return nil }

// TestTrySubmitPassphraseToPendingHoldsInflight pins that the production
// trySubmitPassphraseToPending bumps reg.inflight before UnsealVolume runs
// and only releases it after the dispatched goroutine completes. This is
// the producer half of the race fence (TestPendingPromptsInflightFence
// covers the synchronization property; this test catches future regressions
// that drop the Add(1) or move the Done() earlier).
func TestTrySubmitPassphraseToPendingHoldsInflight(t *testing.T) {
	withPendingPrompts(t)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	fake := &fenceFakeLuksDevice{
		unseal: func(_ int, _ []byte) (*luks.Volume, error) {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
			return &luks.Volume{}, nil
		},
	}

	// Buffered so tryPassphraseAgainstSlots's `case volumes <- v:` sends
	// without needing a consumer goroutine; we're testing the inflight
	// lifecycle, not the unlock-orchestration consumer side.
	volumes := make(chan *luks.Volume, 1)
	reg := &promptRegistration{
		ctx:         context.Background(),
		cancel:      func() {},
		volumes:     volumes,
		d:           fake,
		checkSlots:  []int{0},
		mappingName: "producer-test",
	}
	registerPendingPrompt(reg)

	submitDone := make(chan struct{})
	go func() {
		defer close(submitDone)
		trySubmitPassphraseToPending([]byte("any"))
	}()

	// Wait for UnsealVolume to enter — by which point trySubmitPassphraseToPending
	// has already taken the pendingPrompts lock, called Add(1), released the
	// lock, and dispatched the inner goroutine.
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("UnsealVolume never entered; trySubmitPassphraseToPending stalled")
	}

	// inflight must be >0 — verify by spawning a Wait()er and asserting it
	// blocks while UnsealVolume is hung.
	waitDone := make(chan struct{})
	go func() {
		reg.inflight.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("reg.inflight at zero while UnsealVolume hung — Add(1) missing or Done() premature")
	case <-time.After(100 * time.Millisecond):
		// expected
	}

	// Let UnsealVolume return. The dispatched goroutine's deferred Done()
	// drops inflight to zero; our Wait()er unblocks.
	close(release)

	select {
	case <-waitDone:
		// expected
	case <-time.After(time.Second):
		t.Fatal("inflight did not drop to zero after UnsealVolume returned")
	}

	<-submitDone
	require.Len(t, volumes, 1, "volume should have been sent on the channel")
}

// TestTrySubmitPassphraseCancelsRegistrationOnSuccess pins that a successful
// SSH submission cancels the unlocked device's ctx synchronously — before
// trySubmitPassphraseToPending returns. Without this, sshPromptLoop's next
// pendingDeviceNames() snapshot still lists the just-unlocked device for the
// window between volume-send and luksOpen's deferred unregister, and the
// operator sees the already-unlocked mapping name on the reprompt.
//
// Property: after a successful submission, pendingDeviceNames() must not
// include the unlocked entry, because ctx.Err() is non-nil. Removing
// p.cancel() from trySubmitPassphraseToPending's success branch fails this.
func TestTrySubmitPassphraseCancelsRegistrationOnSuccess(t *testing.T) {
	withPendingPrompts(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	fake := &fenceFakeLuksDevice{
		unseal: func(_ int, _ []byte) (*luks.Volume, error) {
			return &luks.Volume{}, nil
		},
	}
	// Buffered so the send in tryPassphraseAgainstSlots completes without a
	// luksOpen-style consumer.
	volumes := make(chan *luks.Volume, 1)
	reg := &promptRegistration{
		ctx:         ctx,
		cancel:      cancel,
		volumes:     volumes,
		d:           fake,
		checkSlots:  []int{0},
		mappingName: "cancel-on-success",
	}
	registerPendingPrompt(reg)

	unlocked := trySubmitPassphraseToPending([]byte("anything"))
	require.Equal(t, []string{"cancel-on-success"}, unlocked)

	require.Error(t, reg.ctx.Err(),
		"ctx must be cancelled by trySubmitPassphraseToPending on success")

	names := pendingDeviceNames()
	require.NotContains(t, names, "cancel-on-success",
		"pendingDeviceNames must drop entries whose ctx is cancelled")
}

func TestUnmarshalTPM2Field(t *testing.T) {
	// the common, non-sharded case: a single JSON string
	v, sharded, err := unmarshalTPM2Field([]byte(`"aGVsbG8="`))
	require.NoError(t, err)
	require.False(t, sharded)
	require.Equal(t, "aGVsbG8=", v)

	// sharded array (signed-PCR + pcrlock combined enrollment) -> first shard + sharded
	v, sharded, err = unmarshalTPM2Field([]byte(`["aaaa","bbbb"]`))
	require.NoError(t, err)
	require.True(t, sharded)
	require.Equal(t, "aaaa", v)

	// single-element array -> not sharded
	v, sharded, err = unmarshalTPM2Field([]byte(`["only"]`))
	require.NoError(t, err)
	require.False(t, sharded)
	require.Equal(t, "only", v)

	// absent / null -> empty, no error
	for _, raw := range [][]byte{nil, []byte("null"), []byte(" ")} {
		v, sharded, err = unmarshalTPM2Field(raw)
		require.NoError(t, err)
		require.False(t, sharded)
		require.Equal(t, "", v)
	}
}

// TestRecoverSystemdTPM2RejectsPcrlock pins that a pcrlock-bound token (which
// booster cannot satisfy — it needs PolicyAuthorizeNV) is rejected with a clear
// message before any TPM work, instead of the cryptic JSON-unmarshal error the
// sharded array form used to produce.
func TestRecoverSystemdTPM2RejectsPcrlock(t *testing.T) {
	// sharded tpm2-blob (array) = signed-PCR + pcrlock combined enrollment
	shardedTok := luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-blob":["AA==","BB=="],"tpm2-policy-hash":["dead","beef"],"tpm2-pcrs":[7]}`)}
	_, err := recoverSystemdTPM2Password(context.Background(), shardedTok, "cryptroot", "")
	require.ErrorContains(t, err, "pcrlock")

	// pcrlock-only token (single blob, tpm2_pcrlock=true)
	pcrlockTok := luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-blob":"AA==","tpm2_pcrlock":true}`)}
	_, err = recoverSystemdTPM2Password(context.Background(), pcrlockTok, "cryptroot", "")
	require.ErrorContains(t, err, "pcrlock")
}
