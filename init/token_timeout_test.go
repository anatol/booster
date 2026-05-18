package main

// Tests for the serialize-mode per-token timeout helpers (secondsOr,
// perTokenTimeout) and the keyboard-fallback timer resolver
// (effectiveTokenTimeout). These are pure functions over the global config and
// a luksMapping, so they exercise the precedence rules without LUKS devices.

import (
	"context"
	"testing"
	"time"

	"github.com/anatol/luks.go"
	"github.com/stretchr/testify/require"
)

// withConfig swaps the global config for the duration of fn and restores it.
func withConfig(c InitConfig, fn func()) {
	saved := config
	config = c
	defer func() { config = saved }()
	fn()
}

func TestSecondsOr(t *testing.T) {
	t.Parallel()
	require.Equal(t, 10*time.Second, secondsOr(10, 45), "explicit cfg wins")
	require.Equal(t, 45*time.Second, secondsOr(0, 45), "0 falls back to default")
	require.Equal(t, 1*time.Second, secondsOr(1, 45), "smallest positive honoured")
}

func tok(typ, payload string) luks.Token {
	return luks.Token{Type: typ, Payload: []byte(payload)}
}

func TestPerTokenTimeout(t *testing.T) {
	clevis := tok("clevis", `{}`)
	tpm2 := tok("systemd-tpm2", `{"tpm2-pin":false}`)
	tpm2Pin := tok("systemd-tpm2", `{"tpm2-pin":true}`)
	fido2 := tok("systemd-fido2", `{"fido2-clientPin-required":false}`)
	fido2Pin := tok("systemd-fido2", `{"fido2-clientPin-required":true}`)
	unknown := tok("weird", `{}`)

	t.Run("serialize off → never bounded", func(t *testing.T) {
		withConfig(InitConfig{SerializeTokens: false}, func() {
			for _, tk := range []luks.Token{clevis, tpm2, fido2, fido2Pin, unknown} {
				require.Zero(t, perTokenTimeout(tk), "type %s", tk.Type)
			}
		})
	})

	t.Run("serialize on → type defaults", func(t *testing.T) {
		withConfig(InitConfig{SerializeTokens: true}, func() {
			require.Equal(t, 45*time.Second, perTokenTimeout(clevis))
			require.Equal(t, 15*time.Second, perTokenTimeout(tpm2))
			require.Equal(t, 30*time.Second, perTokenTimeout(fido2))
			require.Zero(t, perTokenTimeout(tpm2Pin), "PIN tpm2 exempt")
			require.Zero(t, perTokenTimeout(fido2Pin), "PIN fido2 exempt")
			require.Zero(t, perTokenTimeout(unknown), "unknown type unbounded")
		})
	})

	t.Run("serialize on → config overrides defaults", func(t *testing.T) {
		withConfig(InitConfig{SerializeTokens: true, ClevisTimeout: 90, Tpm2Timeout: 5, Fido2Timeout: 12}, func() {
			require.Equal(t, 90*time.Second, perTokenTimeout(clevis))
			require.Equal(t, 5*time.Second, perTokenTimeout(tpm2))
			require.Equal(t, 12*time.Second, perTokenTimeout(fido2))
			require.Zero(t, perTokenTimeout(tpm2Pin), "PIN still exempt despite config")
		})
	})
}

func TestEffectiveTokenTimeout(t *testing.T) {
	clevis := tok("clevis", `{}`)
	tpm2 := tok("systemd-tpm2", `{"tpm2-pin":false}`)
	tpm2Pin := tok("systemd-tpm2", `{"tpm2-pin":true}`)

	t.Run("explicit crypttab/cmdline wins over everything", func(t *testing.T) {
		m := &luksMapping{tokenTimeout: 7 * time.Second, tokenTimeoutExplicit: true}
		withConfig(InitConfig{SerializeTokens: true, TokenTimeout: 99}, func() {
			require.Equal(t, 7*time.Second, effectiveTokenTimeout(m, []luks.Token{clevis}))
		})
	})

	t.Run("booster.yaml token_timeout when not explicit", func(t *testing.T) {
		m := &luksMapping{tokenTimeout: 30 * time.Second} // implicit default, not explicit
		withConfig(InitConfig{SerializeTokens: true, TokenTimeout: 25}, func() {
			require.Equal(t, 25*time.Second, effectiveTokenTimeout(m, []luks.Token{clevis}))
		})
	})

	t.Run("serialize derived sum of per-token bounds", func(t *testing.T) {
		m := &luksMapping{tokenTimeout: 30 * time.Second} // implicit, ignored in serialize
		withConfig(InitConfig{SerializeTokens: true}, func() {
			// clevis 45 + tpm2 15 + PIN tpm2 0 = 60s
			got := effectiveTokenTimeout(m, []luks.Token{clevis, tpm2, tpm2Pin})
			require.Equal(t, 60*time.Second, got)
		})
	})

	t.Run("serialize, only PIN tokens → mapping default (keyboard-fallback safety net)", func(t *testing.T) {
		// Every serial token is PIN-bearing so the derived sum is 0. Returning
		// 0 here means tokenWg.Wait() with no timer; a FIDO2-PIN goroutine
		// parked on absent hardware would then never release the keyboard
		// fallback and the boot would hang. Must fall through to the mapping's
		// implicit default instead.
		m := &luksMapping{tokenTimeout: 30 * time.Second}
		withConfig(InitConfig{SerializeTokens: true}, func() {
			require.Equal(t, 30*time.Second, effectiveTokenTimeout(m, []luks.Token{tpm2Pin}))
		})
	})

	t.Run("non-serialize, nothing explicit → mapping implicit default", func(t *testing.T) {
		m := &luksMapping{tokenTimeout: 30 * time.Second}
		withConfig(InitConfig{SerializeTokens: false}, func() {
			require.Equal(t, 30*time.Second, effectiveTokenTimeout(m, nil))
		})
	})
}

// TestCtxSleep covers the wait primitive behind the pin_delay hold. The
// safety property of pin_delay is that a cancel-on-win (or a serialize-mode
// per-token timeout) during the hold aborts the sleep *immediately* so the
// PIN prompt is never drawn — that is the cancel cases below, not the
// timer-elapsed one.
func TestCtxSleep(t *testing.T) {
	t.Parallel()

	t.Run("timer elapses → nil after the full duration", func(t *testing.T) {
		t.Parallel()
		start := time.Now()
		require.NoError(t, ctxSleep(context.Background(), 30*time.Millisecond))
		require.GreaterOrEqual(t, time.Since(start), 30*time.Millisecond)
	})

	t.Run("already-cancelled ctx → returns immediately, prompt never held", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		require.ErrorIs(t, ctxSleep(ctx, time.Hour), context.Canceled)
		require.Less(t, time.Since(start), 50*time.Millisecond, "must not sleep out the hold")
	})

	t.Run("cancel-on-win during the hold → aborts well before the delay", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel() // a parallel non-interactive token won the race
		}()
		start := time.Now()
		require.ErrorIs(t, ctxSleep(ctx, time.Hour), context.Canceled)
		require.Less(t, time.Since(start), 200*time.Millisecond)
	})

	t.Run("deadline exceeded surfaces as the ctx error", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		require.ErrorIs(t, ctxSleep(ctx, time.Hour), context.DeadlineExceeded)
	})
}

func TestPinDelay(t *testing.T) {
	t.Run("unset → no delay", func(t *testing.T) {
		withConfig(InitConfig{}, func() {
			require.Zero(t, pinDelay(false, true))
		})
	})

	t.Run("set, concurrent, parallel token racing → delay applies", func(t *testing.T) {
		withConfig(InitConfig{PinDelay: 3}, func() {
			require.Equal(t, 3*time.Second, pinDelay(false, true))
		})
	})

	t.Run("set but serialize mode → no delay (strict ID order)", func(t *testing.T) {
		withConfig(InitConfig{PinDelay: 3}, func() {
			require.Zero(t, pinDelay(true, true))
		})
	})

	t.Run("set but no parallel token → no delay (nothing to wait for)", func(t *testing.T) {
		withConfig(InitConfig{PinDelay: 3}, func() {
			require.Zero(t, pinDelay(false, false))
		})
	})

	t.Run("negative config treated as off", func(t *testing.T) {
		withConfig(InitConfig{PinDelay: -1}, func() {
			require.Zero(t, pinDelay(false, true))
		})
	})
}
