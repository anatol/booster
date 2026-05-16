package main

// Tests for the serialize-mode per-token timeout helpers (secondsOr,
// perTokenTimeout) and the keyboard-fallback timer resolver
// (effectiveTokenTimeout). These are pure functions over the global config and
// a luksMapping, so they exercise the precedence rules without LUKS devices.

import (
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

	t.Run("serialize, only PIN tokens → 0 (wait on tokenWg)", func(t *testing.T) {
		m := &luksMapping{tokenTimeout: 30 * time.Second}
		withConfig(InitConfig{SerializeTokens: true}, func() {
			require.Zero(t, effectiveTokenTimeout(m, []luks.Token{tpm2Pin}))
		})
	})

	t.Run("non-serialize, nothing explicit → mapping implicit default", func(t *testing.T) {
		m := &luksMapping{tokenTimeout: 30 * time.Second}
		withConfig(InitConfig{SerializeTokens: false}, func() {
			require.Equal(t, 30*time.Second, effectiveTokenTimeout(m, nil))
		})
	})
}
