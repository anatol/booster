package main

import (
	"testing"

	luks "github.com/anatol/luks.go"
	"github.com/stretchr/testify/require"
)

// Gating decision for the PCR15 latch: default = extend iff a systemd-tpm2
// token binds PCR15; crypttab tpm2-measure-pcr= overrides (=yes force,
// =no suppress).

func TestTokenBindsPCR15(t *testing.T) {
	cases := []struct {
		name string
		tok  luks.Token
		want bool
	}{
		{"tpm2 binds 7+15", luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-pcrs":[7,15]}`)}, true},
		{"tpm2 binds 7 only", luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-pcrs":[7]}`)}, false},
		{"tpm2 binds nothing", luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-pcrs":[]}`)}, false},
		{"tpm2 no pcrs field", luks.Token{Type: "systemd-tpm2", Payload: []byte(`{}`)}, false},
		{"tpm2 malformed", luks.Token{Type: "systemd-tpm2", Payload: []byte(`{not json`)}, false},
		{"clevis token", luks.Token{Type: "clevis", Payload: []byte(`{"tpm2-pcrs":[15]}`)}, false},
		{"empty type", luks.Token{Type: "", Payload: []byte(`{"tpm2-pcrs":[15]}`)}, false},
	}
	for _, c := range cases {
		require.Equal(t, c.want, tokenBindsPCR15(c.tok), c.name)
	}
}

func TestVolumeKeyLatchMode(t *testing.T) {
	binds15 := luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-pcrs":[7,15]}`)}
	binds7 := luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-pcrs":[7]}`)}

	cases := []struct {
		name       string
		tokens     []luks.Token
		setting    measurePCRSetting
		tpmPresent bool
		want       latchMode
	}{
		// Forced and disabled ignore the token and the TPM probe.
		{"force, no tokens", nil, measurePCRForce, true, latchRequired},
		{"force, even with no TPM", nil, measurePCRForce, false, latchRequired},
		{"disabled, even if bound to 15", []luks.Token{binds15}, measurePCRDisabled, true, latchNone},
		// Auto with a PCR15-binding token: required (fail-closed), as before.
		{"auto, token binds 15", []luks.Token{binds15}, measurePCRAuto, true, latchRequired},
		{"auto, one of several binds 15", []luks.Token{binds7, binds15}, measurePCRAuto, true, latchRequired},
		// Auto, no PCR15 token: defensive when a TPM is present, none when not.
		{"auto, no PCR15 token, TPM present -> defensive", []luks.Token{binds7}, measurePCRAuto, true, latchDefensive},
		{"auto, no tokens, TPM present -> defensive", nil, measurePCRAuto, true, latchDefensive},
		{"auto, no tokens, no TPM -> none", nil, measurePCRAuto, false, latchNone},
		{"auto, token binds 7 only, no TPM -> none", []luks.Token{binds7}, measurePCRAuto, false, latchNone},
	}
	for _, c := range cases {
		require.Equal(t, c.want, volumeKeyLatchMode(c.tokens, c.setting, c.tpmPresent), c.name)
	}
}
