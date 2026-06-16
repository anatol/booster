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

func TestShouldMeasureVolumeKey(t *testing.T) {
	binds15 := luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-pcrs":[7,15]}`)}
	binds7 := luks.Token{Type: "systemd-tpm2", Payload: []byte(`{"tpm2-pcrs":[7]}`)}

	cases := []struct {
		name    string
		tokens  []luks.Token
		setting measurePCRSetting
		want    bool
	}{
		{"force, no tokens", nil, measurePCRForce, true},
		{"force, even if not bound", []luks.Token{binds7}, measurePCRForce, true},
		{"disabled, even if bound to 15", []luks.Token{binds15}, measurePCRDisabled, false},
		{"auto, token binds 15", []luks.Token{binds15}, measurePCRAuto, true},
		{"auto, token binds 7 only", []luks.Token{binds7}, measurePCRAuto, false},
		{"auto, no tokens", nil, measurePCRAuto, false},
		{"auto, one of several binds 15", []luks.Token{binds7, binds15}, measurePCRAuto, true},
	}
	for _, c := range cases {
		require.Equal(t, c.want, shouldMeasureVolumeKey(c.tokens, c.setting), c.name)
	}
}
