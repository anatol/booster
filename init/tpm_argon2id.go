package main

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
)

// tpm2Argon2idFields are the token fields of a systemd v262+ Argon2id PIN.
type tpm2Argon2idFields struct {
	Memcost    uint64 `json:"tpm2_argon2id_memcost"`
	Iterations uint32 `json:"tpm2_argon2id_iterations"`
	Lanes      uint32 `json:"tpm2_argon2id_lanes"`
}

// tpm2Argon2id holds the validated Argon2id cost of a PIN token.
type tpm2Argon2id struct {
	memcostBytes      uint64
	iterations, lanes uint32
}

// params mirrors the checks in systemd's tpm2_parse_luks2_json and
// kdf_argon2id_derive. It returns nil for a token without Argon2id fields.
func (f tpm2Argon2idFields) params(hasSalt bool) (*tpm2Argon2id, error) {
	if f.Memcost == 0 && f.Iterations == 0 && f.Lanes == 0 {
		return nil, nil
	}
	if f.Memcost == 0 || f.Iterations == 0 || f.Lanes == 0 {
		return nil, fmt.Errorf("incomplete Argon2id parameters in tpm2 token")
	}
	if !hasSalt {
		return nil, fmt.Errorf("Argon2id PIN requires tpm2_salt")
	}
	// x/crypto/argon2 takes the lane count as a uint8.
	if f.Lanes > math.MaxUint8 {
		return nil, fmt.Errorf("Argon2id lanes %d not supported", f.Lanes)
	}
	if f.Memcost/1024 > math.MaxUint32 {
		return nil, fmt.Errorf("Argon2id memory cost too large: %d bytes", f.Memcost)
	}
	var si unix.Sysinfo_t
	if unix.Sysinfo(&si) == nil && f.Memcost > si.Totalram*uint64(si.Unit) {
		return nil, fmt.Errorf("Argon2id memory cost %d exceeds physical memory", f.Memcost)
	}
	return &tpm2Argon2id{f.Memcost, f.Iterations, f.Lanes}, nil
}

// tpm2Argon2idPIN mirrors systemd's tpm2_argon2id_derive_split: the base64 of
// the second half of Argon2id(pin, salt) is the TPM PIN, the first half is kept
// for tpm2Argon2idVolumeKey.
func tpm2Argon2idPIN(pin, salt []byte, p tpm2Argon2id) (authValue, key1 []byte) {
	derived := argon2.IDKey(pin, salt, p.iterations, uint32(p.memcostBytes/1024), uint8(p.lanes), 64)
	defer wipe(derived)
	key1 = bytes.Clone(derived[:32])
	b64 := base64.StdEncoding.AppendEncode(nil, derived[32:])
	defer wipe(b64)
	return tpm2AuthFromPIN(b64), key1
}

// tpm2Argon2idVolumeKey mirrors systemd's tpm2_argon2id_hkdf.
func tpm2Argon2idVolumeKey(key1, unsealed []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, key1, unsealed, "systemd-tpm2-argon2id-lock", 32)
}
