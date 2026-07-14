package main

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// verifyPassword reports whether pw matches a systemd/argon2-CLI style argon2id
// PHC string: $argon2id$v=19$m=<KiB>,t=<iter>,p=<lanes>$<b64salt>$<b64hash>.
// The params are read from the hash itself; base64 is unpadded (argon2 CLI).
func verifyPassword(phc string, pw []byte) (bool, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("not an argon2id PHC string")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, fmt.Errorf("unsupported argon2 version %q", parts[2])
	}
	var mem, iter, par int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &par); err != nil {
		return false, fmt.Errorf("bad argon2 params %q: %v", parts[3], err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("bad salt: %v", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("bad hash: %v", err)
	}
	got := argon2.IDKey(pw, salt, uint32(iter), uint32(mem), uint8(par), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// authorizeEmergencyShell decides whether the emergency shell may start. An empty
// hash keeps the historical behaviour (no gate). Otherwise it prompts up to tries
// times and reports success; a read error or a malformed hash denies access
// (fail closed — a broken hash must not grant a root shell).
func authorizeEmergencyShell(hash string, prompt func() ([]byte, error), tries int) bool {
	if hash == "" {
		return true
	}
	for i := 0; i < tries; i++ {
		pw, err := prompt()
		if err != nil {
			return false
		}
		ok, err := verifyPassword(hash, pw)
		if err != nil {
			return false // malformed configured hash
		}
		if ok {
			return true
		}
	}
	return false
}
