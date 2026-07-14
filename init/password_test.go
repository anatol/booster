package main

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// goldenPHC was produced by the real argon2 CLI the manpage tells users to run:
//   printf 'hunter2-correct' | argon2 'boostersalt12345' -id -t 3 -m 16 -p 4 -e
// It pins interop with that tool (unpadded base64, m=64MiB t=3 p=4).
const goldenPHC = "$argon2id$v=19$m=65536,t=3,p=4$Ym9vc3RlcnNhbHQxMjM0NQ$YVOIENbv5h37WfbpMl6VgxCWPe7oOTlc0bJDgJhjUS4"

func TestVerifyPassword(t *testing.T) {
	ok, err := verifyPassword(goldenPHC, []byte("hunter2-correct"))
	require.NoError(t, err)
	require.True(t, ok, "the correct password must verify against an argon2-CLI hash")

	ok, err = verifyPassword(goldenPHC, []byte("wrong"))
	require.NoError(t, err)
	require.False(t, ok, "a wrong password must not verify")

	for _, bad := range []string{
		"", "notaphc", "$argon2id$v=19$m=65536,t=3,p=4$onlyfourfields",
		"$bcrypt$v=19$m=1,t=1,p=1$YWJj$YWJj", // wrong algorithm
	} {
		_, err := verifyPassword(bad, []byte("x"))
		require.Error(t, err, "malformed PHC %q must error", bad)
	}
}

func TestAuthorizeEmergencyShell(t *testing.T) {
	const correct = "hunter2-correct"

	// Empty hash: backward-compatible, always allowed (no prompt).
	require.True(t, authorizeEmergencyShell("", func() ([]byte, error) {
		t.Fatal("must not prompt when no password is configured")
		return nil, nil
	}, 3))

	// Correct on first try.
	require.True(t, authorizeEmergencyShell(goldenPHC,
		func() ([]byte, error) { return []byte(correct), nil }, 3))

	// Wrong every time -> denied after tries.
	calls := 0
	require.False(t, authorizeEmergencyShell(goldenPHC, func() ([]byte, error) {
		calls++
		return []byte("nope"), nil
	}, 3))
	require.Equal(t, 3, calls, "must use all attempts")

	// Read error -> denied.
	require.False(t, authorizeEmergencyShell(goldenPHC,
		func() ([]byte, error) { return nil, errors.New("no tty") }, 3))

	// Malformed configured hash -> denied (fail closed).
	require.False(t, authorizeEmergencyShell("garbage",
		func() ([]byte, error) { return []byte(correct), nil }, 3))
}
