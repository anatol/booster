package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseBluetoothAddress(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in, want string
	}{
		{"00:1A:7D:DA:71:13", "00:1A:7D:DA:71:13"},
		{"00:1a:7d:da:71:13", "00:1A:7D:DA:71:13"},
	} {
		got, err := parseBluetoothAddress(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.want, got)
	}

	for _, in := range []string{
		"",
		"00:1A:7D:DA:71",
		"00:1A:7D:DA:71:13:00",
		"00-1A-7D-DA-71-13",
		"001A.7DDA.7113",
		"00:1A:7D:DA:71:1G",
		" 00:1A:7D:DA:71:13",
	} {
		_, err := parseBluetoothAddress(in)
		require.Error(t, err, "%q must be rejected", in)
	}
}
