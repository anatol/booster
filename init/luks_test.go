package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
