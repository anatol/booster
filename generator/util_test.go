package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseProperties(t *testing.T) {
	got := parseProperties("PROP1=VAL1\nPROP2=VAL2\nPROP3=VAL3\nFONT=cp866-8x14\n")

	expect := map[string]string{
		"PROP1": "VAL1",
		"PROP2": "VAL2",
		"PROP3": "VAL3",
		"FONT":  "cp866-8x14",
	}
	require.Equal(t, expect, got)
}
