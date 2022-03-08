package main

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLz4Writer(t *testing.T) {
	w := bytes.NewBuffer(nil)
	c, err := newLz4Writer(w, true)
	require.NoError(t, err)
	_, err = c.Write([]byte("hello"))
	require.NoError(t, err)
	c.Close()

	require.Equal(t, []byte("\x02!L\x18\x06\x00\x00\x00Phello"), w.Bytes())
}

func TestLz4Reader(t *testing.T) {
	r := bytes.NewBuffer([]byte("\x02!L\x18\x06\x00\x00\x00Phello"))
	c, err := newLz4Reader(r)
	require.NoError(t, err)
	plain, err := io.ReadAll(c)
	require.NoError(t, err)
	c.Close()

	require.Equal(t, "hello", string(plain))
}
