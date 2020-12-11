package main

import (
	"testing"
)

func TestMemZeroBytes(t *testing.T) {
	data := []byte{10, 40, 50, 33}
	MemZeroBytes(data)
	for i, e := range data {
		if e != 0 {
			t.Fatalf("MemZeroBytes() did not clear element # %v", i)
		}
	}
}
