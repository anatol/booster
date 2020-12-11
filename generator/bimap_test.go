package main

import "testing"

func TestBimap(t *testing.T) {
	b := NewBimap()

	if err := b.Add("f1", "p1"); err != nil {
		t.Fatal()
	}
	if val, _ := b.forward["f1"]; val != "p1" {
		t.Fail()
	}
	if val, _ := b.reverse["p1"]; val != "f1" {
		t.Fail()
	}

	if err := b.Add("f2", "p1"); err == nil {
		t.Fail()
	}
}
