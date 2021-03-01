package main

import "testing"

func TestReadEmptyConfig(t *testing.T) {
	t.Parallel()

	c, err := readGeneratorConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if c.compression != "zstd" {
		t.Fatalf("expected default compression zstd, got %s", c.compression)
	}
}
