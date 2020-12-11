package main

import "fmt"

type Bimap struct {
	forward, reverse map[string]string
}

func NewBimap() *Bimap {
	return &Bimap{
		forward: make(map[string]string),
		reverse: make(map[string]string),
	}
}

func (b *Bimap) Add(key, value string) error {
	if v, ok := b.forward[key]; ok {
		return fmt.Errorf("provided key already used in mapping %s->%s", key, v)
	}
	if k, ok := b.reverse[value]; ok {
		return fmt.Errorf("provided value already used in mapping %s->%s", k, value)
	}

	b.forward[key] = value
	b.reverse[value] = key

	return nil
}
