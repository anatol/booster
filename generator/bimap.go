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

func (b *Bimap) Add(key, value string, aliases ...string) error {
	if v, ok := b.forward[key]; ok && v != value {
		return fmt.Errorf("key %s maps to multiple values (%s,%s)", key, v, value)
	}
	b.forward[key] = value

	if k, ok := b.reverse[value]; ok && k != key {
		return fmt.Errorf("multiple keys (%s,%s) map to the same value %s", k, key, value)
	}
	b.reverse[value] = key

	for _, a := range aliases {
		if k, ok := b.reverse[a]; ok && k != key {
			return fmt.Errorf("multiple keys (%s,%s) map to the same alias %s", k, key, a)
		}
		b.reverse[a] = key
	}

	return nil
}
