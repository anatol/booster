package main

import (
	"fmt"
	"strings"
)

// parseBluetoothAddress checks that s is a Bluetooth device address written
// the way BlueZ and bluetoothctl write it, six colon-separated hex octets, and
// returns it upper-cased, the form BlueZ names its state directories by.
func parseBluetoothAddress(s string) (string, error) {
	invalid := fmt.Errorf("%q is not a Bluetooth address like 00:1A:7D:DA:71:13", s)
	if len(s) != 17 {
		return "", invalid
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i%3 == 2 {
			if c != ':' {
				return "", invalid
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return "", invalid
		}
	}
	return strings.ToUpper(s), nil
}
