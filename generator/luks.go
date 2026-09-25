package main

import (
	"os"
	"strings"

	"github.com/anatol/luks.go"
)

// detectHostClevisTokens inspects block devices on the host looking for LUKS2
// partitions enrolled with a "clevis" token.
func detectHostClevisTokens() (bool, error) {
	entries, err := os.ReadDir("/sys/class/block")
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return false, nil
		}
		return false, err
	}

	for _, entry := range entries {
		devName := entry.Name()
		// Quick filter: skip virtual devices that are never physical LUKS partitions
		if strings.HasPrefix(devName, "loop") || strings.HasPrefix(devName, "ram") || strings.HasPrefix(devName, "zram") {
			continue
		}
		devPath := "/dev/" + devName
		d, err := luks.Open(devPath)
		if err != nil {
			continue
		}
		tokens, err := d.Tokens()
		d.Close()
		if err != nil {
			continue
		}
		for _, t := range tokens {
			if t.Type == "clevis" {
				return true, nil
			}
		}
	}
	return false, nil
}
