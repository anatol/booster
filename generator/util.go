package main

import "regexp"

// parseProperties parses input in form of "PROP1=VAL1\nPROP2=VAL2\n..." into a map
func parseProperties(data string) map[string]string {
	re := regexp.MustCompile(`(\w+)=(\S+)`)
	matches := re.FindAllStringSubmatch(data, -1)
	result := make(map[string]string)
	for _, m := range matches {
		result[m[1]] = m[2]
	}

	return result
}
