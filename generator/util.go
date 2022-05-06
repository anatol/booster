package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

// parseProperties parses input in form of "PROP1=VAL1\nPROP2=VAL2\n..." into a map.
// whitespace are stripped from values.
// parameter strip specifies whether values should strip leading+trailing quotes
func parseProperties(data string, strip bool) map[string]string {
	re := regexp.MustCompile(`(\w+)=\s*(\S+)\s*`)
	matches := re.FindAllStringSubmatch(data, -1)
	result := make(map[string]string)
	for _, m := range matches {
		value := m[2]
		if strip {
			value = stripQuotes(strings.TrimSpace(value))
		}
		result[m[1]] = value
	}

	return result
}

// Opening a lot of module files in parallel requires high limit of open file descriptors
// TODO: Golang's 1024 descriptors limit is removed in 1.19 (https://github.com/golang/go/issues/46279)
//       drop this function once Golang 1.19 becomes default version.
func increaseOpenFileLimit() {
	limit := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}

	// first try to set the process limit to infinity
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err == nil {
		// it worked!
		return
	}

	// if the current process unprivileged then the only thing we can do is to set soft limit to max limit value

	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		warning("unable to get open file limit: %v", err)
		return
	}

	if limit.Cur >= limit.Max {
		return // nothing to increase
	}

	debug("increasing open file limit %d->%d", limit.Cur, limit.Max)
	limit.Cur = limit.Max

	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		warning("unable to increase open file limit: %v", err)
	}
}

func unwrapExitError(err error) error {
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("%v: %v", err, string(exitErr.Stderr))
	}
	return err
}

// stripQuotes removes leading and trailing quote symbols if they wrap the given sentence
func stripQuotes(in string) string {
	l := len(in)
	if in[0] == '"' && in[l-1] == '"' {
		return in[1 : l-1]
	}

	return in
}
