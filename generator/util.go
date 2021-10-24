package main

import (
	"regexp"

	"golang.org/x/sys/unix"
)

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

// Opening a lot of module files in parallel requires high limit of open file descriptors
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
