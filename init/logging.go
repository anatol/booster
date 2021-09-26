package main

import (
	"fmt"
	"os"
)

const (
	// TOTHINK rename to debug/info/warning
	levelSevere = iota
	levelWarning
	levelDebug
)

var (
	verbosityLevel = levelWarning // by default show warnings and errors

	kmsg *os.File
)

func printMessage(format string, level int, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	fmt.Println(msg)
	_, _ = fmt.Fprint(kmsg, "<", level, ">booster: ", msg, "\n")
}

func debug(format string, v ...interface{}) {
	if verbosityLevel >= levelDebug {
		printMessage(format, 7, v...)
	}
}

func warning(format string, v ...interface{}) {
	if verbosityLevel >= levelWarning {
		printMessage(format, 6, v...)
	}
}

func severe(format string, v ...interface{}) {
	if verbosityLevel >= levelSevere {
		printMessage(format, 4, v...)
	}
}

const sysKmsgFile = "/proc/sys/kernel/printk_devkmsg"

func disableKmsgThrottling() error {
	return os.WriteFile(sysKmsgFile, []byte("on\n"), 0644)
}
