package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/anatol/booster/init/quirk"
)

const (
	// TOTHINK rename to debug/info/warning
	levelError = iota
	levelWarning
	levelInfo
	levelDebug
)

var (
	verbosityLevel = levelInfo // by default show info messages and errors
	printToConsole bool

	devKmsg *os.File
)

func printMessage(format string, requestedLevel, kernelLevel int, v ...interface{}) {
	if verbosityLevel < requestedLevel {
		return
	}

	msg := fmt.Sprintf(format, v...)
	if devKmsg != nil {
		kmsg := msg
		// The maximum size of the kmsg is determined by LOG_LINE_MAX in kernel/printk/printk.c
		// Currently the kernel limit is 976. Trim our messages to something smaller than the limit.
		if len(kmsg) > 903 {
			kmsg = kmsg[:900] + "..."
		}
		_, err := fmt.Fprint(devKmsg, "<", kernelLevel, ">booster: ", kmsg, "\n")
		if err != nil {
			fmt.Printf("kmsg: %v\n", err)
		}
	}
	if printToConsole {
		fmt.Println(msg)
	}
}

func debug(format string, v ...interface{}) {
	printMessage(format, levelDebug, 7, v...)
}

func info(format string, v ...interface{}) {
	printMessage(format, levelInfo, 6, v...)
}

func warning(format string, v ...interface{}) {
	printMessage(format, levelWarning, 4, v...)
}

// this is for critical error messages, call this function 'severe' to avoid name clashing with error class
func severe(format string, v ...interface{}) {
	printMessage(format, levelError, 2, v...)
}

const sysKmsgFile = "/proc/sys/kernel/printk_devkmsg"

func disableKmsgThrottling() error {
	data, err := os.ReadFile(sysKmsgFile)
	if err != nil {
		return err
	}
	enable := []byte("on\n")
	if bytes.Equal(data, enable) {
		return nil
	}

	return os.WriteFile(sysKmsgFile, enable, 0o644)
}

// console prints message to console
// but if we are compiling the binary with "tets" tag (e.g. for integration tests) then it prints message to kmsg to avoid
// messing log output in qemu console
func console(format string, v ...interface{}) {
	if quirk.TestEnabled {
		msg := fmt.Sprintf(format, v...)
		_, _ = fmt.Fprint(devKmsg, "<", 2, ">booster: ", msg, "\n")
	} else {
		fmt.Printf(format, v...)
	}
}
