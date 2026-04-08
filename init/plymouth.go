package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	plymouthEnabled  bool
	plymouthInitDone = make(chan struct{})
)

// waitForPlymouthInit blocks until the plymouth initialization phase is
// complete (either plymouthd is running or plymouth was disabled).
// Safe to call multiple times; returns immediately after the first close.
func waitForPlymouthInit() {
	<-plymouthInitDone
}

// initPlymouth starts the plymouth daemon and shows the splash screen.
// On failure, it logs a warning and disables plymouth so the boot can continue.
func initPlymouth() {
	if !plymouthEnabled {
		return
	}

	// Create /run/plymouth directory needed by plymouthd
	if err := os.MkdirAll("/run/plymouth", 0o755); err != nil {
		warning("plymouth: failed to create /run/plymouth: %v", err)
		plymouthEnabled = false
		return
	}

	// Wait for a usable DRM device. Prefer a real GPU over simpledrm.
	// Ideally Plymouth would start on simpledrm immediately and transition
	// to the real GPU via DRM hot-unplug (as described in the Arch wiki).
	// However, that transition requires Plymouth to monitor for new DRM
	// devices via libudev (udev_monitor). Booster receives raw kernel
	// uevents via netlink but does not run udevd, so the /run/udev/data/
	// device database that libudev depends on is not maintained. Without
	// udevd, Plymouth cannot detect the GPU appearing after it has already
	// started. Instead we wait for the real GPU driver to load before
	// starting Plymouth.
	if !waitForDrmDevice(5 * time.Second) {
		warning("plymouth: no DRM device found, disabling plymouth")
		plymouthEnabled = false
		return
	}

	// Create udev database entries for DRM devices so that Plymouth's
	// udev_device_get_is_initialized() check passes. Without these files,
	// Plymouth skips all DRM devices and falls back to the details plugin
	// (text-based fallback).
	// When booster.log includes "console", skip DRM entries so Plymouth
	// reverts to the details plugin — graphical splash and console debug
	// output cannot coexist on the same terminal.
	if printToConsole {
		info("plymouth: booster.log=console is set, reverting to details plugin (text-based fallback)")
	} else {
		createDrmUdevEntries()
	}

	// Build plymouthd arguments
	args := getPlymouthdArgs()

	debug("starting plymouthd with args: %v", args)

	cmd := exec.Command("plymouthd", args...)
	cmd.Env = []string{"PATH=/usr/bin"}
	// Use Start() instead of Run(). Plymouthd may not daemonize in debug
	// mode (plymouth.debug on kernel cmdline), so Run() would block forever
	// waiting for the foreground process to exit. Start() returns immediately
	// and we use "plymouth --wait --ping" to detect when the daemon is ready.
	if err := cmd.Start(); err != nil {
		warning("plymouth: failed to start plymouthd: %v", err)
		plymouthEnabled = false
		return
	}
	go cmd.Wait() // reap process in background

	// Wait for plymouthd to be ready. Plymouth's --wait flag has its own
	// internal retry loop but it only retries on connection failure. If
	// plymouthd accepts the connection but isn't ready to process pings
	// (still in device setup), --wait returns failure immediately. So we
	// implement our own retry loop.
	pingDeadline := time.Now().Add(20 * time.Second)
	pingOK := false
	for time.Now().Before(pingDeadline) {
		if exec.Command("plymouth", "--ping").Run() == nil {
			pingOK = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !pingOK {
		warning("plymouth: daemon not responding to ping after 20s")
		plymouthEnabled = false
		return
	}

	// Show splash
	if err := exec.Command("plymouth", "show-splash").Run(); err != nil {
		warning("plymouth: failed to show splash: %v", err)
		// plymouthd is running but splash failed; keep plymouth enabled
		// for password prompts which may still work
	}

	info("plymouth splash started")
}

// getPlymouthdArgs returns the plymouthd command-line arguments.
// Following the same convention as dracut and mkinitcpio, we do NOT pass
// --kernel-command-line or --debug. Plymouthd reads /proc/cmdline directly
// and handles plymouth.debug, splash, quiet, etc. internally.
//
// For debug logging, add one of these to the kernel cmdline:
//   - plymouth.debug                                 → live output to /dev/tty1
//   - plymouth.debug=stream:/run/plymouth/debug.log  → live output to file
//   - plymouth.debug=file:/run/plymouth/debug.log    → buffer dumped to file at exit
//                                                      (live output still goes to /dev/tty1)
func getPlymouthdArgs() []string {
	return []string{
		"--mode=boot",
		"--pid-file=/run/plymouth/pid",
		"--attach-to-session",
	}
}

// plymouthAskPassword prompts the user for a password via plymouth.
// Returns the password bytes or an error if plymouth fails.
func plymouthAskPassword(prompt string) ([]byte, error) {
	cmd := exec.Command("plymouth", "ask-for-password", "--prompt="+prompt)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	// plymouth outputs the password followed by a newline
	password := strings.TrimRight(string(out), "\n")
	return []byte(password), nil
}

// statusMessage shows msg on the Plymouth splash, or on the console if Plymouth
// is disabled. Passing an empty string clears the Plymouth message (no-op on console).
func statusMessage(msg string) {
	if plymouthEnabled {
		plymouthMessage(msg)
	} else if msg != "" {
		console(msg + "\n")
	}
}

// plymouthMessage displays a message on the plymouth splash screen.
func plymouthMessage(msg string) {
	if err := exec.Command("plymouth", "display-message", "--text="+msg).Run(); err != nil {
		debug("plymouth: display-message failed: %v", err)
	}
}

// plymouthQuit tells plymouth to quit with a timeout so it can't hang boot.
func plymouthQuit() {
	if !plymouthEnabled {
		return
	}
	debug("plymouth: sending quit")
	if err := exec.Command("plymouth", "quit").Run(); err != nil {
		warning("plymouth: quit failed: %v", err)
	}
}

// plymouthNewroot tells plymouth about the new root filesystem.
// This must be called before moveMountpointsToHost.
func plymouthNewroot(root string) {
	if !plymouthEnabled {
		return
	}
	debug("plymouth: setting newroot to %s", root)
	if err := exec.Command("plymouth", "update-root-fs", "--new-root-dir="+root).Run(); err != nil {
		warning("plymouth: update-root-fs failed: %v", err)
	}
}

// waitForDrmDevice waits for a DRM card device to appear in /dev/dri/.
// It prefers non-simpledrm devices since simpledrm cards are often replaced
// by a real GPU driver during early boot.
func waitForDrmDevice(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	var fallback string
	for time.Now().Before(deadline) {
		matches, _ := filepath.Glob("/dev/dri/card*")
		for _, card := range matches {
			if isSimpledrm(card) {
				if fallback == "" {
					debug("plymouth: found simpledrm device %s, waiting for real GPU", card)
					fallback = card
				}
				continue
			}
			debug("plymouth: found DRM device %s", card)
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	// No real GPU appeared; use simpledrm if available
	if fallback != "" {
		debug("plymouth: using simpledrm fallback %s", fallback)
		return true
	}
	return false
}

// isSimpledrm checks whether a /dev/dri/cardN device is backed by simpledrm.
func isSimpledrm(devPath string) bool {
	cardName := filepath.Base(devPath)
	driverLink, err := os.Readlink(filepath.Join("/sys/class/drm", cardName, "device", "driver"))
	if err != nil {
		return false
	}
	// The simpledrm module registers as platform driver "simple-framebuffer",
	// so the sysfs driver name is "simple-framebuffer", not "simpledrm".
	return filepath.Base(driverLink) == "simple-framebuffer"
}

// createDrmUdevEntries creates udev database files for DRM card devices.
// Plymouth uses udev_device_get_is_initialized() to check whether a DRM
// device is ready. This function checks for /run/udev/data/c<major>:<minor>
// files. Without udevd running, these files don't exist and Plymouth skips
// every DRM device, falling back to the details plugin (text-based fallback) after an 8s timeout.
//
// This follows the same pattern as devMapperUpdateUdevDb() in udev.go.
func createDrmUdevEntries() {
	if err := os.MkdirAll("/run/udev/data/", 0o755); err != nil {
		warning("plymouth: failed to create /run/udev/data: %v", err)
		return
	}

	cards, _ := filepath.Glob("/sys/class/drm/card[0-9]*")
	for _, card := range cards {
		cardName := filepath.Base(card)

		// Skip DRM connector entries (card1-DP-1, card1-eDP-1, etc.)
		// which don't have dev files. We only want card devices.
		if strings.Contains(cardName, "-") {
			continue
		}

		devBytes, err := os.ReadFile(filepath.Join(card, "dev"))
		if err != nil {
			debug("plymouth: failed to read dev for %s: %v", cardName, err)
			continue
		}

		devStr := strings.TrimSpace(string(devBytes))
		if devStr == "" || !strings.Contains(devStr, ":") {
			debug("plymouth: unexpected dev content for %s: %q", cardName, devStr)
			continue
		}
		dbFile := "/run/udev/data/c" + devStr
		if err := os.WriteFile(dbFile, []byte("I:1\nV:1\n"), 0o644); err != nil {
			warning("plymouth: failed to write %s: %v", dbFile, err)
			continue
		}
		debug("plymouth: created udev db entry %s", dbFile)
	}
}
