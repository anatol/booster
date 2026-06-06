package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	plymouthEnabled  bool
	plymouthInitDone = make(chan struct{})
	// plymouthPasswordMu serializes plymouthAskPassword calls so concurrent
	// unlock goroutines don't stack two prompts on the splash at once.
	plymouthPasswordMu sync.Mutex
)

// waitForPlymouthInit blocks until the plymouth initialization phase is
// complete (either plymouthd is running or plymouth was disabled), or until
// ctx is cancelled. Returns ctx.Err() on cancellation, nil otherwise.
// Safe to call multiple times; returns immediately after the first close.
func waitForPlymouthInit(ctx context.Context) error {
	select {
	case <-plymouthInitDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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

	// Write plymouthd stderr directly to /dev/kmsg rather than inheriting
	// booster's stderr. Inherited fds are closed (FD_CLOEXEC) when booster
	// exec's to systemd, causing plymouthd to receive EPIPE on its next
	// stderr write and die — before systemd's plymouth-start.service can
	// attach to the existing session.
	kmsg, err := os.OpenFile("/dev/kmsg", os.O_WRONLY, 0)
	if err != nil {
		debug("plymouth: could not open /dev/kmsg for plymouthd stderr: %v", err)
	} else {
		cmd.Stderr = kmsg
	}

	// Use Start() instead of Run(). Plymouthd may not daemonize in debug
	// mode (plymouth.debug on kernel cmdline), so Run() would block forever
	// waiting for the foreground process to exit. Start() returns immediately
	// and we use a socket ping to detect when the daemon is ready.
	if err := cmd.Start(); err != nil {
		warning("plymouth: failed to start plymouthd: %v", err)
		plymouthEnabled = false
		return
	}
	if kmsg != nil {
		kmsg.Close() // booster no longer needs this end; plymouthd inherited it
	}
	go cmd.Wait() // reap process in background

	// Wait for plymouthd to be ready via direct socket ping. Plymouth's
	// --wait flag has its own internal retry loop but only retries on
	// connection failure; if plymouthd accepts the connection but isn't
	// ready (still in device setup), --wait returns failure immediately.
	pingDeadline := time.Now().Add(20 * time.Second)
	pingOK := false
	for time.Now().Before(pingDeadline) {
		if plymouthPingOnce() {
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
	if err := plymouthCmd('$', ""); err != nil {
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
//     (live output still goes to /dev/tty1)
func getPlymouthdArgs() []string {
	return []string{
		"--mode=boot",
		"--pid-file=/run/plymouth/pid",
		"--attach-to-session",
	}
}

// plymouthAskPassword displays a password prompt on the splash and blocks
// until the user submits a password — or ctx is cancelled, in which case
// the underlying socket is closed. The goroutine returns cleanly either
// way. plymouthd builds whose connection-hangup handler tears down pending
// prompts also dismiss the on-screen UI on close; older builds leave the
// prompt UI visible until the splash is otherwise cleared.
//
// Wire ctx to the LUKS unlock done channel so a sibling token unlocking the
// volume cancels this prompt automatically.
func plymouthAskPassword(ctx context.Context, prompt string) ([]byte, error) {
	plymouthPasswordMu.Lock()
	defer plymouthPasswordMu.Unlock()
	// Re-check after acquiring: if another goroutine was showing a prompt
	// and the volume got unlocked while we were waiting on the mutex, skip
	// our prompt entirely so we don't flash a UI for an already-unlocking
	// volume.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	out, err := plymouthAskPasswordSocket(ctx, prompt)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return bytes.TrimRight(out, "\n"), nil
}

// askPasswordWithFallback prompts via plymouth when enabled, falling back
// to the console reader on plymouth failure. Returns ctx.Err() without
// falling back when ctx is cancelled — avoids flashing a console prompt
// for a volume another unlock path has already won.
func askPasswordWithFallback(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
	if plymouthEnabled {
		password, err := plymouthAskPassword(ctx, prompt)
		if err == nil {
			return password, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		warning("Plymouth password prompt failed: %v, falling back to console", err)
	}
	return readPassword(ctx, prompt, postPrompt)
}

// statusMessage shows msg on the Plymouth splash, or on the console if Plymouth
// is disabled. Passing an empty string clears the Plymouth message (no-op on console).
//
// On the console, if a password prompt is active and its volume hasn't been
// unlocked yet, the current line is erased and the prompt is reprinted beneath
// the message so the cursor stays at the bottom. Once the prompt's done channel
// closes (volume unlocked by another token), the redraw is skipped — otherwise
// the unlock status message would reprint a stale prompt that ctx-cancel hasn't
// torn down yet.
func statusMessage(msg string) {
	if plymouthEnabled {
		plymouthMessage(msg)
	} else if msg != "" {
		consoleMu.Lock()
		if consolePrompt.active && !promptVolumeUnlocked() {
			consolePrint("\n\n" + msg + "\n\n" + consolePrompt.text + strings.Repeat("*", consolePrompt.asterisks))
		} else {
			consolePrint("\n\n" + msg + "\n\n")
		}
		consoleMu.Unlock()
	}
}

// Plymouth always shows; console shows only when a password prompt is visible.
func statusMessageIfPrompt(msg string) {
	if plymouthEnabled {
		statusMessage(msg)
		return
	}
	consoleMu.Lock()
	visible := consolePrompt.active && !promptVolumeUnlocked()
	consoleMu.Unlock()
	if visible {
		statusMessage(msg)
	}
}

// promptVolumeUnlocked reports whether the active prompt's volume has been
// unlocked already (its done channel has closed). Caller must hold consoleMu.
func promptVolumeUnlocked() bool {
	if consolePrompt.done == nil {
		return false
	}
	select {
	case <-consolePrompt.done:
		return true
	default:
		return false
	}
}

// clearSplashStatusSync synchronously clears the splash status line. Used at
// boot handoff (switchRoot) so the last "unlocked via …" frame isn't left
// behind on the splash after we exec to systemd. Synchronous because
// goroutine-deferred work doesn't survive exec — a fire-and-forget clear
// can be cancelled by the exec before plymouthd ever sees it.
func clearSplashStatusSync() {
	if !plymouthEnabled {
		return
	}
	if err := plymouthCmd('M', ""); err != nil {
		debug("plymouth: clear status failed: %v", err)
	}
}

// plymouthMessage displays a message on the plymouth splash screen.
//
// Fire-and-forget: send in a goroutine so callers never block on plymouthd.
// plymouthd is single-threaded and can stall during render setup or while a
// password prompt is on screen; a synchronous in-process call would block
// the calling goroutine on splash state, slowing concurrent unlock work.
func plymouthMessage(msg string) {
	go func() {
		if err := plymouthCmd('M', msg); err != nil {
			debug("plymouth: display-message failed: %v", err)
		}
	}()
}

// plymouthQuit tells plymouth to quit.
func plymouthQuit() {
	if !plymouthEnabled {
		return
	}
	debug("plymouth: sending quit")
	// Quit frame: Q + arg-marker + arg-len(1) + retain_splash(0).
	if _, err := plymouthSendRecv([]byte{'Q', 2, 1, 0}); err != nil {
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
	if err := plymouthCmd('R', root); err != nil {
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

// createDrmUdevEntries creates udev database files for all DRM devices.
// Without udevd running, the database files under /run/udev/data/ don't exist
// and Plymouth fails two successive checks for every device:
//
//  1. udev_device_get_is_initialized() — requires any db file to exist (I:1).
//  2. udev_device_has_tag(device, "seat") — requires a G:seat line in the db.
//
// Both checks must pass; if either fails Plymouth skips the device. With no
// usable DRM device Plymouth falls back to the text (details) plugin.
//
// Three kinds of entries are needed:
//   - Card devices (card0, card1): character devices → /run/udev/data/c<major>:<minor>
//   - Render nodes (renderD128, ...): character devices → /run/udev/data/c<major>:<minor>
//   - Connector/output entries (card0-eDP-1, card0-HDMI-A-1, ...): no dev
//     file → /run/udev/data/+drm:<sysname>
//
// Card nodes get G:seat + G:uaccess; render nodes get only G:uaccess (real udev
// does not seat-assign render nodes); connectors get G:seat (matching what a real
// udevd writes via 70-seat.rules / 73-seat-late.rules).
func createDrmUdevEntries() {
	if err := os.MkdirAll("/run/udev/data/", 0o755); err != nil {
		warning("plymouth: failed to create /run/udev/data: %v", err)
		return
	}

	entries, _ := filepath.Glob("/sys/class/drm/*")
	for _, entry := range entries {
		entryName := filepath.Base(entry)

		devBytes, err := os.ReadFile(filepath.Join(entry, "dev"))
		if err == nil {
			// Character device (card0, renderD128, …): use c<major>:<minor>.
			devStr := strings.TrimSpace(string(devBytes))
			if devStr == "" || !strings.Contains(devStr, ":") {
				debug("plymouth: unexpected dev content for %s: %q", entryName, devStr)
				continue
			}
			dbFile := "/run/udev/data/c" + devStr
			content := "I:1\nG:seat\nG:uaccess\n"
			if strings.HasPrefix(entryName, "render") {
				content = "I:1\nG:uaccess\n"
			}
			if err := os.WriteFile(dbFile, []byte(content), 0o644); err != nil {
				warning("plymouth: failed to write %s: %v", dbFile, err)
				continue
			}
			debug("plymouth: created udev db entry %s for %s", dbFile, entryName)
		} else {
			// Connector/output entry (card0-eDP-1, card0-HDMI-A-1, …): no dev
			// file, so libudev uses +<subsystem>:<sysname> as the db key.
			dbFile := "/run/udev/data/+drm:" + entryName
			if err := os.WriteFile(dbFile, []byte("I:1\nG:seat\n"), 0o644); err != nil {
				warning("plymouth: failed to write %s: %v", dbFile, err)
				continue
			}
			debug("plymouth: created udev db entry %s for %s", dbFile, entryName)
		}
	}
}
