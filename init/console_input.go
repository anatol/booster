package main

// console_input.go — raw-mode password reader plus the CSI/UTF-8 input scanner
// it consumes.
//
// Why this exists (the headline value of the package):
//   The cooked-mode reader this replaces (bufio.Scanner over stdin in ICANON
//   mode) blocks in read(2) with no way to honour ctx cancellation. When a
//   token (TPM2 PCR-only / touchless FIDO2 / clevis) wins the unlock race
//   while the keyboard prompt is showing, the cooked reader stays stuck in
//   read(2): boot continues for the unlocked volume but the prompt is left
//   dangling, inputMutex/keyboardMu stay held, and any subsequent volumes
//   that need keyboard entry block indefinitely. The user has to manually
//   press Enter on the now-pointless prompt.
//
//   readPasswordOn (below) replaces that with a Poll(100ms) + Read(1 byte)
//   loop that checks ctx.Done() between polls. On cancel the reader returns
//   within ~100ms, termios is restored, the prompt line is terminated with a
//   newline, and locks are released. End-to-end behaviour: when a token wins,
//   the keyboard prompt dismisses cleanly without user intervention.
//
//   Headline test: TestReadPasswordOnCtxCancelReturnsPromptly in
//   console_input_pty_test.go exercises this end-to-end with a real pty pair.
//
// Why we wrote our own scanner instead of using a library:
//   Booster is an initramfs — every dep adds cgo risk, binary size, and
//   supply-chain surface. golang.org/x/term is line-mode only (the bug
//   above). All third-party CSI/raw-input libs (charmbracelet/x/input,
//   peterh/liner, eiannone/keyboard, mattn/go-tty) pull substantial
//   transitive deps. The custom scanner is ~250 LOC; the smallest dep that
//   covers our needs adds an order of magnitude more.
//
// Scanner design (the inputScanner type):
//   Inspired by Plymouth's on_key_event state machine in
//   src/libply-splash-core/ply-keyboard.c (specifically lines 274–369), but
//   reimplemented as a per-byte FSM (finite state machine) rather than
//   Plymouth's slice-scan.
//   Functionally equivalent for well-formed input. UTF-8 helpers
//   (utf8LeadLen, trimLastCodepoint, countCodepoints) are byte-pattern
//   ports of the corresponding ply_utf8_* functions.
//
//   Intentional divergences from Plymouth:
//     - We keep ISIG so Ctrl+C still cancels (Plymouth's cfmakeraw clears it)
//     - We accept both \x08 (BS) and \x7f (DEL) as backspace; Plymouth only DEL
//     - We have proper Ctrl+W word-kill; Plymouth collapses Ctrl+W to line-kill
//     - We handle OSC, DCS, and bracketed-paste sequences; Plymouth doesn't
//     - We validate UTF-8 (overlong/surrogate/>U+10FFFF rejected); Plymouth doesn't
//     - We bound CSI parameter accumulation to avoid lock-up on garbage input
//   See the cross-reference in init/console_input_test.go header for details.
//
// Scanner goals:
//   - Silently consume ANSI CSI sequences (arrow keys, function keys,
//     bracketed-paste markers, OSC payloads) so they cannot leak into the
//     password buffer.
//   - Reassemble UTF-8 multi-byte codepoints across Feed() call boundaries
//     so the caller sees one keyChar event per codepoint, not one per byte.
//   - Map Ctrl+U / Ctrl+W to keyKillLine / keyKillWord for line editing.
//   - Pass printable ASCII and other "normal" codepoints through as keyChar.
//   - Track bracketed-paste state so clipboard control bytes aren't
//     interpreted as editing keys (relevant on serial / IPMI (Intelligent
//     Platform Management Interface) consoles).
//
// References:
//   ECMA-48 (ANSI X3.64): control sequence definitions. See in particular
//     §5.4 (control sequence syntax) and §5.5 (string sequences for OSC etc.)
//   xterm Control Sequences:
//     https://invisible-island.net/xterm/ctlseqs/ctlseqs.html
//   Plymouth keyboard handler (the design inspiration):
//     gitlab.freedesktop.org/plymouth/plymouth → src/libply-splash-core/ply-keyboard.c
//
// Acronym key (terminal escape sequences from ECMA-48 / xterm):
//   CSI — Control Sequence Introducer (\x1b[)
//   SS3 — Single Shift 3 (\x1bO; alternate arrow-key encoding)
//   OSC — Operating System Command (\x1b]; e.g. set window title, OSC 52 clipboard)
//   DCS — Device Control String (\x1bP)
//   SOS — Start of String (\x1bX)
//   PM  — Privacy Message (\x1b^)
//   APC — Application Program Command (\x1b_)
//   ST  — String Terminator (\x1b\\ or 0x9c; ends OSC/DCS/SOS/PM/APC strings)
//   BEL — Bell (0x07; alternative OSC string terminator)
//   EL  — Erase In Line (CSI K; clears screen line, used by eraseLineAndAdvance)
//   BS  — Backspace (0x08)
//   DEL — Delete (0x7f)
//   CR  — Carriage Return (0x0d)
//   LF  — Line Feed (0x0a)

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/anatol/booster/init/quirk"
	"golang.org/x/sys/unix"
)

// keyEvent is the result type returned by inputScanner.Feed.
type keyEvent int

const (
	keyNone      keyEvent = iota // byte consumed mid-sequence; no visible event
	keyChar                      // a printable character (ASCII or UTF-8 codepoint)
	keyEnter                     // CR / LF — end of input
	keyEOF                       // Ctrl+D (0x04) — end-of-input on empty buffer; no-op otherwise
	keyBackspace                 // BS (0x08) or DEL (0x7f) — erase last char
	keyTab                       // Tab (0x09) — cycle the password echo mode
	keyKillLine                  // Ctrl+U (0x15) — erase entire line
	keyKillWord                  // Ctrl+W (0x17) — erase back to last whitespace
)

// inputScanner is a small stateful byte scanner.  Create with a zero value and
// call Feed() for each byte received from the TTY.
//
// Partial sequences (e.g. the two bytes of a UTF-8 codepoint split across two
// read() calls) are held in the internal buffer and completed on the next
// Feed() call; only then is a keyChar event emitted.
type inputScanner struct {
	// csiState tracks where we are in consuming an escape sequence.
	//   csiNone     — normal, no escape in progress
	//   csiEscape   — saw \x1b, waiting for next byte
	//   csiCSI      — saw \x1b[ (CSI), consuming params until final byte 0x40–0x7e
	//   csiSS3      — saw \x1bO, consuming one more byte (SS3 final)
	//   csiFuncKey  — saw \x1b[[  (Linux function-key prefix), one more byte
	//   csiOSC      — inside OSC (\x1b]…), consuming until BEL or ST
	//   csiOSCEsc   — saw \x1b inside OSC, expecting \\ to complete ST
	//   csiStringTerm    — inside DCS / SOS / PM / APC string, consuming until ST
	//   csiStringTermEsc — saw \x1b inside string-term seq, expecting \\
	csiState int

	// csiParams accumulates parameter / intermediate bytes inside csiCSI so we
	// can recognise specific sequences (e.g. \x1b[200~ paste-start). Bounded
	// to avoid unbounded growth from a malicious or garbage paste payload.
	csiParams   [16]byte
	csiParamLen int

	// inPaste is true between bracketed-paste markers \x1b[200~ and \x1b[201~.
	// Inside paste, control bytes are treated as literal characters rather than
	// editing keys — clipboard contents shouldn't trigger backspace, submit, etc.
	inPaste bool

	// utf8Buf holds the bytes of an in-progress multi-byte UTF-8 codepoint.
	// When utf8Pending > 0 we are inside a codepoint and waiting for
	// remaining continuation bytes.
	utf8Buf     [4]byte
	utf8Len     int // total expected bytes in current codepoint (2, 3, or 4)
	utf8Pending int // how many bytes we have accumulated so far
}

const (
	csiNone          = iota
	csiEscape        // saw 0x1b
	csiCSI           // saw 0x1b [
	csiSS3           // saw 0x1b O
	csiFuncKey       // saw 0x1b [ [
	csiOSC           // saw 0x1b ] (Operating System Command)
	csiOSCEsc        // saw 0x1b inside OSC body — expecting \\ to complete ST
	csiStringTerm    // saw 0x1b P / X / ^ / _ (DCS, SOS, PM, APC)
	csiStringTermEsc // saw 0x1b inside DCS/SOS/PM/APC body
)

// utf8LeadLen returns the expected total byte length for a UTF-8 sequence
// starting with the given lead byte, or 0 if the byte is not a valid lead.
func utf8LeadLen(b byte) int {
	switch {
	case b&0xe0 == 0xc0: // 110xxxxx — 2-byte sequence
		return 2
	case b&0xf0 == 0xe0: // 1110xxxx — 3-byte sequence
		return 3
	case b&0xf8 == 0xf0: // 11110xxx — 4-byte sequence
		return 4
	default:
		return 0
	}
}

// trimLastCodepoint removes the last UTF-8 codepoint from b and returns the
// shorter slice.  If b is empty or malformed, b is returned unchanged.
func trimLastCodepoint(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	// Walk backward over continuation bytes (0x80–0xBF) until we find the lead.
	i := len(b) - 1
	for i > 0 && b[i]&0xc0 == 0x80 {
		i--
	}
	return b[:i]
}

// countCodepoints counts the number of UTF-8 codepoints in b.
// Continuation bytes (0x80–0xBF) are not counted as codepoints.
func countCodepoints(b []byte) int {
	n := 0
	for _, c := range b {
		if c&0xc0 != 0x80 { // not a continuation byte
			n++
		}
	}
	return n
}

// killWord removes the last "word" from password b, where a word boundary is
// defined by an ASCII space.  Returns the new slice and the number of
// codepoints removed (for asterisk accounting).
//
// Semantics (consistent with Plymouth / bash Ctrl+W):
//   - If the buffer ends with spaces, erase those spaces first.
//   - Then erase back to the previous space (exclusive) or to the start.
func killWord(b []byte) (newBuf []byte, codepointsRemoved int) {
	if len(b) == 0 {
		return b, 0
	}
	end := len(b)
	// Walk backward over trailing spaces.
	i := end
	for i > 0 && b[i-1] == ' ' {
		i--
	}
	// Walk backward over the non-space word.
	for i > 0 && b[i-1] != ' ' {
		i--
	}
	removed := countCodepoints(b[i:end])
	return b[:i], removed
}

// Feed processes one byte from the terminal and returns a keyEvent plus the
// character bytes for keyChar events. For keyChar events the returned []byte
// is valid only until the next Feed() call (it aliases the scanner's internal
// utf8Buf — copy if you need to retain it past the next Feed).
//
// State-machine flow (csiState transitions):
//
//	csiNone (idle)
//	  ├─ 0x1b              → csiEscape
//	  ├─ 0x80–0xff (UTF-8 lead)        → utf8Pending>0 (mid-codepoint)
//	  ├─ 0x20–0x7e         → emit keyChar
//	  ├─ \r \n             → emit keyEnter
//	  ├─ 0x04 (Ctrl+D)     → emit keyEOF (caller: end on empty, no-op otherwise)
//	  ├─ 0x08 0x7f         → emit keyBackspace
//	  ├─ 0x09              → emit keyTab
//	  ├─ 0x15              → emit keyKillLine
//	  ├─ 0x17              → emit keyKillWord
//	  └─ other 0x00–0x1f   → drop silently
//
//	csiEscape (saw 0x1b)
//	  ├─ '['               → csiCSI       (CSI: arrows, function keys, paste markers)
//	  ├─ 'O'               → csiSS3       (SS3: alt arrow encoding)
//	  ├─ ']'               → csiOSC       (Operating System Command)
//	  ├─ 'P','X','^','_'   → csiStringTerm (DCS, SOS, PM, APC)
//	  └─ other             → csiNone (drop)
//
//	csiCSI (saw 0x1b[)  — accumulates params/intermediates in csiParams[:csiParamLen]
//	  ├─ '[' (only when csiParamLen==0)   → csiFuncKey (Linux \x1b[[ prefix)
//	  ├─ 0x40–0x7e (final byte)           → csiNone; if final=='~' and params=="200"/"201" toggle inPaste
//	  ├─ 0x20–0x3f (param/intermediate)   → accumulate; abort to csiNone if >cap (16)
//	  └─ (no other transitions)
//
//	csiSS3, csiFuncKey       — consume one byte and return to csiNone
//	csiOSC, csiStringTerm    — consume body until BEL (0x07) or 8-bit ST (0x9c);
//	                            on 0x1b transition to csiOSCEsc / csiStringTermEsc
//	csiOSCEsc, csiStringTermEsc — '\\' completes 7-bit ST (csiNone); else back to body state
//
// Bracketed-paste mode (inPaste=true) modifies csiNone behaviour:
//   - 0x1b still starts an escape sequence (so we can detect \x1b[201~ paste-end)
//   - All other bytes (including control bytes like \x08, \n) pass through as
//     keyChar literals — clipboard content is opaque, not editing input.
func (s *inputScanner) Feed(b byte) (event keyEvent, chars []byte) {
	// ── UTF-8 continuation ────────────────────────────────────────────────
	// If we are mid-codepoint, accumulate bytes until complete.
	if s.utf8Pending > 0 {
		if b&0xc0 != 0x80 {
			// Not a continuation byte — the prior sequence was malformed.
			// Drop it and fall through to process b as a fresh byte.
			s.utf8Pending = 0
			s.utf8Len = 0
		} else {
			s.utf8Buf[s.utf8Pending] = b
			s.utf8Pending++
			if s.utf8Pending == s.utf8Len {
				// Complete codepoint — validate before emitting. This rejects
				// overlong encodings, surrogates (U+D800–DFFF), and codepoints
				// above U+10FFFF that utf8LeadLen alone can't filter.
				n := s.utf8Len
				s.utf8Pending = 0
				s.utf8Len = 0
				if !utf8.Valid(s.utf8Buf[:n]) {
					return keyNone, nil
				}
				return keyChar, s.utf8Buf[:n]
			}
			return keyNone, nil
		}
	}

	// ── CSI / escape-sequence state machine ──────────────────────────────
	switch s.csiState {
	case csiEscape:
		switch b {
		case '[':
			s.csiState = csiCSI
			s.csiParamLen = 0
			return keyNone, nil
		case 'O':
			s.csiState = csiSS3
			return keyNone, nil
		case ']':
			// Operating System Command — consume body until BEL or ST.
			s.csiState = csiOSC
			return keyNone, nil
		case 'P', 'X', '^', '_':
			// DCS, SOS, PM, APC — same string-terminator rules as OSC.
			s.csiState = csiStringTerm
			return keyNone, nil
		default:
			// Lone ESC followed by something unexpected — drop both.
			s.csiState = csiNone
			return keyNone, nil
		}

	case csiCSI:
		// '[' as the first byte after \x1b[ is the Linux function-key prefix
		// (\x1b[[A–E for F1–F5). We only enter csiFuncKey when no params have
		// been accumulated yet — once we've seen any param/intermediate, '['
		// would just be an unusual but legal CSI continuation byte that we
		// already consume in the accumulate branch below.
		if b == '[' && s.csiParamLen == 0 {
			s.csiState = csiFuncKey
			return keyNone, nil
		}
		// CSI final byte is in range 0x40–0x7e.
		if b >= 0x40 && b <= 0x7e {
			// Detect bracketed-paste markers: \x1b[200~ and \x1b[201~.
			if b == '~' && s.csiParamLen == 3 {
				switch string(s.csiParams[:3]) {
				case "200":
					s.inPaste = true
				case "201":
					s.inPaste = false
				}
			}
			s.csiState = csiNone
			s.csiParamLen = 0
			return keyNone, nil
		}
		// Parameter (0x30–0x3f) or intermediate (0x20–0x2f) byte.
		// Accumulate up to the cap; if we overflow, abort the CSI to avoid
		// swallowing real keystrokes from a garbage/malicious payload.
		if s.csiParamLen < len(s.csiParams) {
			s.csiParams[s.csiParamLen] = b
			s.csiParamLen++
		} else {
			s.csiState = csiNone
			s.csiParamLen = 0
		}
		return keyNone, nil

	case csiSS3:
		// SS3 final: a single byte A–Z.  Consume and reset.
		s.csiState = csiNone
		return keyNone, nil

	case csiFuncKey:
		// Linux function key: \x1b[[ + one final byte (A–E for F1–F5).
		s.csiState = csiNone
		return keyNone, nil

	case csiOSC:
		// Body bytes are silently consumed. End on BEL (0x07) or 8-bit ST (0x9c),
		// or on \x1b which may be the start of 7-bit ST (\x1b\\).
		if b == 0x07 || b == 0x9c {
			s.csiState = csiNone
		} else if b == 0x1b {
			s.csiState = csiOSCEsc
		}
		return keyNone, nil

	case csiOSCEsc:
		// After ESC inside OSC: '\\' completes ST; otherwise stay in OSC body.
		if b == '\\' {
			s.csiState = csiNone
		} else {
			s.csiState = csiOSC
		}
		return keyNone, nil

	case csiStringTerm:
		// DCS, SOS, PM, APC — same termination rules as OSC.
		if b == 0x07 || b == 0x9c {
			s.csiState = csiNone
		} else if b == 0x1b {
			s.csiState = csiStringTermEsc
		}
		return keyNone, nil

	case csiStringTermEsc:
		if b == '\\' {
			s.csiState = csiNone
		} else {
			s.csiState = csiStringTerm
		}
		return keyNone, nil
	}

	// ── Normal byte processing (csiState == csiNone) ──────────────────────

	// 0x1b always starts an escape sequence — even inside paste mode, since
	// that's how we detect the \x1b[201~ paste-end marker.
	if b == 0x1b {
		s.csiState = csiEscape
		return keyNone, nil
	}

	// In paste mode: clipboard content is delivered literally. Don't interpret
	// control bytes as editing keys — an embedded \x08 from the clipboard
	// shouldn't backspace, an embedded \n shouldn't submit early, etc.
	if s.inPaste {
		if b >= 0x80 {
			n := utf8LeadLen(b)
			if n > 0 {
				s.utf8Buf[0] = b
				s.utf8Pending = 1
				s.utf8Len = n
				return keyNone, nil
			}
			return keyNone, nil
		}
		// ASCII (printable or control) — pass through as a single-byte char.
		s.utf8Buf[0] = b
		return keyChar, s.utf8Buf[:1]
	}

	// Well-known control bytes.
	switch b {
	case '\r', '\n': // CR, LF
		return keyEnter, nil
	case 0x04: // Ctrl+D — caller decides (skip on empty, no-op otherwise)
		return keyEOF, nil
	case 0x09: // Tab
		return keyTab, nil
	case 0x08, 0x7f: // BS or DEL
		return keyBackspace, nil
	case 0x15: // Ctrl+U — kill line
		return keyKillLine, nil
	case 0x17: // Ctrl+W — kill word
		return keyKillWord, nil
	}

	// High bytes (0x80–0xff): could be UTF-8 multi-byte lead or Latin-1.
	if b >= 0x80 {
		n := utf8LeadLen(b)
		if n > 0 {
			// Start of a multi-byte UTF-8 codepoint.
			s.utf8Buf[0] = b
			s.utf8Pending = 1
			s.utf8Len = n
			return keyNone, nil
		}
		// Invalid or unexpected high byte — drop silently.
		return keyNone, nil
	}

	// Plain printable ASCII (0x20–0x7e).
	if b >= 0x20 && b <= 0x7e {
		s.utf8Buf[0] = b
		return keyChar, s.utf8Buf[:1]
	}

	// All other control bytes (0x00–0x1f excluding the ones above) are dropped.
	return keyNone, nil
}

// passwordEchoMode selects what the password prompt paints per typed
// character: one asterisk, nothing at all, or the literal character.
type passwordEchoMode int

const (
	echoAsterisks passwordEchoMode = iota // one "*" per codepoint; the default
	echoSilent                            // no visual feedback (sudo-style)
	echoPlaintext                         // literal characters, for typo hunting
)

// defaultPasswordEchoCycle is the Tab order when password_echo is unset:
// asterisks → silent → plaintext. Plaintext last keeps the historical
// first-press behavior (hide the feedback) and makes the reveal mode
// reachable only deliberately, never on the way to hiding.
var defaultPasswordEchoCycle = []passwordEchoMode{echoAsterisks, echoSilent, echoPlaintext}

// parsePasswordEcho maps a password_echo config value — an ordered,
// comma-separated list of unique modes — to the prompt's Tab cycle. The first
// entry is the startup mode; Tab advances through the list in order, wrapping.
// A single entry pins the prompt (Tab is a no-op). Empty selects the default
// cycle. The generator validates the same syntax at image build time; the
// boolean here guards against a hand-edited image config.
func parsePasswordEcho(val string) ([]passwordEchoMode, bool) {
	if val == "" {
		return defaultPasswordEchoCycle, true
	}
	parts := strings.Split(val, ",")
	cycle := make([]passwordEchoMode, 0, len(parts))
	for _, p := range parts {
		var m passwordEchoMode
		switch strings.TrimSpace(p) {
		case "asterisks":
			m = echoAsterisks
		case "silent":
			m = echoSilent
		case "plaintext":
			m = echoPlaintext
		default:
			return defaultPasswordEchoCycle, false
		}
		if slices.Contains(cycle, m) {
			return defaultPasswordEchoCycle, false
		}
		cycle = append(cycle, m)
	}
	return cycle, true
}

// Prompt echo policy from the init config (password_echo). Set once in
// readConfig before any prompt is shown; read-only afterwards. The first
// entry is the prompt's startup mode; Tab advances through the cycle,
// wrapping. A single-entry cycle pins the prompt.
var passwordEchoCycle = defaultPasswordEchoCycle

// echoFor renders the visible form of password under mode: one asterisk per
// codepoint, nothing, or the literal bytes. Erase paths assume one terminal
// cell per codepoint; a double-width glyph echoed in plaintext mode leaves
// half a cell behind on backspace (cosmetic only — the buffer stays correct).
func echoFor(password []byte, mode passwordEchoMode) string {
	switch mode {
	case echoAsterisks:
		return strings.Repeat("*", countCodepoints(password))
	case echoPlaintext:
		return string(password)
	}
	return ""
}

// consoleMu serializes all stdout writes so that concurrent status message
// reprints and raw-mode keystroke echoes never interleave. Held briefly during
// every consolePrint call.
var consoleMu sync.Mutex

// consolePrompt tracks the active password prompt so statusMessage (declared
// in plymouth.go) can erase the current line, print the status, and reprint
// the prompt beneath it without losing the user's typed-echo state.
//
// Invariants (must hold while consoleMu is held):
//   - active == true iff a readPasswordOn is running and has finished its
//     initial prompt print
//   - text is the prompt string passed to readPasswordOn; statusMessage uses
//     it to redraw after writing a status line
//   - echoed is exactly the feedback currently painted after the prompt text
//     ("" in silent mode, asterisks, or the literal password in plaintext
//     mode); readPasswordOn maintains it with consoleMu held so redraw paths
//     can repaint prompt + feedback verbatim, and erase paths can remove
//     exactly countCodepoints(echoed) cells
//   - done mirrors the active prompt's ctx.Done(); statusMessage selects on
//     it to skip a redraw once the volume is unlocked by another method
//     (avoids redrawing a prompt that's about to be dismissed)
var consolePrompt struct {
	active bool
	text   string
	echoed string
	done   <-chan struct{}
}

// consolePrint writes msg without acquiring consoleMu. Callers must hold consoleMu.
func consolePrint(msg string) {
	if quirk.TestEnabled {
		_, _ = fmt.Fprint(devKmsg, "<", 2, ">booster: ", msg, "\n")
	} else {
		fmt.Print(msg)
	}
}

// consolePrintWithPromptRedraw writes msg to the console under consoleMu,
// re-painting any active password prompt below so the user's cursor stays
// at the bottom. Used by log levels (info, warning, severe) which would
// otherwise overwrite the prompt line mid-input.
//
// The live prompt line is erased in place before msg scrolls it away:
// otherwise the terminal archives it intact in scrollback, which in plaintext
// echo mode preserves the literal passphrase in history (and in the capture
// buffer of serial/IPMI consoles).
func consolePrintWithPromptRedraw(msg string) {
	consoleMu.Lock()
	defer consoleMu.Unlock()
	if consolePrompt.active && !promptVolumeUnlocked() {
		consoleEcho(eraseLine)
		consolePrint(msg + "\n" + consolePrompt.text + promptEchoedForPrint())
	} else {
		consolePrint(msg + "\n")
	}
}

// promptEchoedForPrint returns the prompt feedback to repaint after a status
// or log message. In qemu integration builds (-tags test) consolePrint writes
// to /dev/kmsg, where repainting the feedback would log the literal passphrase
// whenever the prompt is in plaintext mode — repaint nothing there (the
// per-keystroke echo is already suppressed by consoleEcho for the same
// reason). Callers must hold consoleMu.
func promptEchoedForPrint() string {
	if quirk.TestEnabled {
		return ""
	}
	return consolePrompt.echoed
}

// consoleEcho writes terminal-only decoration (asterisks, backspace, line-erase
// sequences) under consoleMu. In qemu integration builds (-tags test) it is a
// no-op: per-character writes to /dev/kmsg flood the kernel log without
// rendering anything useful (issue #360). readPasswordOn emits one summary
// "password typed" line at end-of-input to keep a breadcrumb in test logs.
// Callers must hold consoleMu.
func consoleEcho(msg string) {
	if quirk.TestEnabled {
		return
	}
	fmt.Print(msg)
}

// Terminal byte sequences written via consoleEcho.
const (
	eraseChar           = "\b \b"          // erase the character at the cursor
	eraseLine           = "\r\x1b[K"       // wipe the current line in place
	eraseLineAndAdvance = eraseLine + "\n" // wipe current line and move to next
)

var inputMutex sync.Mutex

// readPasswordLocked reads a password from stdin in raw terminal mode, echoing
// keystroke feedback per the configured password echo mode (asterisks by
// default). Cancels cleanly when ctx is done. The caller must hold inputMutex.
func readPasswordLocked(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
	return readPasswordOn(ctx, os.Stdin, prompt, postPrompt)
}

// readPasswordOn is the testable core of readPasswordLocked: same behavior, but
// reads/writes via the supplied tty (must be a real terminal — pipes will fail
// the termios ioctls). Production passes os.Stdin; tests pass a pty slave so
// they can exercise termios setup, the Poll loop, and ctx cancellation
// end-to-end. See TestReadPasswordOn* in console_input_pty_test.go.
//
// Read-loop design (the cancellable-read primitive):
//   - Termios is set to VMIN=1, VTIME=0: read(2) would block until 1 byte.
//   - Instead of calling Read directly, we poll(2) with a 100ms timeout.
//   - Between polls we check ctx.Err() — if cancelled, return ctx.Err()
//     within at most ~100ms, restore termios via defer, end the prompt
//     line with a newline, release inputMutex via the caller.
//   - This is the mechanism that fixes the "dangling prompt on autounlock
//     win" bug. Without it (cooked-mode bufio.Scanner), the read blocks in
//     read(2) until the user manually types something — meanwhile keyboardMu
//     and inputMutex stay held, blocking subsequent volumes' prompts.
//
// Why 100ms specifically: trades ctx-cancel responsiveness against
// wakeup overhead. 100ms is imperceptible to users (no input lag) but
// guarantees a prompt visual dismiss on autounlock. Could be tighter
// (10ms) at the cost of more wakeups on idle prompts; 100ms picks the
// "responsive enough" point.
//
// Termios contract (set in raw mode, restored on every return path via defer):
//   - ECHO off:    don't double-print typed bytes (we echo asterisks ourselves)
//   - ICANON off:  disable kernel line buffering — get every byte immediately
//   - IEXTEN off:  disable Ctrl+V quote-next and other extended processing
//   - ISIG ON:     keep Ctrl+C → SIGINT (intentional divergence from Plymouth)
//   - ICRNL/IXON/IXOFF/BRKINT/INPCK/ISTRIP/INLCR/IGNCR off: no input
//     translation or flow control. Notably IXON off means Ctrl+S no longer
//     freezes the prompt (a real bug fix vs upstream).
//   - VMIN=1, VTIME=0: each Read returns as soon as 1 byte is available.
func readPasswordOn(ctx context.Context, tty *os.File, prompt, postPrompt string) ([]byte, error) {
	fd := int(tty.Fd())

	// Drain type-ahead so prior keystrokes don't feed this prompt.
	_ = unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)

	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}

	// Raw mode: disable echo and canonical (line-buffered) input.
	// Keep ISIG so Ctrl+C still fires SIGINT.
	// Clear input transformations the kernel would otherwise apply:
	//   - ICRNL: CR-to-NL translation (we want raw CR, our scanner handles both)
	//   - IXON/IXOFF: software flow control (Ctrl+S would freeze the prompt)
	//   - IEXTEN: extended processing including Ctrl+V quote-next
	//   - BRKINT: break signal generation
	//   - INPCK/ISTRIP: parity checking (uncommon; defensive)
	//   - INLCR/IGNCR: NL-to-CR / CR-ignore translations
	raw := *termios
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.IEXTEN
	raw.Lflag |= unix.ISIG
	raw.Iflag &^= unix.ICRNL | unix.IXON | unix.IXOFF | unix.BRKINT |
		unix.INPCK | unix.ISTRIP | unix.INLCR | unix.IGNCR
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, err
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, termios)

	consoleMu.Lock()
	consolePrint(prompt)
	consolePrompt.active = true
	consolePrompt.text = prompt
	consolePrompt.echoed = ""
	consolePrompt.done = ctx.Done()
	consoleMu.Unlock()

	defer func() {
		consoleMu.Lock()
		consolePrompt.active = false
		consolePrompt.done = nil
		consoleMu.Unlock()
	}()

	// cancelRead is the cleanup hook for ctx-cancellation mid-prompt: flush
	// type-ahead so partial bytes don't bleed into the next prompt, mark the
	// prompt inactive, erase the prompt line so it doesn't linger on screen,
	// and return ctx.Err() so the caller can distinguish cancel from "user
	// pressed Enter". Termios restoration happens via defer above.
	cancelRead := func() ([]byte, error) {
		_ = unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
		consoleMu.Lock()
		consolePrompt.active = false
		consoleEcho(eraseLineAndAdvance)
		consoleMu.Unlock()
		return nil, ctx.Err()
	}

	var password []byte
	cycle := passwordEchoCycle
	modeIdx := 0
	mode := cycle[modeIdx]
	var b [1]byte
	var scanner inputScanner
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
loop:
	for {
		if _, err := unix.Poll(fds, 100); err != nil && err != unix.EINTR {
			return nil, err
		}
		if ctx.Err() != nil {
			return cancelRead()
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, err := tty.Read(b[:])
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if n == 0 {
			// Read is permitted to return (0, nil); guard against replaying b[0]
			// from the previous iteration.
			continue
		}
		ev, ch := scanner.Feed(b[0])
		switch ev {
		case keyEnter:
			break loop
		case keyEOF:
			// Ctrl+D: traditional EOF semantics — end input only if the buffer is
			// empty (so the user can skip the prompt). Otherwise no-op so a fat-
			// fingered Ctrl+D mid-passphrase doesn't silently submit a partial.
			if len(password) == 0 {
				break loop
			}
		case keyChar:
			// ch holds one complete codepoint (1–4 bytes).
			password = append(password, ch...)
			if add := echoFor(ch, mode); add != "" {
				consoleMu.Lock()
				consolePrompt.echoed += add
				consoleEcho(add)
				consoleMu.Unlock()
			}
		case keyBackspace:
			if len(password) > 0 {
				// Remove the last UTF-8 codepoint from the buffer.
				password = trimLastCodepoint(password)
				if mode != echoSilent {
					consoleMu.Lock()
					consolePrompt.echoed = string(trimLastCodepoint([]byte(consolePrompt.echoed)))
					consoleEcho(eraseChar)
					consoleMu.Unlock()
				}
			}
		case keyTab: // advance the echo mode through the configured cycle
			if len(cycle) < 2 {
				// Single-mode cycle: the prompt is pinned; Tab is ignored (and
				// never lands in the password — the scanner ate the byte).
				continue
			}
			consoleMu.Lock()
			for range countCodepoints([]byte(consolePrompt.echoed)) {
				consoleEcho(eraseChar)
			}
			modeIdx = (modeIdx + 1) % len(cycle)
			mode = cycle[modeIdx]
			consolePrompt.echoed = echoFor(password, mode)
			consoleEcho(consolePrompt.echoed)
			consoleMu.Unlock()
		case keyKillLine: // Ctrl+U — erase entire password
			if len(password) > 0 {
				consoleMu.Lock()
				for range countCodepoints([]byte(consolePrompt.echoed)) {
					consoleEcho(eraseChar)
				}
				consolePrompt.echoed = ""
				consoleMu.Unlock()
				password = password[:0]
			}
		case keyKillWord: // Ctrl+W — erase back to last whitespace
			if len(password) > 0 {
				newPwd, removed := killWord(password)
				if removed > 0 {
					if mode != echoSilent {
						consoleMu.Lock()
						for range removed {
							consolePrompt.echoed = string(trimLastCodepoint([]byte(consolePrompt.echoed)))
							consoleEcho(eraseChar)
						}
						consoleMu.Unlock()
					}
					password = newPwd
				}
			}
			// keyNone: mid-sequence, do nothing
		}
	}

	if postPrompt != "" {
		// Newline before the postPrompt so it renders on its own line below
		// the typed asterisks, not glued to the right of them.
		console("\n" + postPrompt)
	}
	if !quirk.TestEnabled {
		console("\n")
	} else if len(password) > 0 {
		// Replace the per-keystroke asterisks consoleEcho suppressed in
		// test builds with one breadcrumb line — issue #360.
		info("password typed (%d chars)", countCodepoints(password))
	}
	return password, nil
}

func readPassword(ctx context.Context, prompt, postPrompt string) ([]byte, error) {
	inputMutex.Lock()
	defer inputMutex.Unlock()
	return readPasswordLocked(ctx, prompt, postPrompt)
}
