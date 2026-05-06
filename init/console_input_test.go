package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// feedAll feeds every byte in input to the scanner and collects the non-None
// events.  Each returned entry is (event, chars-snapshot).
type scanResult struct {
	event keyEvent
	chars []byte
}

func feedAll(s *inputScanner, input []byte) []scanResult {
	var out []scanResult
	for _, b := range input {
		ev, ch := s.Feed(b)
		if ev != keyNone {
			cp := make([]byte, len(ch))
			copy(cp, ch)
			out = append(out, scanResult{ev, cp})
		}
	}
	return out
}

// ── Arrow keys / CSI sequences ──────────────────────────────────────────────

func TestScannerArrowKeysConsumed(t *testing.T) {
	// Up/Down/Right/Left arrow → \x1b[A–D must all be silently dropped.
	for _, seq := range []string{"\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D"} {
		var s inputScanner
		results := feedAll(&s, []byte(seq))
		require.Empty(t, results, "arrow %q must produce no events", seq)
	}
}

func TestScannerBracketedPasteMarkersConsumed(t *testing.T) {
	// \x1b[200~ and \x1b[201~ must be consumed entirely — they must not produce
	// keyChar events.
	for _, marker := range []string{"\x1b[200~", "\x1b[201~"} {
		var s inputScanner
		results := feedAll(&s, []byte(marker))
		require.Empty(t, results, "paste marker %q must produce no events", marker)
	}
}

func TestScannerFunctionKeysConsumed(t *testing.T) {
	// Linux function-key sequences \x1b[[A–E (F1–F5) must be consumed.
	for _, seq := range []string{"\x1b[[A", "\x1b[[B", "\x1b[[C", "\x1b[[D", "\x1b[[E"} {
		var s inputScanner
		results := feedAll(&s, []byte(seq))
		require.Empty(t, results, "function key %q must produce no events", seq)
	}
}

func TestScannerSS3SequencesConsumed(t *testing.T) {
	// SS3 sequences \x1bOA–Z must be consumed (Home/End/PF-keys).
	for _, seq := range []string{"\x1bOA", "\x1bOP", "\x1bOZ"} {
		var s inputScanner
		results := feedAll(&s, []byte(seq))
		require.Empty(t, results, "SS3 %q must produce no events", seq)
	}
}

func TestScannerCSIAfterArrowNormalTyping(t *testing.T) {
	// \x1b[A (arrow) followed by "abc" — arrow consumed, "abc" comes through.
	var s inputScanner
	results := feedAll(&s, []byte("\x1b[Aabc"))
	require.Equal(t, 3, len(results))
	require.Equal(t, keyChar, results[0].event)
	require.Equal(t, []byte("a"), results[0].chars)
	require.Equal(t, keyChar, results[1].event)
	require.Equal(t, []byte("b"), results[1].chars)
	require.Equal(t, keyChar, results[2].event)
	require.Equal(t, []byte("c"), results[2].chars)
}

// ── UTF-8 multi-byte ─────────────────────────────────────────────────────────

func TestScannerUTF8TwoByteCodepoint(t *testing.T) {
	// é = U+00E9 = 0xc3 0xa9 — two bytes, one keyChar event.
	var s inputScanner
	results := feedAll(&s, []byte{0xc3, 0xa9})
	require.Equal(t, 1, len(results), "two-byte codepoint must emit one keyChar")
	require.Equal(t, keyChar, results[0].event)
	require.Equal(t, []byte{0xc3, 0xa9}, results[0].chars)
}

func TestScannerUTF8ThreeByteCodepoint(t *testing.T) {
	// € = U+20AC = 0xe2 0x82 0xac
	var s inputScanner
	results := feedAll(&s, []byte{0xe2, 0x82, 0xac})
	require.Equal(t, 1, len(results))
	require.Equal(t, keyChar, results[0].event)
	require.Equal(t, []byte{0xe2, 0x82, 0xac}, results[0].chars)
}

func TestScannerUTF8FourByteCodepoint(t *testing.T) {
	// 𝄞 = U+1D11E = 0xf0 0x9d 0x84 0x9e
	var s inputScanner
	results := feedAll(&s, []byte{0xf0, 0x9d, 0x84, 0x9e})
	require.Equal(t, 1, len(results))
	require.Equal(t, keyChar, results[0].event)
	require.Equal(t, []byte{0xf0, 0x9d, 0x84, 0x9e}, results[0].chars)
}

func TestScannerUTF8SplitAcrossFeedCalls(t *testing.T) {
	// Simulate partial read: the two bytes of 'é' arrive in separate Feed calls.
	// The first byte must return keyNone; the second must complete the codepoint.
	var s inputScanner

	ev, ch := s.Feed(0xc3) // lead byte of é
	require.Equal(t, keyNone, ev, "lead byte alone must not emit an event")
	require.Nil(t, ch)

	ev, ch = s.Feed(0xa9) // continuation byte
	require.Equal(t, keyChar, ev, "completing continuation must emit keyChar")
	require.Equal(t, []byte{0xc3, 0xa9}, ch)
}

func TestScannerUTF8MixedWithASCII(t *testing.T) {
	// "héllo" — h(ASCII) + é(2-byte) + l + l + o
	var s inputScanner
	input := []byte("h\xc3\xa9llo")
	results := feedAll(&s, input)
	require.Equal(t, 5, len(results), "héllo must emit 5 keyChar events (one per codepoint)")

	require.Equal(t, []byte("h"), results[0].chars)
	require.Equal(t, []byte{0xc3, 0xa9}, results[1].chars) // é
	require.Equal(t, []byte("l"), results[2].chars)
	require.Equal(t, []byte("l"), results[3].chars)
	require.Equal(t, []byte("o"), results[4].chars)
}

// ── Control keys ─────────────────────────────────────────────────────────────

func TestScannerCtrlU(t *testing.T) {
	var s inputScanner
	ev, _ := s.Feed(0x15) // Ctrl+U
	require.Equal(t, keyKillLine, ev)
}

func TestScannerCtrlW(t *testing.T) {
	var s inputScanner
	ev, _ := s.Feed(0x17) // Ctrl+W
	require.Equal(t, keyKillWord, ev)
}

func TestScannerEnterCRLF(t *testing.T) {
	for _, b := range []byte{'\r', '\n'} {
		var s inputScanner
		ev, _ := s.Feed(b)
		require.Equal(t, keyEnter, ev, "byte 0x%02x must be keyEnter", b)
	}
}

func TestScannerCtrlDIsKeyEOF(t *testing.T) {
	// Ctrl+D emits keyEOF (distinct from keyEnter) so readPasswordOn can
	// gate behaviour on buffer length: end on empty buffer, no-op otherwise.
	var s inputScanner
	ev, _ := s.Feed(0x04)
	require.Equal(t, keyEOF, ev)
}

func TestScannerBackspace(t *testing.T) {
	for _, b := range []byte{0x08, 0x7f} {
		var s inputScanner
		ev, _ := s.Feed(b)
		require.Equal(t, keyBackspace, ev, "byte 0x%02x must be keyBackspace", b)
	}
}

func TestScannerTab(t *testing.T) {
	var s inputScanner
	ev, _ := s.Feed(0x09)
	require.Equal(t, keyTab, ev)
}

// ── Plain ASCII passthrough ──────────────────────────────────────────────────

func TestScannerPrintableASCII(t *testing.T) {
	var s inputScanner
	results := feedAll(&s, []byte("hello"))
	require.Equal(t, 5, len(results))
	for i, r := range results {
		require.Equal(t, keyChar, r.event, "char %d", i)
		require.Equal(t, []byte{[]byte("hello")[i]}, r.chars)
	}
}

func TestScannerNonPrintableControlDropped(t *testing.T) {
	// 0x01, 0x02, 0x1f are not any of the mapped control bytes — must drop.
	for _, b := range []byte{0x01, 0x02, 0x1f} {
		var s inputScanner
		ev, _ := s.Feed(b)
		require.Equal(t, keyNone, ev, "byte 0x%02x must be dropped", b)
	}
}

func TestScannerHighASCIIDropped(t *testing.T) {
	// 0x80 is an unexpected byte (not a valid UTF-8 lead in isolation) — drop.
	// 0xff is also invalid.
	for _, b := range []byte{0x80, 0xff} {
		var s inputScanner
		ev, _ := s.Feed(b)
		require.Equal(t, keyNone, ev, "invalid high byte 0x%02x must be dropped", b)
	}
}

// ── Multi-sequence interaction ───────────────────────────────────────────────

func TestScannerBracketedPasteWithPayload(t *testing.T) {
	// \x1b[200~ hello \x1b[201~ — markers consumed, "hello" passes through.
	var s inputScanner
	input := []byte("\x1b[200~hello\x1b[201~")
	results := feedAll(&s, input)

	var chars []byte
	for _, r := range results {
		if r.event == keyChar {
			chars = append(chars, r.chars...)
		}
	}
	require.Equal(t, []byte("hello"), chars)
}

func TestScannerMultipleArrowsThenTyping(t *testing.T) {
	// Three arrow keys then "pw" — arrows consumed, "pw" emitted.
	var s inputScanner
	input := []byte("\x1b[A\x1b[B\x1b[Cpw")
	results := feedAll(&s, input)

	var chars []byte
	for _, r := range results {
		if r.event == keyChar {
			chars = append(chars, r.chars...)
		}
	}
	require.Equal(t, []byte("pw"), chars)
}

func TestScannerCtrlUAfterChars(t *testing.T) {
	// "abc" then Ctrl+U — three keyChar events then one keyKillLine.
	var s inputScanner
	results := feedAll(&s, []byte("abc\x15"))
	require.Equal(t, 4, len(results))
	require.Equal(t, keyChar, results[0].event)
	require.Equal(t, keyChar, results[1].event)
	require.Equal(t, keyChar, results[2].event)
	require.Equal(t, keyKillLine, results[3].event)
}

func TestScannerCtrlWAfterWord(t *testing.T) {
	// "foo bar" then Ctrl+W — chars then keyKillWord.
	var s inputScanner
	results := feedAll(&s, []byte("foo bar\x17"))
	var events []keyEvent
	for _, r := range results {
		events = append(events, r.event)
	}
	require.Equal(t, keyKillWord, events[len(events)-1])
}

// ── OSC / DCS escape-sequence handling ───────────────────────────────────────

func TestScannerOSCBodyDoesNotLeakIntoPassword(t *testing.T) {
	// OSC 52 (set clipboard) terminated by BEL: body and terminator must be
	// silently consumed, not leaked into the password buffer.
	var s inputScanner
	input := []byte("\x1b]52;c;malicious\x07hello")
	results := feedAll(&s, input)

	var chars []byte
	for _, r := range results {
		if r.event == keyChar {
			chars = append(chars, r.chars...)
		}
	}
	require.Equal(t, []byte("hello"), chars, "OSC body must not leak into password")
}

func TestScannerOSCBodyTerminatedByST(t *testing.T) {
	// OSC terminated by 7-bit ST (\x1b\\): body consumed, "x" passes through.
	var s inputScanner
	input := []byte("\x1b]0;title\x1b\\x")
	results := feedAll(&s, input)

	var chars []byte
	for _, r := range results {
		if r.event == keyChar {
			chars = append(chars, r.chars...)
		}
	}
	require.Equal(t, []byte("x"), chars)
}

func TestScannerDCSBodyConsumed(t *testing.T) {
	// DCS body terminated by ST: payload consumed, "y" passes through.
	var s inputScanner
	input := []byte("\x1bP1;2qpayload\x1b\\y")
	results := feedAll(&s, input)

	var chars []byte
	for _, r := range results {
		if r.event == keyChar {
			chars = append(chars, r.chars...)
		}
	}
	require.Equal(t, []byte("y"), chars)
}

// ── Bracketed-paste mode ─────────────────────────────────────────────────────

func TestScannerBracketedPasteEmbeddedControlBytesLiteral(t *testing.T) {
	// Inside paste mode, control bytes must be treated as literal characters
	// rather than triggering backspace / kill-line / submit.
	var s inputScanner
	// "ab\x08c" inside paste — no backspace; all 4 bytes pass through.
	input := []byte("\x1b[200~ab\x08c\x1b[201~")
	results := feedAll(&s, input)

	var chars []byte
	var events []keyEvent
	for _, r := range results {
		events = append(events, r.event)
		if r.event == keyChar {
			chars = append(chars, r.chars...)
		}
	}
	require.Equal(t, []byte{'a', 'b', 0x08, 'c'}, chars,
		"control bytes inside paste must pass through literally")
	for _, ev := range events {
		require.NotEqual(t, keyBackspace, ev, "no backspace events in paste mode")
		require.NotEqual(t, keyEnter, ev, "no enter events in paste mode")
	}
}

func TestScannerBracketedPasteEmbeddedNewlineLiteral(t *testing.T) {
	// A pasted newline inside bracketed-paste must NOT trigger early submit.
	var s inputScanner
	input := []byte("\x1b[200~line1\nline2\x1b[201~")
	results := feedAll(&s, input)

	var chars []byte
	var events []keyEvent
	for _, r := range results {
		events = append(events, r.event)
		if r.event == keyChar {
			chars = append(chars, r.chars...)
		}
	}
	require.Equal(t, []byte("line1\nline2"), chars)
	for _, ev := range events {
		require.NotEqual(t, keyEnter, ev, "pasted newline must not submit")
	}
}

// ── CSI parameter accumulator bound ──────────────────────────────────────────

func TestScannerCSIParamOverflowAbortsAndRecovers(t *testing.T) {
	// A CSI with more parameter bytes than the accumulator holds (16) must
	// abort the sequence rather than swallow keystrokes indefinitely. After
	// abort, normal typing must resume.
	var s inputScanner
	// 32 digits then a final byte — overflows the param buffer.
	long := append([]byte("\x1b["), []byte("12345678901234567890123456789012")...)
	long = append(long, 'm')
	long = append(long, []byte("typed")...) // these must still emit keyChar
	results := feedAll(&s, long)

	var chars []byte
	for _, r := range results {
		if r.event == keyChar {
			chars = append(chars, r.chars...)
		}
	}
	// After CSI abort, the digits/'m' may or may not appear (acceptable either
	// way) but "typed" must definitely come through — proving the scanner
	// recovered from CSI state.
	require.Contains(t, string(chars), "typed",
		"scanner must recover from CSI param overflow")
}

// ── UTF-8 validation ─────────────────────────────────────────────────────────

func TestScannerUTF8RejectsOverlongAndOutOfRange(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		// Overlong encoding of 'A' (U+0041) as 2 bytes: 0xc1 0x81 — invalid.
		{"overlong A", []byte{0xc1, 0x81}},
		// Surrogate U+D800 encoded as 3-byte UTF-8: 0xed 0xa0 0x80 — invalid.
		{"surrogate U+D800", []byte{0xed, 0xa0, 0x80}},
		// Codepoint above U+10FFFF: 0xf4 0x90 0x80 0x80 (= U+110000) — invalid.
		{"above U+10FFFF", []byte{0xf4, 0x90, 0x80, 0x80}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s inputScanner
			results := feedAll(&s, tc.input)
			for _, r := range results {
				require.NotEqual(t, keyChar, r.event,
					"invalid UTF-8 (%s) must not emit keyChar", tc.name)
			}
		})
	}
}

// TestScannerUTF8ThreeByteSplitOneByteAtATime verifies the FSM handles a
// 3-byte UTF-8 codepoint arriving as 1+1+1 across three Feed() calls. Realistic
// for slow serial / IPMI consoles where each byte may arrive in its own read.
func TestScannerUTF8ThreeByteSplitOneByteAtATime(t *testing.T) {
	// '€' = U+20AC = 0xe2 0x82 0xac
	var s inputScanner

	ev, ch := s.Feed(0xe2)
	require.Equal(t, keyNone, ev, "first lead byte alone must not emit")
	require.Nil(t, ch)

	ev, ch = s.Feed(0x82)
	require.Equal(t, keyNone, ev, "first continuation alone must not emit")
	require.Nil(t, ch)

	ev, ch = s.Feed(0xac)
	require.Equal(t, keyChar, ev, "second continuation must complete the codepoint")
	require.Equal(t, []byte{0xe2, 0x82, 0xac}, ch)
}

// TestKillWord pins down killWord's contract on the boundary inputs:
// trailing whitespace is consumed first, then the trailing word.
func TestKillWord(t *testing.T) {
	cases := []struct {
		name      string
		input     []byte
		want      []byte
		wantCount int
	}{
		{"empty", []byte{}, []byte{}, 0},
		{"single word", []byte("word"), []byte{}, 4},
		{"word then spaces", []byte("word   "), []byte{}, 7},
		{"word space word", []byte("a b"), []byte("a "), 1},
		{"trailing space then word", []byte("a b "), []byte("a "), 2},
		{"only spaces", []byte("   "), []byte{}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, n := killWord(tc.input)
			require.Equal(t, tc.want, got, "killWord(%q) result", tc.input)
			require.Equal(t, tc.wantCount, n, "killWord(%q) removed-count", tc.input)
		})
	}
}
