package display

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateASCII(t *testing.T) {
	cases := []struct {
		s      string
		length int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 8, "hello..."},
		{"hello world", 4, "h..."},
	}
	for _, c := range cases {
		if got := Truncate(c.s, c.length); got != c.want {
			t.Errorf("Truncate(%q, %d): want %q, got %q", c.s, c.length, c.want, got)
		}
	}
}

func TestTruncateSmallLengthNoPanic(t *testing.T) {
	// Pre-fix code panicked via s[:length-3] for length < 3.
	cases := []struct {
		s      string
		length int
		want   string
	}{
		{"hello", 3, "hel"},
		{"hello", 2, "he"},
		{"hello", 1, "h"},
		{"hello", 0, ""},
		{"hello", -1, ""},
	}
	for _, c := range cases {
		if got := Truncate(c.s, c.length); got != c.want {
			t.Errorf("Truncate(%q, %d): want %q, got %q", c.s, c.length, c.want, got)
		}
	}
}

func TestTruncateRuneSafety(t *testing.T) {
	// Cyrillic: every letter is 2 bytes in UTF-8.
	s := "привет мир" // 19 bytes
	for length := 0; length <= len(s)+1; length++ {
		got := Truncate(s, length)
		if !utf8.ValidString(got) {
			t.Errorf("Truncate(%q, %d) produced invalid UTF-8: %q", s, length, got)
		}
		if length >= 0 && len(got) > len(s) {
			t.Errorf("Truncate(%q, %d) grew the string: %q", s, length, got)
		}
		if len(s) > length && length > 3 && len(got) > length {
			t.Errorf("Truncate(%q, %d) exceeds length: %q (%d bytes)", s, length, got, len(got))
		}
	}
	// Cut lands mid-rune: must back off to the previous boundary.
	if got := Truncate(s, 8); got != "пр..." {
		t.Errorf("mid-rune cut: want %q, got %q", "пр...", got)
	}
}

func TestSanitizeTerminal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"clean ascii", "CN=example.com", "CN=example.com"},
		{"ansi escape", "\x1b[31mevil\x1b[0m", "\uFFFD[31mevil\uFFFD[0m"},
		{"bel", "ding\a", "ding\uFFFD"},
		{"del", "x\x7fy", "x\uFFFDy"},
		{"null", "a\x00b", "a\uFFFDb"},
		{"newline tab cr preserved", "a\nb\tc\rd", "a\nb\tc\rd"},
		{"emoji and cyrillic preserved", "⚠️ привет 🙂", "⚠️ привет 🙂"},
		{"osc title injection", "\x1b]0;pwned\x07", "\uFFFD]0;pwned\uFFFD"},
	}
	for _, c := range cases {
		if got := SanitizeTerminal(c.in); got != c.want {
			t.Errorf("%s: SanitizeTerminal(%q): want %q, got %q", c.name, c.in, c.want, got)
		}
	}
}

func TestSanitizeTerminalFastPathReturnsSameString(t *testing.T) {
	in := strings.Repeat("clean ", 10)
	if got := SanitizeTerminal(in); got != in {
		t.Errorf("clean input must be returned unchanged")
	}
}

func TestSanitizeField(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"clean ascii", "CN=example.com", "CN=example.com"},
		{"c0 escape", "\x1b[31mevil", "\uFFFD[31mevil"},
		{"del", "x\x7fy", "x\uFFFDy"},
		{"null", "a\x00b", "a\uFFFDb"},
		// C1 as UTF-8. U+009B is the 8-bit CSI, U+009D the 8-bit OSC.
		{"c1 as utf8 (csi)", "c\u009b31m", "c\uFFFD31m"},
		{"c1 as utf8 (osc)", "c\u009d2J", "c\uFFFD2J"},
		// C1 as a raw invalid byte: the carrier an IA5-unchecked AIA/CRL
		// general name can supply. A range loop yields RuneError/size 1 here,
		// so a predicate testing only unicode.IsControl would miss it.
		{"c1 as raw byte", "c\x9b31m", "c\uFFFD31m"},
		{"invalid byte alone", "\x80", "\uFFFD"},
		// Unlike SanitizeTerminal, a field has no legitimate line breaks.
		{"lf", "a\nb", "a\uFFFDb"},
		{"cr", "a\rb", "a\uFFFDb"},
		{"tab", "a\tb", "a\uFFFDb"},
		{"crlf", "a\r\nb", "a\uFFFD\uFFFDb"},
		{"printable and multibyte preserved", "⚠️ привет 🙂 日本語", "⚠️ привет 🙂 日本語"},
		{"genuine replacement rune preserved", "a\uFFFDb", "a\uFFFDb"},
	}
	for _, c := range cases {
		if got := SanitizeField(c.in); got != c.want {
			t.Errorf("%s: SanitizeField(%q): want %q, got %q", c.name, c.in, c.want, got)
		}
	}
}

func TestSanitizeFieldFastPathReturnsSameString(t *testing.T) {
	in := strings.Repeat("clean ", 10)
	if got := SanitizeField(in); got != in {
		t.Errorf("clean input must be returned unchanged")
	}
}

// SanitizeTerminal is applied to already-composed messages, so its allow-list
// for \n, \r and \t is load-bearing: tightening it here would strip every
// formatter newline and collapse all human output into one line. Pinned so a
// later edit cannot silently do that.
func TestSanitizeTerminalUnchanged(t *testing.T) {
	critical := []struct {
		in   string
		want string
	}{
		{"a\nb", "a\nb"},
		{"a\rb", "a\rb"},
		{"a\tb", "a\tb"},
		{"line one\nline two\n", "line one\nline two\n"},
	}
	for _, c := range critical {
		if got := SanitizeTerminal(c.in); got != c.want {
			t.Errorf("SanitizeTerminal(%q) = %q, want %q: the composed-message allow-list changed", c.in, got, c.want)
		}
	}
	// And the documented C0/DEL behaviour stays put.
	if got := SanitizeTerminal("\x1b[31m"); got != "\uFFFD[31m" {
		t.Errorf("SanitizeTerminal C0 handling changed: got %q", got)
	}
}

func TestSanitizeFields(t *testing.T) {
	if got := SanitizeFields(nil); got != nil {
		t.Errorf("nil input must return nil, got %#v", got)
	}
	if got := SanitizeFields([]string{}); got != nil {
		t.Errorf("empty input must return nil, got %#v", got)
	}
	got := SanitizeFields([]string{"ok", "a\nb", "c\u009bd"})
	want := []string{"ok", "a\uFFFDb", "c\uFFFDd"}
	if len(got) != len(want) {
		t.Fatalf("SanitizeFields returned %d elements, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SanitizeFields[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
