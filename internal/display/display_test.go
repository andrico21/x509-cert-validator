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
