package validator

import (
	"bytes"
	"strings"
	"testing"
)

// TestWarnRecordsWhenPrintingIsGated pins the invariant the JSON channel
// depends on: a warning must be collected even when nothing is printed. If
// Warn returned early under JSON mode or at a silent verbosity, the -json
// document would lose exactly the diagnostics it exists to carry - which
// would be worse than printing them to stdout, since nothing would remain.
func TestWarnRecordsWhenPrintingIsGated(t *testing.T) {
	cases := []struct {
		name     string
		level    Verbosity
		jsonMode bool
		prints   bool
	}{
		{"normal verbosity, human output", LevelNormal, false, true},
		{"normal verbosity, json output", LevelNormal, true, false},
		{"silent, human output", LevelSilent, false, false},
		{"ultra-silent, human output", LevelUltraSilent, false, false},
		{"silent, json output", LevelSilent, true, false},
	}

	for _, c := range cases {
		var buf bytes.Buffer
		l := &StderrLogger{Level: c.level, Out: &buf, JSONMode: c.jsonMode}
		l.Warn("warning %d: %s\n", 1, "detail")

		if got := l.Warnings(); len(got) != 1 {
			t.Errorf("%s: collected %d warnings, want 1", c.name, len(got))
			continue
		}
		// The recorded copy is trimmed of the trailing newline so it can be
		// carried in a JSON string without stray line breaks.
		if want := "warning 1: detail"; l.Warnings()[0] != want {
			t.Errorf("%s: recorded %q, want %q", c.name, l.Warnings()[0], want)
		}

		printed := buf.Len() > 0
		if printed != c.prints {
			t.Errorf("%s: printed=%v, want %v (output %q)", c.name, printed, c.prints, buf.String())
		}
	}
}

// TestNormalSuppressedInJSONMode is the regression for stdout pollution: the
// JSON document is written to stdout, so a diagnostic printed there makes the
// stream unparseable.
func TestNormalSuppressedInJSONMode(t *testing.T) {
	var buf bytes.Buffer
	l := &StderrLogger{Level: LevelNormal, Out: &buf, JSONMode: true}
	l.Normal("progress line\n")
	if buf.Len() != 0 {
		t.Errorf("Normal wrote %q in JSON mode; stdout must stay a pure document", buf.String())
	}

	// And it still prints when JSON mode is off.
	buf.Reset()
	l.JSONMode = false
	l.Normal("progress line\n")
	if !strings.Contains(buf.String(), "progress line") {
		t.Errorf("Normal suppressed outside JSON mode; got %q", buf.String())
	}
}

// TestWarningsOrderAndAccumulation checks the collector is append-only and
// ordered, since the JSON array is read in that order.
func TestWarningsOrderAndAccumulation(t *testing.T) {
	l := NewStderrLogger(LevelUltraSilent) // no printing at all
	if got := l.Warnings(); len(got) != 0 {
		t.Errorf("fresh logger has %d warnings, want 0", len(got))
	}
	l.Warn("first")
	l.Warn("second %s", "arg")
	got := l.Warnings()
	if len(got) != 2 || got[0] != "first" || got[1] != "second arg" {
		t.Errorf("warnings = %q, want [first, second arg]", got)
	}
}
