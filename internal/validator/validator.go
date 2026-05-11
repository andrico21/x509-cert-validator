// Package validator provides the verbosity model and Logger interface
// shared by the validation subpackages (certload, aia, crl, etc.).
//
// This package is intentionally small in PR5b Step E: it defines the
// Logger surface plus a stderr-backed default implementation so the
// soon-to-be-extracted subpackages have a stable seam to log through.
// The Validator struct that owns shared HTTP client + run-scoped state
// will land in a follow-up step once the subpackages are in place.
package validator

import (
	"fmt"
	"io"
	"os"
)

// Verbosity selects the user-facing output level for a validation run.
// Values mirror the original main-package constants verbatim so that
// callers can keep using literal 0/1/2 when interoperating.
type Verbosity int

const (
	// LevelNormal prints all diagnostic output (default).
	LevelNormal Verbosity = 0
	// LevelSilent suppresses normal output; only a single FAIL line is
	// emitted on failure (via Logger.Fail).
	LevelSilent Verbosity = 1
	// LevelUltraSilent suppresses all output; only the process exit
	// code communicates pass/fail.
	LevelUltraSilent Verbosity = 2
)

// Logger is the minimal logging surface used by the validation
// subpackages. Implementations decide where output goes (stdout for
// normal user-facing diagnostics, stderr for FAIL/error lines per
// CLI convention) and which verbosity level gates which method.
//
// Methods MUST be safe to call regardless of verbosity; gating is the
// implementation's responsibility.
type Logger interface {
	// Normal prints user-facing diagnostic output. Suppressed when
	// verbosity is Silent or UltraSilent.
	Normal(format string, args ...any)
	// Verbosity returns the configured level so callers can short-circuit
	// expensive formatting (e.g. building ASCII chain graphs) when output
	// would be discarded anyway.
	Verbosity() Verbosity
}

// StderrLogger is the default Logger implementation. Normal diagnostics
// go to a configurable Out writer (defaults to os.Stdout); error/FAIL
// lines go to a configurable Err writer (defaults to os.Stderr).
//
// The split exists so tests can capture each stream independently and so
// callers preserve the long-standing CLI convention of writing
// validation diagnostics to stdout while keeping FAIL lines and panics
// on stderr.
type StderrLogger struct {
	Level Verbosity
	Out   io.Writer // defaults to os.Stdout if nil
	Err   io.Writer // defaults to os.Stderr if nil (reserved for Fail/error paths added later)
}

// NewStderrLogger constructs a StderrLogger at the given verbosity that
// writes diagnostics to os.Stdout and errors to os.Stderr.
func NewStderrLogger(level Verbosity) *StderrLogger {
	return &StderrLogger{Level: level, Out: os.Stdout, Err: os.Stderr}
}

// Normal implements Logger.Normal. Output is discarded unless verbosity
// is LevelNormal, matching the original main-package logNormal helper.
func (l *StderrLogger) Normal(format string, args ...any) {
	if l.Level != LevelNormal {
		return
	}
	w := l.Out
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprintf(w, format, args...)
}

// Verbosity implements Logger.Verbosity.
func (l *StderrLogger) Verbosity() Verbosity { return l.Level }
