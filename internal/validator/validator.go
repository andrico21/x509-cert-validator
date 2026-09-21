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
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andrico21/x509-cert-validator/internal/display"
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
	// Warn records a security-relevant diagnostic and prints it under the
	// same rules as Normal. Recording is independent of both verbosity and
	// output format: the collected set is the machine-readable channel that
	// -json exposes, so a caller that only prints would lose the warning
	// exactly when a machine consumer needs it.
	Warn(format string, args ...any)
	// Warnings returns the warnings recorded so far, in order. The caller
	// must not mutate the returned slice.
	Warnings() []string
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

	// JSONMode suppresses printing, because stdout then carries the JSON
	// document and any prose written ahead of it makes that document
	// unparseable. Warnings are still collected.
	JSONMode bool

	// warnings is append-only for the life of a run. The validation paths
	// are sequential (no goroutines in aia/crl/main), so no lock is needed.
	warnings []string
}

// NewStderrLogger constructs a StderrLogger at the given verbosity that
// writes diagnostics to os.Stdout and errors to os.Stderr.
func NewStderrLogger(level Verbosity) *StderrLogger {
	return &StderrLogger{Level: level, Out: os.Stdout, Err: os.Stderr}
}

// Normal implements Logger.Normal. Output is discarded unless verbosity
// is LevelNormal, matching the original main-package logNormal helper,
// and is also discarded in JSON mode so stdout stays a pure document.
// The formatted output passes through display.SanitizeTerminal so
// untrusted certificate fields logged by subpackages (aia, crl) cannot
// inject terminal escape sequences.
func (l *StderrLogger) Normal(format string, args ...any) {
	if l.Level != LevelNormal || l.JSONMode {
		return
	}
	w := l.Out
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprint(w, display.SanitizeTerminal(fmt.Sprintf(format, args...)))
}

// Warn implements Logger.Warn. The message is always recorded; printing
// follows Normal's rules (normal verbosity, not JSON mode). Recording
// before the gate is deliberate: if it happened after, JSON mode would
// convert "stdout polluted" into "diagnostic silently lost".
func (l *StderrLogger) Warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.warnings = append(l.warnings, strings.TrimRight(msg, "\n"))
	if l.Level != LevelNormal || l.JSONMode {
		return
	}
	w := l.Out
	if w == nil {
		w = os.Stdout
	}
	fmt.Fprint(w, display.SanitizeTerminal(msg))
}

// Warnings implements Logger.Warnings. The returned slice is the live
// backing array; callers must not mutate it.
func (l *StderrLogger) Warnings() []string { return l.warnings }

// Verbosity implements Logger.Verbosity.
func (l *StderrLogger) Verbosity() Verbosity { return l.Level }

// Validator carries the run-scoped dependencies shared by every network
// caller during a single validation run: a *http.Client (so connection
// pooling benefits accrue across AIA + CRL + remote-cert fetches), a
// Logger for progress output, the per-fetch timeout, and the four
// independent download size caps.
//
// Construct once per main() invocation; pass to aia.NewFetcher and
// crl.NewChecker so both subpackages share the same client + logger.
//
// Validator does NOT own configuration parsing (cli.Config does) and
// does NOT own per-cert printing (those helpers remain in main until
// PR5b Step J relocates them). Its sole responsibility is supplying
// pre-configured network plumbing.
type Validator struct {
	HTTPClient      *http.Client
	Logger          Logger
	PerFetchTimeout time.Duration

	MaxAIABytes        int64
	MaxCRLBytes        int64
	MaxLocalFileBytes  int64
	MaxRemoteCertBytes int64
}

// New builds a Validator with the supplied verbosity, output mode and
// size limits. The HTTP client is configured with the supplied per-fetch
// timeout and a CheckRedirect policy that caps redirects at maxRedirects.
//
// Pass logger=nil to construct a default StderrLogger at the supplied
// level; pass a non-nil logger to override (useful in tests). jsonMode
// suppresses printing from that default logger so stdout carries only the
// JSON document; it is ignored when a logger is supplied, since the
// caller then owns the logger's configuration.
func New(level Verbosity, perFetchTimeout time.Duration, maxRedirects int,
	maxAIA, maxCRL, maxLocal, maxRemote int64, logger Logger, jsonMode bool) *Validator {
	if logger == nil {
		logger = NewStderrLogger(level)
		if sl, ok := logger.(*StderrLogger); ok {
			sl.JSONMode = jsonMode
		}
	}
	client := &http.Client{
		Timeout: perFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}
	return &Validator{
		HTTPClient:         client,
		Logger:             logger,
		PerFetchTimeout:    perFetchTimeout,
		MaxAIABytes:        maxAIA,
		MaxCRLBytes:        maxCRL,
		MaxLocalFileBytes:  maxLocal,
		MaxRemoteCertBytes: maxRemote,
	}
}
