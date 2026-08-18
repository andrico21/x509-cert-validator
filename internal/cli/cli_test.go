package cli

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// ============================================================================
// bindAliases
// ============================================================================

func TestBindAliasesBindsSameValue(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	canonical := fs.Int("max-foo", 100, "max foo")

	bindAliases(fs, map[string]string{"maxfoo": "max-foo"})

	alias := fs.Lookup("maxfoo")
	if alias == nil {
		t.Fatal("alias -maxfoo not registered")
	}
	if !strings.HasPrefix(alias.Usage, "alias for -") {
		t.Errorf("alias usage should start with 'alias for -', got %q", alias.Usage)
	}

	// Setting via alias must mutate the canonical value (shared Value).
	if err := fs.Parse([]string{"-maxfoo", "999"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *canonical != 999 {
		t.Errorf("alias did not mutate canonical: got %d, want 999", *canonical)
	}
}

func TestBindAliasesSkipsUnknownCanonical(t *testing.T) {
	// Unknown canonicals must be a silent no-op (not panic) so that
	// bindAliases is safe to call before all canonicals are registered.
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	bindAliases(fs, map[string]string{"alias": "nonexistent"})

	if fs.Lookup("alias") != nil {
		t.Error("alias for unknown canonical should NOT be registered")
	}
}

func TestBindAliasesSkipsExistingAlias(t *testing.T) {
	// If the alias name is already registered as a real flag, leave it
	// alone (defensive against accidental shadowing).
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Int("max-foo", 100, "max foo")
	fs.Bool("maxfoo", true, "pre-existing real flag")

	bindAliases(fs, map[string]string{"maxfoo": "max-foo"})

	existing := fs.Lookup("maxfoo")
	if existing == nil || existing.Usage != "pre-existing real flag" {
		t.Errorf("existing flag should be untouched, got %+v", existing)
	}
}

// ============================================================================
// printDefaultsExcludingAliases
// ============================================================================

func TestPrintDefaultsExcludingAliases(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Int("max-foo", 100, "max foo")
	fs.String("type", "any", "validation type")
	fs.Bool("crl", false, "enable CRL")
	bindAliases(fs, map[string]string{"maxfoo": "max-foo"})

	var buf strings.Builder
	printDefaultsExcludingAliases(&buf, fs)
	out := buf.String()

	if !strings.Contains(out, "-max-foo") {
		t.Errorf("canonical -max-foo missing, got:\n%s", out)
	}
	if strings.Contains(out, "-maxfoo") {
		t.Errorf("alias -maxfoo should NOT appear in help output, got:\n%s", out)
	}
	// Non-bool defaults are rendered quoted (mirrors current help output
	// shipped in tests.sh; both int and string use %q formatting).
	if !strings.Contains(out, `(default "100")`) {
		t.Errorf("expected quoted int default '(default \"100\")', got:\n%s", out)
	}
	// string default rendered quoted
	if !strings.Contains(out, `(default "any")`) {
		t.Errorf("expected quoted string default '(default \"any\")', got:\n%s", out)
	}
	// bool false (zero value) default omitted entirely
	if strings.Contains(out, "(default false)") {
		t.Errorf("zero-value bool default should be omitted, got:\n%s", out)
	}
}

// ============================================================================
// isZeroValueFlag
// ============================================================================

func TestIsZeroValueFlag(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Int("i", 0, "")
	fs.String("s", "", "")
	fs.Bool("b", false, "")

	fi := fs.Lookup("i")
	fsf := fs.Lookup("s")
	fb := fs.Lookup("b")

	cases := []struct {
		name string
		f    *flag.Flag
		v    string
		want bool
	}{
		{"int zero", fi, "0", true},
		{"int non-zero", fi, "5", false},
		{"string empty", fsf, "", true},
		{"string non-empty", fsf, "x", false},
		{"bool false", fb, "false", true},
		{"bool true", fb, "true", false},
	}
	for _, c := range cases {
		if got := isZeroValueFlag(c.f, c.v); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// ============================================================================
// Parse - happy path + alias acceptance + missing-cert error
// ============================================================================

func TestParseHappyPath(t *testing.T) {
	cfg, err := Parse([]string{"-cert", "leaf.pem", "-dns", "example.com", "-crl"}, "test", io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CertPath != "leaf.pem" {
		t.Errorf("CertPath: got %q, want leaf.pem", cfg.CertPath)
	}
	if cfg.DNSName != "example.com" {
		t.Errorf("DNSName: got %q, want example.com", cfg.DNSName)
	}
	if !cfg.EnableCRL {
		t.Error("EnableCRL should be true")
	}
}

func TestParseAcceptsLegacyAliases(t *testing.T) {
	// Every documented alias must still parse successfully so we don't
	// break users who scripted against the old flag names.
	cfg, err := Parse([]string{
		"-cert", "leaf.pem",
		"-includeRoot",
		"-showGraph",
		"-maxaia", "1024",
		"-maxcrl", "2048",
		"-maxlocal", "4096",
		"-maxcert", "8192",
	}, "test", io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.IncludeRoot {
		t.Error("IncludeRoot should be true")
	}
	if !cfg.ShowGraph {
		t.Error("ShowGraph should be true")
	}
	if cfg.MaxAIA != 1024 || cfg.MaxCRL != 2048 || cfg.MaxLocal != 4096 || cfg.MaxRemote != 8192 {
		t.Errorf("size caps not bound via aliases: AIA=%d CRL=%d Local=%d Remote=%d",
			cfg.MaxAIA, cfg.MaxCRL, cfg.MaxLocal, cfg.MaxRemote)
	}
}

func TestParseRejectsUnknownType(t *testing.T) {
	_, err := Parse([]string{"-cert", "leaf.pem", "-type", "bogus"}, "test", io.Discard)
	if err == nil {
		t.Fatal("expected error for unknown -type value")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if pe.ExitCode != 1 {
		t.Errorf("ExitCode: got %d, want 1", pe.ExitCode)
	}
	if !strings.Contains(pe.Message, "unknown type") {
		t.Errorf("Message: got %q, want substring 'unknown type'", pe.Message)
	}
}

func TestParseRejectsZeroSizeCap(t *testing.T) {
	_, err := Parse([]string{"-cert", "leaf.pem", "-max-aia", "0"}, "test", io.Discard)
	if err == nil {
		t.Fatal("expected error for zero -max-aia")
	}
	if _, ok := err.(*ParseError); !ok {
		t.Errorf("expected *ParseError, got %T: %v", err, err)
	}
}

func TestParseRejectsBadAtTime(t *testing.T) {
	_, err := Parse([]string{"-cert", "leaf.pem", "-at", "not-rfc3339"}, "test", io.Discard)
	if err == nil {
		t.Fatal("expected error for malformed -at")
	}
	if _, ok := err.(*ParseError); !ok {
		t.Errorf("expected *ParseError, got %T: %v", err, err)
	}
}

// ============================================================================
// Parse - help / unknown flag exit codes (Fixes 7+8)
// ============================================================================

func TestParseHelpExitsZero(t *testing.T) {
	var buf strings.Builder
	_, err := Parse([]string{"-h"}, "test", &buf)
	if err == nil {
		t.Fatal("expected *ParseError signal for -h")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if pe.ExitCode != 0 {
		t.Errorf("-h ExitCode: want 0 (stdlib ErrHelp convention), got %d", pe.ExitCode)
	}
	if pe.Message != "" {
		t.Errorf("-h Message: want empty (no 'flag: help requested' noise), got %q", pe.Message)
	}
	if !strings.Contains(buf.String(), "Usage of") {
		t.Errorf("usage text not rendered to writer, got:\n%s", buf.String())
	}
}

func TestParseUnknownFlagExitsTwo(t *testing.T) {
	var buf strings.Builder
	_, err := Parse([]string{"-bogus"}, "test", &buf)
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if pe.ExitCode != 2 {
		t.Errorf("unknown flag ExitCode: want 2, got %d", pe.ExitCode)
	}
	if !strings.Contains(pe.Message, "bogus") {
		t.Errorf("Message should mention the offending flag, got %q", pe.Message)
	}
	if !strings.Contains(buf.String(), "Usage of") {
		t.Errorf("usage text not rendered to writer on unknown flag, got:\n%s", buf.String())
	}
}

// ============================================================================
// normalizeSNI (IPv6 handling)
// ============================================================================

func TestNormalizeSNI(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"example.com", "example.com"},
		{"example.com:443", "example.com"},
		{"  host:8443  ", "host"},
		{"[::1]:443", "::1"},                 // bracketed IPv6 with port: host extracted
		{"::1", "::1"},                       // bare IPv6: previously mangled to ":"
		{"host:notaport", "host"},            // SplitHostPort does not validate port digits
		{"host:443:extra", "host:443:extra"}, // unparseable: left untouched
	}
	for _, c := range cases {
		if got := normalizeSNI(c.in); got != c.want {
			t.Errorf("normalizeSNI(%q): want %q, got %q", c.in, c.want, got)
		}
	}
}

// ============================================================================
// Parse - inspect/split/json/expiry flags (certinspect feature port)
// ============================================================================

func TestParseModeDefaultsToValidate(t *testing.T) {
	cfg, err := Parse([]string{"-cert", "leaf.pem"}, "test", io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != ModeValidate {
		t.Errorf("Mode: got %d, want ModeValidate", cfg.Mode)
	}
	if cfg.Days != 30 {
		t.Errorf("Days default: got %d, want 30", cfg.Days)
	}
	if cfg.Export != "" {
		t.Errorf("Export default: got %q, want empty", cfg.Export)
	}
	if cfg.ExportFormat != "bundle" {
		t.Errorf("ExportFormat default: got %q, want bundle", cfg.ExportFormat)
	}
	if cfg.ExportScope != "ca" {
		t.Errorf("ExportScope default: got %q, want ca", cfg.ExportScope)
	}
	if cfg.ExportName != "index" {
		t.Errorf("ExportName default: got %q, want index", cfg.ExportName)
	}
}

func TestParseInspectMode(t *testing.T) {
	cfg, err := Parse([]string{"-inspect", "-cert", "bundle.pem", "-json", "-days", "10", "-fail-expired", "-full"}, "test", io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Mode != ModeInspect {
		t.Errorf("Mode: got %d, want ModeInspect", cfg.Mode)
	}
	if !cfg.JSON || !cfg.FailExpired || !cfg.Full {
		t.Errorf("expected JSON/FailExpired/Full all true, got %+v", cfg)
	}
	if cfg.Days != 10 {
		t.Errorf("Days: got %d, want 10", cfg.Days)
	}
}

func TestParseExport(t *testing.T) {
	cfg, err := Parse([]string{"-inspect", "-cert", "bundle.pem", "-export", "out", "-export-format", "split", "-export-scope", "all", "-export-name", "subject"}, "test", io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Export != "out" {
		t.Errorf("Export: got %q, want out", cfg.Export)
	}
	if cfg.ExportFormat != "split" || cfg.ExportScope != "all" || cfg.ExportName != "subject" {
		t.Errorf("export options: Format=%q Scope=%q Name=%q", cfg.ExportFormat, cfg.ExportScope, cfg.ExportName)
	}
}

func TestParseFailExpiring(t *testing.T) {
	// -fail-expiring parses independently and coexists with -fail-expired.
	cfg, err := Parse([]string{"-inspect", "-cert", "b.pem", "-days", "30", "-fail-expiring"}, "test", io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.FailExpiring {
		t.Error("FailExpiring: want true")
	}
	if cfg.FailExpired {
		t.Error("FailExpired: want false when only -fail-expiring given")
	}

	// Both gates together is allowed (no mutual exclusion).
	both, err := Parse([]string{"-inspect", "-cert", "b.pem", "-fail-expired", "-fail-expiring"}, "test", io.Discard)
	if err != nil {
		t.Fatalf("both gates: unexpected error: %v", err)
	}
	if !both.FailExpired || !both.FailExpiring {
		t.Errorf("both gates: want FailExpired && FailExpiring, got %+v", both)
	}

	// Default is off.
	def, err := Parse([]string{"-cert", "b.pem"}, "test", io.Discard)
	if err != nil {
		t.Fatalf("default: unexpected error: %v", err)
	}
	if def.FailExpiring {
		t.Error("FailExpiring default: want false")
	}
}

func TestParseRejectsMultipleOutputFormats(t *testing.T) {
	for _, args := range [][]string{
		{"-cert", "x.pem", "-json", "-silent"},
		{"-cert", "x.pem", "-json", "-ultra-silent"},
		{"-cert", "x.pem", "-silent", "-ultra-silent"},
	} {
		_, err := Parse(args, "test", io.Discard)
		pe, ok := err.(*ParseError)
		if !ok {
			t.Fatalf("args %v: expected *ParseError, got %T: %v", args, err, err)
		}
		if pe.ExitCode != 1 || !strings.Contains(pe.Message, "one output format") {
			t.Errorf("args %v: want exit 1 + 'one output format', got code=%d msg=%q", args, pe.ExitCode, pe.Message)
		}
	}
}

func TestParseRejectsBadExportEnums(t *testing.T) {
	cases := []struct {
		args   []string
		substr string
	}{
		{[]string{"-cert", "x.pem", "-export-format", "bogus"}, "export-format"},
		{[]string{"-cert", "x.pem", "-export-scope", "bogus"}, "export-scope"},
		{[]string{"-cert", "x.pem", "-export-name", "bogus"}, "export-name"},
	}
	for _, c := range cases {
		_, err := Parse(c.args, "test", io.Discard)
		pe, ok := err.(*ParseError)
		if !ok {
			t.Fatalf("args %v: expected *ParseError, got %T: %v", c.args, err, err)
		}
		if pe.ExitCode != 1 || !strings.Contains(pe.Message, c.substr) {
			t.Errorf("args %v: want exit 1 + %q, got code=%d msg=%q", c.args, c.substr, pe.ExitCode, pe.Message)
		}
	}
}

func TestParseRejectsNegativeDays(t *testing.T) {
	_, err := Parse([]string{"-cert", "x.pem", "-days", "-1"}, "test", io.Discard)
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("expected *ParseError, got %T: %v", err, err)
	}
	if pe.ExitCode != 1 || !strings.Contains(pe.Message, "days") {
		t.Errorf("want exit 1 + 'days', got code=%d msg=%q", pe.ExitCode, pe.Message)
	}
}
