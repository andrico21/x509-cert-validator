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
		"-createCAbundle", "bundle.crt",
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
	if cfg.CreateBundlePath != "bundle.crt" {
		t.Errorf("CreateBundlePath: got %q", cfg.CreateBundlePath)
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
