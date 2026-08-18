// Package cli encapsulates command-line argument parsing for the
// x509-cert-validator binary. It owns the canonical flag definitions,
// the backward-compatibility alias mappings, the custom -h output, and
// post-parse validation of size limits and -type values.
//
// Parse is pure: it constructs its own *flag.FlagSet (never touches
// flag.CommandLine), never calls os.Exit, and returns either a fully
// populated Config or a typed error describing what went wrong. The
// caller decides how to react (print + exit vs propagate). This keeps
// the package trivially testable from helpers_test.go without leaking
// process state across cases.
//
// The set of canonical flag names and their alias map is the single
// source of truth for the user-facing CLI surface. tests.sh exercises
// both canonical and legacy alias spellings; do not rename or drop
// either side without updating tests in the same change.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Default size limits (mirrored from the main package's constants of
// the same name; kept here so cli.Parse is a self-contained unit and
// so tests can reference defaults without importing main).
const (
	DefaultMaxAIADownloadBytes   int64 = 512 * 1024
	DefaultMaxCRLDownloadBytes   int64 = 20 * 1024 * 1024
	DefaultMaxLocalFileBytes     int64 = 1024 * 1024
	DefaultMaxRemoteCertFileSize int64 = 512 * 1024
)

// Verbosity levels. Mirrors the main package's LevelNormal/Silent/UltraSilent.
type Verbosity int

const (
	VerbosityNormal      Verbosity = 0
	VerbositySilent      Verbosity = 1
	VerbosityUltraSilent Verbosity = 2
)

// Mode is the operation the tool performs. ModeValidate (default) runs
// full chain validation exactly as the legacy tool did; ModeInspect
// describes certificate(s) without building or validating a chain;
// ModeSplit writes each input certificate to its own file. Inspect and
// Split are mutually exclusive with each other.
type Mode int

const (
	ModeValidate Mode = iota
	ModeInspect
	ModeSplit
)

// Config holds every value derivable from the command line after
// Parse succeeds. Fields are organized in the same order as the
// original main()'s flag.* declarations to make code review against
// the legacy implementation straightforward.
type Config struct {
	// Inputs
	CertPath string
	RootPath string
	DNSName  string
	SNI      string // already trimmed; host extracted if host:port supplied
	AtTime   time.Time

	// Switches
	EnableCRL        bool
	EnableAIA        bool
	CreateBundlePath string
	IncludeRoot      bool
	Usage            string // "server" | "client" | "any"
	ShowGraph        bool
	ShowVersion      bool
	FPShowAll        bool

	// Verbosity (computed from -silent / -ultra-silent)
	Verbosity Verbosity

	// Size limits
	MaxAIA    int64
	MaxCRL    int64
	MaxLocal  int64
	MaxRemote int64

	// Operation mode + inspect/split/output options (certinspect feature
	// port). Default Mode is ModeValidate; every field below is additive
	// and leaves the legacy validate path unchanged when unset.
	Mode        Mode
	JSON        bool   // -json: machine-readable output
	NoColor     bool   // -no-color: disable ANSI color in inspect table
	Full        bool   // -full: inspect full per-certificate detail
	Days        int    // -days: expiry warning threshold (days)
	FailExpired bool   // -fail-expired: exit 2 if any evaluated cert expired
	OutDir      string // -outdir: output directory for -split
	SplitName   string // -split-name: "index" | "subject"

	// Positional intermediates (CLI args after flags)
	IntermediateArgs []string
}

// ParseError is returned by Parse for any user-facing failure
// (unknown flag, bad -at value, non-positive size limit, unknown -type,
// etc.) and for -h/--help. The Message field is operator-facing and may
// be empty (help requested: usage was already rendered, nothing to add);
// ExitCode mirrors conventional CLI behavior: 0 for -h (stdlib
// flag.ErrHelp convention), 1 for value-validation errors, 2 for
// flag-parse errors.
type ParseError struct {
	Message  string
	ExitCode int
}

func (e *ParseError) Error() string { return e.Message }

// Parse parses the supplied argument slice (typically os.Args[1:]) and
// returns either a populated *Config or a *ParseError. It writes
// nothing to stderr/stdout itself; callers route Usage output through
// the supplied writer when ParseError.PrintUsage is true.
//
// progName is used in usage output (typically os.Args[0]).
func Parse(args []string, progName string, usageOut io.Writer) (*Config, error) {
	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	// Suppress fs.Parse's own "flag provided but not defined" stderr
	// line; we'll surface a uniform error via ParseError instead.
	fs.SetOutput(io.Discard)

	// Custom usage closure - writes to caller-supplied sink so tests
	// can capture it.
	fs.Usage = func() { writeUsage(usageOut, progName, fs) }

	certPath := fs.String("cert", "", "Path to Certificate PEM/DER, HTTP URL (download), or HTTPS URL (live probe). Note: file:// is NOT supported.")
	rootPath := fs.String("root", "", "Path/URL to Root CA PEM/DER (optional; uses System Roots if empty). Supports local path, http(s) download, or https live-probe (same as -cert).")
	dnsName := fs.String("dns", "", "Optional: Verify specific DNS name")
	sni := fs.String("sni", "", "Optional: Override TLS SNI for live HTTPS probes (https://...)")
	atTime := fs.String("at", "", "Optional: Validate at RFC3339 time")
	enableCRL := fs.Bool("crl", false, "Enable certificate revocation checking (CRL)")
	enableAIA := fs.Bool("aia", false, "Enable automatic AIA fetching")
	createBundlePath := fs.String("create-ca-bundle", "", "Optional: Path to create/export CA bundle. On success, exports from verified chain(s).")
	includeRoot := fs.Bool("include-root", false, "Include Root/Trust-Anchor certificate(s) in the generated bundle")
	usage := fs.String("type", "any", "Validation type: server, client, or any")
	showGraph := fs.Bool("show-graph", false, "Display ASCII graph of the verified chain")
	silent := fs.Bool("silent", false, "Output only pass/fail status and cert ID")
	ultraSilent := fs.Bool("ultra-silent", false, "No output, exit code only (0=Pass, 1=Fail)")
	showVersion := fs.Bool("version", false, "Print version and exit")
	fpShowAll := fs.Bool("fp-show-all", false, "Show alternative fingerprint algo values (+MD5, SHA-384, SHA-512)")

	maxAIA := fs.Int64("max-aia", DefaultMaxAIADownloadBytes, "Max bytes to download per AIA issuer fetch")
	maxCRL := fs.Int64("max-crl", DefaultMaxCRLDownloadBytes, "Max bytes to download per CRL URL")
	maxLocal := fs.Int64("max-local", DefaultMaxLocalFileBytes, "Max bytes to read from local cert file")
	maxRemote := fs.Int64("max-cert", DefaultMaxRemoteCertFileSize, "Max bytes to download for remote cert file (http/https)")

	// Operation modes (default = validate). Inspect/Split are mutually exclusive.
	inspectMode := fs.Bool("inspect", false, "Inspect mode: describe certificate(s) without validating a chain (accepts file, directory, bundle, - for stdin, or URL)")
	splitMode := fs.Bool("split", false, "Split mode: write each input certificate to its own file (see -outdir, -split-name)")

	// Output format + expiry (apply across modes).
	jsonOut := fs.Bool("json", false, "Machine-readable JSON output (mutually exclusive with -silent/-ultra-silent)")
	noColor := fs.Bool("no-color", false, "Disable ANSI color in -inspect table output")
	full := fs.Bool("full", false, "Inspect: show full per-certificate detail (implied by -json)")
	days := fs.Int("days", 30, "Expiry warning threshold in days")
	failExpired := fs.Bool("fail-expired", false, "Exit code 2 if any evaluated certificate is expired")
	outDir := fs.String("outdir", "certs", "Output directory for -split")
	splitName := fs.String("split-name", "index", "Split file naming mode: index or subject")

	// Backward-compat aliases bound to the SAME flag.Value as the
	// canonical name so both spellings update the same memory.
	bindAliases(fs, map[string]string{
		"createCAbundle": "create-ca-bundle",
		"includeRoot":    "include-root",
		"showGraph":      "show-graph",
		"ultrasilent":    "ultra-silent",
		"maxaia":         "max-aia",
		"maxcrl":         "max-crl",
		"maxlocal":       "max-local",
		"maxcert":        "max-cert",
	})

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// -h/--help: the fs.Usage closure already rendered the full
			// usage text to usageOut. Exit 0 per stdlib convention, with
			// no extra noise ("flag: help requested") on stderr.
			return nil, &ParseError{Message: "", ExitCode: 0}
		}
		// Unknown flag / bad value: flag pkg already invoked fs.Usage too;
		// surface the error message with the conventional exit code 2.
		return nil, &ParseError{
			Message:  err.Error(),
			ExitCode: 2,
		}
	}

	cfg := &Config{
		CertPath:         *certPath,
		RootPath:         *rootPath,
		DNSName:          *dnsName,
		SNI:              normalizeSNI(*sni),
		EnableCRL:        *enableCRL,
		EnableAIA:        *enableAIA,
		CreateBundlePath: *createBundlePath,
		IncludeRoot:      *includeRoot,
		Usage:            *usage,
		ShowGraph:        *showGraph,
		ShowVersion:      *showVersion,
		FPShowAll:        *fpShowAll,
		MaxAIA:           *maxAIA,
		MaxCRL:           *maxCRL,
		MaxLocal:         *maxLocal,
		MaxRemote:        *maxRemote,
		JSON:             *jsonOut,
		NoColor:          *noColor,
		Full:             *full,
		Days:             *days,
		FailExpired:      *failExpired,
		OutDir:           *outDir,
		SplitName:        *splitName,
		IntermediateArgs: fs.Args(),
	}

	switch {
	case *ultraSilent:
		cfg.Verbosity = VerbosityUltraSilent
	case *silent:
		cfg.Verbosity = VerbositySilent
	default:
		cfg.Verbosity = VerbosityNormal
	}

	// -version short-circuits all further validation; the caller
	// handles it before any other work.
	if cfg.ShowVersion {
		return cfg, nil
	}

	if cfg.MaxAIA <= 0 || cfg.MaxCRL <= 0 || cfg.MaxLocal <= 0 || cfg.MaxRemote <= 0 {
		return nil, &ParseError{
			Message:  fmt.Sprintf("size limits must be > 0 (got max-aia=%d max-crl=%d max-local=%d max-cert=%d)", cfg.MaxAIA, cfg.MaxCRL, cfg.MaxLocal, cfg.MaxRemote),
			ExitCode: 1,
		}
	}

	switch cfg.Usage {
	case "server", "client", "any":
		// ok
	default:
		return nil, &ParseError{
			Message:  fmt.Sprintf("unknown type: %s", cfg.Usage),
			ExitCode: 1,
		}
	}

	if *atTime != "" {
		t, err := time.Parse(time.RFC3339, *atTime)
		if err != nil {
			return nil, &ParseError{
				Message:  fmt.Sprintf("invalid -at time: %v", err),
				ExitCode: 1,
			}
		}
		cfg.AtTime = t
	}

	// --- Operation mode: -inspect and -split are mutually exclusive. ---
	switch {
	case *inspectMode && *splitMode:
		return nil, &ParseError{
			Message:  "choose only one operation: -inspect or -split (not both)",
			ExitCode: 1,
		}
	case *inspectMode:
		cfg.Mode = ModeInspect
	case *splitMode:
		cfg.Mode = ModeSplit
	default:
		cfg.Mode = ModeValidate
	}

	// --- Output format: at most one of -json / -silent / -ultra-silent. ---
	formats := 0
	for _, on := range []bool{*jsonOut, *silent, *ultraSilent} {
		if on {
			formats++
		}
	}
	if formats > 1 {
		return nil, &ParseError{
			Message:  "choose only one output format: -json, -silent, or -ultra-silent",
			ExitCode: 1,
		}
	}

	// --- -days must be non-negative. ---
	if cfg.Days < 0 {
		return nil, &ParseError{
			Message:  fmt.Sprintf("-days must be >= 0 (got %d)", cfg.Days),
			ExitCode: 1,
		}
	}

	// --- -split-name is a small enum. ---
	switch cfg.SplitName {
	case "index", "subject":
		// ok
	default:
		return nil, &ParseError{
			Message:  fmt.Sprintf("unknown -split-name: %s (want index or subject)", cfg.SplitName),
			ExitCode: 1,
		}
	}

	return cfg, nil
}

// normalizeSNI trims surrounding whitespace and drops any :port suffix so
// callers can pass the result directly as the TLS ServerName. Uses
// net.SplitHostPort so IPv6 forms work: "[::1]:443" yields "::1" and a
// bare IPv6 literal such as "::1" is returned unchanged (the previous
// manual last-colon split mangled it into ":"). Anything SplitHostPort
// cannot parse is returned as-is. Note crypto/tls omits SNI entirely for
// IP-literal ServerNames per RFC 6066, so IP inputs are diagnostic-only.
func normalizeSNI(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || !strings.Contains(s, ":") {
		return s
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return s
}

// bindAliases attaches each alias name to the flag.Value of its
// canonical counterpart in fs. Aliases are flagged as deprecated in
// usage but still update the same underlying memory.
func bindAliases(fs *flag.FlagSet, aliases map[string]string) {
	for alias, canonical := range aliases {
		canonFlag := fs.Lookup(canonical)
		if canonFlag == nil {
			continue
		}
		if existing := fs.Lookup(alias); existing != nil {
			continue
		}
		fs.Var(canonFlag.Value, alias, fmt.Sprintf("alias for -%s (deprecated; kept for backward compatibility)", canonical))
	}
}

// writeUsage renders the canonical -h output to w. It mirrors the
// legacy flag.Usage closure verbatim including the "EXAMPLES:" block
// and the trailing aliases note so tests.sh -h diffs remain stable.
func writeUsage(w io.Writer, progName string, fs *flag.FlagSet) {
	fmt.Fprintf(w, "Usage of %s:\n", progName)
	printDefaultsExcludingAliases(w, fs)
	fmt.Fprintln(w, "\nEXAMPLES:")
	fmt.Fprintln(w, "  1. Live HTTPS Probe (Check server's current chain):")
	fmt.Fprintln(w, "     x509-cert-validator -cert https://github.com")

	fmt.Fprintln(w, "\n  2. Validate a Remote Certificate File (e.g., from an AIA URL):")
	fmt.Fprintln(w, "     x509-cert-validator -cert http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt")

	fmt.Fprintln(w, "\n  3. Validation with Specific Constraints (-dns, -at, -type, -crl):")
	fmt.Fprintln(w, "     x509-cert-validator -cert leaf.pem -dns example.com -at \"2025-12-25T12:00:00Z\"")
	fmt.Fprintln(w, "     x509-cert-validator -cert client-cert.pem -type client")
	fmt.Fprintln(w, "     x509-cert-validator -cert leaf.pem -crl")

	fmt.Fprintln(w, "\n  4. Fix Local Chain & Export Bundle:")
	fmt.Fprintln(w, "     x509-cert-validator -cert leaf.pem -aia -create-ca-bundle full-chain.crt")
	fmt.Fprintln(w, "     Exporting Root CA (-include-root) requires explicit specification of root CA's certificate file (-root <filename>).")
	fmt.Fprintln(w, "     x509-cert-validator -cert leaf.pem -aia -create-ca-bundle bundle.crt -include-root -root custom-root-ca.crt")
	fmt.Fprintln(w, "     (⚠️  SECURITY WARNING: This also exports the Root CA certificate.)")
	fmt.Fprintln(w, "     (    Never install an unknown Root CA unless you know what you are doing)")
	fmt.Fprintln(w, "     (    and have verified its fingerprint manually.)")
	fmt.Fprintln(w, "     (    Trusting a malicious Root might lead to interception of your private data.)")

	fmt.Fprintln(w, "\n  5. Visualization:")
	fmt.Fprintln(w, "     x509-cert-validator -cert leaf.pem -show-graph")

	fmt.Fprintln(w, "\n  6. Silent Mode (Short status line only):")
	fmt.Fprintln(w, "     x509-cert-validator -cert leaf.pem -silent")
	fmt.Fprintln(w, "     > PASS [github.com] Serial:12345...")

	fmt.Fprintln(w, "\n  7. Ultra Silent (Exit code only):")
	fmt.Fprintln(w, "     x509-cert-validator -cert leaf.pem -ultra-silent")
	fmt.Fprintln(w, "     (echo $?)")

	fmt.Fprintln(w, "\n  8. Structured JSON output (validate/inspect/split):")
	fmt.Fprintln(w, "     x509-cert-validator -cert https://github.com -json")

	fmt.Fprintln(w, "\n  9. Inspect certificate(s) without validating (file, directory, bundle, or - for stdin):")
	fmt.Fprintln(w, "     x509-cert-validator -inspect -cert bundle.pem")
	fmt.Fprintln(w, "     x509-cert-validator -inspect -cert ./certs-dir --full")
	fmt.Fprintln(w, "     cat chain.pem | x509-cert-validator -inspect -cert -")

	fmt.Fprintln(w, "\n  10. Expiry gate for cron/CI (exit 2 if expired; pairs with silent modes):")
	fmt.Fprintln(w, "     x509-cert-validator -inspect -cert leaf.pem -days 30 -fail-expired -ultra-silent")

	fmt.Fprintln(w, "\n  11. Split a multi-cert bundle into individual files:")
	fmt.Fprintln(w, "     x509-cert-validator -split -cert bundle.pem -outdir out -split-name subject")

	fmt.Fprintln(w, "\nNote: legacy flag names (e.g. -createCAbundle, -includeRoot, -showGraph,")
	fmt.Fprintln(w, "      -ultrasilent, -maxaia, -maxcrl, -maxlocal, -maxcert) remain accepted")
	fmt.Fprintln(w, "      as hidden aliases for backward compatibility.")
}

// printDefaultsExcludingAliases mirrors flag.PrintDefaults but skips
// any flag whose usage starts with "alias for -" so legacy spellings
// stay hidden from -h output. Format mirrors stdlib output exactly.
func printDefaultsExcludingAliases(w io.Writer, fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		if strings.HasPrefix(f.Usage, "alias for -") {
			return
		}
		var b strings.Builder
		fmt.Fprintf(&b, "  -%s", f.Name)
		name, usageStr := flag.UnquoteUsage(f)
		if len(name) > 0 {
			b.WriteString(" ")
			b.WriteString(name)
		}
		// Mirror stdlib: 4-space indent for the usage line if name is
		// long, otherwise tab.
		if b.Len() <= 4 {
			b.WriteString("\t")
		} else {
			b.WriteString("\n    \t")
		}
		b.WriteString(strings.ReplaceAll(usageStr, "\n", "\n    \t"))
		if !isZeroValueFlag(f, f.DefValue) {
			if _, ok := f.Value.(interface{ IsBoolFlag() bool }); ok {
				fmt.Fprintf(&b, " (default %s)", f.DefValue)
			} else {
				fmt.Fprintf(&b, " (default %q)", f.DefValue)
			}
		}
		fmt.Fprintln(w, b.String())
	})
}

// isZeroValueFlag reports whether the supplied string equals the
// zero value for the flag's underlying type. Mirrors stdlib
// flag.isZeroValue (unexported) closely enough for our flag types.
func isZeroValueFlag(_ *flag.Flag, value string) bool {
	switch value {
	case "", "0", "false":
		return true
	}
	return false
}
