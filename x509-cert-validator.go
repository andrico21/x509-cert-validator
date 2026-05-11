package main

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- MD5 fingerprints are intentionally exposed (-fp-show-all) as a diagnostic identifier, not for cryptographic security.
	"crypto/sha1" // #nosec G505 -- SHA-1 fingerprints are a standard, intentional diagnostic identifier (parity with openssl x509 -fingerprint -sha1).
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/andrico21/x509-cert-validator/internal/x509util"
)

// Verbosity Levels
const (
	LevelNormal      = 0
	LevelSilent      = 1
	LevelUltraSilent = 2
)

// Default size limits (can be overridden by flags)
const (
	DefaultMaxAIADownloadBytes   int64 = 512 * 1024       // 512KB
	DefaultMaxCRLDownloadBytes   int64 = 20 * 1024 * 1024 // 20MB (covers big public-CA CRLs + headroom)
	DefaultMaxLocalFileBytes     int64 = 1 * 1024 * 1024  // 1MB
	DefaultMaxRemoteCertFileSize int64 = 512 * 1024       // 512KB

	DefaultMaxHTTPRedirects = 3

	DefaultHTTPTimeout     = 10 * time.Second
	DefaultTLSProbeTimeout = 5 * time.Second

	// DefaultGlobalTimeout caps the overall wall-clock budget for all network
	// operations performed during a single validation run (AIA chain walk +
	// per-level CRL fetches + remote cert load). Per-fetch caps still apply
	// via DefaultHTTPTimeout / DefaultTLSProbeTimeout; this is the umbrella.
	DefaultGlobalTimeout = 60 * time.Second
)

// version is set at build time via -ldflags "-X main.version=1.0"
var version = "dev"

var (
	verbosity          int
	targetLeaf         *x509.Certificate // Global reference for error reporting
	rootSourceLabel    string            // Tracks where the Root Trust came from (System vs File)
	hasUnsupportedAlgo bool              // Flag to track if we found GOST/unknown algos or unsupported curves
	hasInsecureAlgo    bool              // Flag to track if Go rejected verification due to insecure algorithm policy (e.g., SHA1)
	sniOverride        string            // Optional SNI override for live HTTPS probes

	// Effective limits (set from flags)
	maxAIADownloadBytes   int64 = DefaultMaxAIADownloadBytes
	maxCRLDownloadBytes   int64 = DefaultMaxCRLDownloadBytes
	maxLocalFileBytes     int64 = DefaultMaxLocalFileBytes
	maxRemoteCertFileSize int64 = DefaultMaxRemoteCertFileSize
	showAllFP             bool

	// hiddenAliasFlags lists flag names that are accepted on the CLI for backward
	// compatibility with older script callers (incl. tests.sh) but should NOT
	// appear in -h help output. Populated by aliasFlags() during flag setup.
	hiddenAliasFlags = map[string]struct{}{}
)

// aliasFlags registers each (alias -> canonical) pair as an additional CLI flag
// that writes through to the SAME underlying value as its canonical flag. The
// alias is recorded in hiddenAliasFlags so printDefaultsExcludingAliases() can
// suppress it from -h output.
//
// Behavior is type-preserving: bool/string/int64 aliases delegate through to the
// canonical flag's flag.Value, which routes parsed input to the original
// pointer (e.g. flag.Bool returns *bool, flag.String returns *string).
//
// Panics on misuse (unknown canonical name, alias collision) so configuration
// bugs surface at startup, not at parse time.
func aliasFlags(aliases map[string]string) {
	for alias, canonical := range aliases {
		canonFlag := flag.Lookup(canonical)
		if canonFlag == nil {
			panic(fmt.Sprintf("aliasFlags: unknown canonical flag %q (alias %q)", canonical, alias))
		}
		if existing := flag.Lookup(alias); existing != nil {
			panic(fmt.Sprintf("aliasFlags: alias %q already registered as a flag", alias))
		}
		// Bind alias to the SAME flag.Value -- both names update the same memory.
		// Usage string intentionally points users at the canonical name.
		flag.Var(canonFlag.Value, alias, fmt.Sprintf("alias for -%s (deprecated; kept for backward compatibility)", canonical))
		hiddenAliasFlags[alias] = struct{}{}
	}
}

// printDefaultsExcludingAliases mirrors flag.PrintDefaults but skips entries
// recorded in hiddenAliasFlags so legacy aliases do not clutter -h output.
func printDefaultsExcludingAliases(w io.Writer) {
	flag.VisitAll(func(f *flag.Flag) {
		if _, hidden := hiddenAliasFlags[f.Name]; hidden {
			return
		}
		// Format mirrors stdlib flag.PrintDefaults (single-letter flags get one
		// dash, longer ones get one dash too -- Go's flag package uses single-dash
		// for everything; we keep parity).
		s := fmt.Sprintf("  -%s", f.Name)
		name, usageStr := flag.UnquoteUsage(f)
		if name != "" {
			s += " " + name
		}
		// Two-space indent for the help text on the next line, matching stdlib.
		s += "\n    \t"
		s += strings.ReplaceAll(usageStr, "\n", "\n    \t")
		if !isZeroValueFlag(f, f.DefValue) {
			// Match stdlib formatting: numerics & bools bare, strings quoted.
			// Heuristic: if DefValue parses as int or float, treat as numeric.
			if _, err := strconv.ParseInt(f.DefValue, 10, 64); err == nil {
				s += fmt.Sprintf(" (default %s)", f.DefValue)
			} else if _, err := strconv.ParseFloat(f.DefValue, 64); err == nil {
				s += fmt.Sprintf(" (default %s)", f.DefValue)
			} else if f.DefValue == "true" || f.DefValue == "false" {
				s += fmt.Sprintf(" (default %s)", f.DefValue)
			} else {
				s += fmt.Sprintf(" (default %q)", f.DefValue)
			}
		}
		fmt.Fprintln(w, s)
	})
}

// isZeroValueFlag reports whether the given default string represents the
// zero value for the flag's underlying type. Mirrors stdlib flag.isZeroValue
// well enough for our use (we only call it from help output).
func isZeroValueFlag(f *flag.Flag, value string) bool {
	switch value {
	case "", "false", "0":
		return true
	}
	return false
}

func main() {
	// --- Usage ---
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		printDefaultsExcludingAliases(os.Stderr)
		fmt.Fprintln(os.Stderr, "\nEXAMPLES:")
		fmt.Fprintln(os.Stderr, "  1. Live HTTPS Probe (Check server's current chain):")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert https://github.com")

		fmt.Fprintln(os.Stderr, "\n  2. Validate a Remote Certificate File (e.g., from an AIA URL):")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt")

		fmt.Fprintln(os.Stderr, "\n  3. Validation with Specific Constraints (-dns, -at, -type, -crl):")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -dns example.com -at \"2025-12-25T12:00:00Z\"")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert client-cert.pem -type client")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -crl")

		fmt.Fprintln(os.Stderr, "\n  4. Fix Local Chain & Export Bundle:")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -aia -create-ca-bundle full-chain.crt")
		fmt.Fprintln(os.Stderr, "     Exporting Root CA (-include-root) requires explicit specification of root CA's certificate file (-root <filename>).")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -aia -create-ca-bundle bundle.crt -include-root -root custom-root-ca.crt")
		fmt.Fprintln(os.Stderr, "     (⚠️  SECURITY WARNING: This also exports the Root CA certificate.)")
		fmt.Fprintln(os.Stderr, "     (    Never install an unknown Root CA unless you know what you are doing)")
		fmt.Fprintln(os.Stderr, "     (    and have verified its fingerprint manually.)")
		fmt.Fprintln(os.Stderr, "     (    Trusting a malicious Root might lead to interception of your private data.)")

		fmt.Fprintln(os.Stderr, "\n  5. Visualization:")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -show-graph")

		fmt.Fprintln(os.Stderr, "\n  6. Silent Mode (Short status line only):")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -silent")
		fmt.Fprintln(os.Stderr, "     > PASS [github.com] Serial:12345...")

		fmt.Fprintln(os.Stderr, "\n  7. Ultra Silent (Exit code only):")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -ultra-silent")
		fmt.Fprintln(os.Stderr, "     (echo $?)")
		fmt.Fprintln(os.Stderr, "\nNote: legacy flag names (e.g. -createCAbundle, -includeRoot, -showGraph,")
		fmt.Fprintln(os.Stderr, "      -ultrasilent, -maxaia, -maxcrl, -maxlocal, -maxcert) remain accepted")
		fmt.Fprintln(os.Stderr, "      as hidden aliases for backward compatibility.")
	}

	// --- CLI Arguments ---
	//
	// Naming convention: canonical flags use kebab-case (e.g. -create-ca-bundle).
	// Legacy run-together / camelCase names (e.g. -createCAbundle, -includeRoot,
	// -showGraph, -ultrasilent, -maxaia, -maxcrl, -maxlocal, -maxcert) remain
	// accepted as HIDDEN aliases via aliasFlags() below for backward compatibility
	// with existing scripts (incl. tests.sh) and operator muscle memory.
	certPath := flag.String("cert", "", "Path to Certificate PEM/DER, HTTP URL (download), or HTTPS URL (live probe). Note: file:// is NOT supported.")
	rootPath := flag.String("root", "", "Path/URL to Root CA PEM/DER (optional; uses System Roots if empty). Supports local path, http(s) download, or https live-probe (same as -cert).")
	dnsName := flag.String("dns", "", "Optional: Verify specific DNS name")
	sni := flag.String("sni", "", "Optional: Override TLS SNI for live HTTPS probes (https://...)")
	atTime := flag.String("at", "", "Optional: Validate at RFC3339 time")
	enableCRL := flag.Bool("crl", false, "Enable certificate revocation checking (CRL)")
	enableAIA := flag.Bool("aia", false, "Enable automatic AIA fetching")
	createBundlePath := flag.String("create-ca-bundle", "", "Optional: Path to create/export CA bundle. On success, exports from verified chain(s).")
	includeRoot := flag.Bool("include-root", false, "Include Root/Trust-Anchor certificate(s) in the generated bundle")
	usage := flag.String("type", "any", "Validation type: server, client, or any")
	showGraph := flag.Bool("show-graph", false, "Display ASCII graph of the verified chain")
	silent := flag.Bool("silent", false, "Output only pass/fail status and cert ID")
	ultraSilent := flag.Bool("ultra-silent", false, "No output, exit code only (0=Pass, 1=Fail)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	fpShowAll := flag.Bool("fp-show-all", false, "Show alternative fingerprint algo values (+MD5, SHA-384, SHA-512)")

	// --- Size limit flags ---
	maxAIA := flag.Int64("max-aia", DefaultMaxAIADownloadBytes, "Max bytes to download per AIA issuer fetch")
	maxCRL := flag.Int64("max-crl", DefaultMaxCRLDownloadBytes, "Max bytes to download per CRL URL")
	maxLocal := flag.Int64("max-local", DefaultMaxLocalFileBytes, "Max bytes to read from local cert file")
	maxRemote := flag.Int64("max-cert", DefaultMaxRemoteCertFileSize, "Max bytes to download for remote cert file (http/https)")

	// --- Backward-compatibility aliases (hidden from -h output) ---
	// Each alias binds to the SAME underlying variable as its canonical flag, so
	// behavior is identical regardless of which name the caller used.
	aliasFlags(map[string]string{
		"createCAbundle": "create-ca-bundle",
		"includeRoot":    "include-root",
		"showGraph":      "show-graph",
		"ultrasilent":    "ultra-silent",
		"maxaia":         "max-aia",
		"maxcrl":         "max-crl",
		"maxlocal":       "max-local",
		"maxcert":        "max-cert",
	})

	flag.Parse()

	if *showVersion {
		fmt.Printf("x509-cert-validator %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// --- Apply size limits ---
	if *maxAIA <= 0 || *maxCRL <= 0 || *maxLocal <= 0 || *maxRemote <= 0 {
		exitErr(fmt.Errorf("size limits must be > 0 (got max-aia=%d max-crl=%d max-local=%d max-cert=%d)", *maxAIA, *maxCRL, *maxLocal, *maxRemote))
	}
	maxAIADownloadBytes = *maxAIA
	maxCRLDownloadBytes = *maxCRL
	maxLocalFileBytes = *maxLocal
	maxRemoteCertFileSize = *maxRemote
	showAllFP = *fpShowAll

	// --- Verbosity ---
	if *ultraSilent {
		verbosity = LevelUltraSilent
	} else if *silent {
		verbosity = LevelSilent
	} else {
		verbosity = LevelNormal
	}

	if *certPath == "" {
		if verbosity == LevelNormal {
			flag.Usage()
		}
		os.Exit(1)
	}

	// Reject file:// explicitly (requested)
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(*certPath)), "file://") {
		exitErr(fmt.Errorf("unsupported -cert scheme: file:// is not accepted; provide a local path or http(s) URL"))
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(*rootPath)), "file://") {
		exitErr(fmt.Errorf("unsupported -root scheme: file:// is not accepted; provide a local path or http(s) URL"))
	}

	sniOverride = strings.TrimSpace(*sni)
	if sniOverride != "" && strings.Contains(sniOverride, ":") {
		if h, _, err := net.SplitHostPort(sniOverride); err == nil {
			sniOverride = h
		}
	}

	logNormal("Runtime: %s\n", runtime.Version())

	// --- 0. Root context with global wall-clock cap for all network operations.
	// Per-fetch caps (DefaultHTTPTimeout / DefaultTLSProbeTimeout) still apply
	// inside individual helpers; this umbrella prevents pathological worst-case
	// latency from a deep AIA walk + many CRL fetches stacking up.
	ctx, cancelCtx := context.WithTimeout(context.Background(), DefaultGlobalTimeout)
	defer cancelCtx()

	// --- 1. Setup Validation Time ---
	currentTime := time.Now()
	if *atTime != "" {
		t, err := time.Parse(time.RFC3339, *atTime)
		if err != nil {
			exitErr(fmt.Errorf("invalid -at time: %v", err))
		}
		currentTime = t
	}
	logNormal("Validation Time: %s\n", currentTime.Format(time.RFC3339))

	// --- 2. Determine Key Usage ---
	var keyUsages []x509.ExtKeyUsage
	switch *usage {
	case "server":
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "any":
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	default:
		exitErr(fmt.Errorf("unknown type: %s", *usage))
	}

	// --- 3. Load Roots (File/URL or System) ---
	var roots *x509.CertPool
	var rootCerts []*x509.Certificate
	var poolList []*x509.Certificate // For signature-based parent checks + AIA walk

	if *rootPath != "" {
		rootSourceLabel = "Explicit User Root"
		logNormal("--- Loading Roots (File/URL) ---\n")
		roots = x509.NewCertPool()
		for _, cert := range loadAll(ctx, *rootPath) {
			printShortID("Root", cert)
			if !cert.IsCA {
				logNormal("  ⚠️ WARNING: Root input cert is NOT marked as CA\n")
			}
			roots.AddCert(cert)
			rootCerts = append(rootCerts, cert)
			poolList = append(poolList, cert)
		}
	} else {
		rootSourceLabel = "System Trust Store"
		logNormal("--- Loading Roots (System) ---\n")
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			logNormal("⚠️  Failed to load system roots: %v. Using empty pool.\n", err)
			roots = x509.NewCertPool()
			rootSourceLabel = "Empty/Failed Store"
		} else {
			logNormal("ℹ️  Loaded System Root Store.\n")
		}
	}

	// --- 4. Load Intermediates (CLI args after flags) ---
	inters := x509.NewCertPool()
	var discoveredIntermediates []*x509.Certificate // what we actually have locally (server-sent + AIA fetched + CLI inters)

	if len(flag.Args()) > 0 {
		logNormal("\n--- Loading Intermediates (CLI) ---\n")
		for _, path := range flag.Args() {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(path)), "file://") {
				exitErr(fmt.Errorf("unsupported intermediate scheme: file:// is not accepted (%s)", path))
			}
			for _, cert := range loadAll(ctx, path) {
				printShortID("Inter", cert)
				if !cert.IsCA {
					logNormal("  ⚠️ WARNING: Intermediate is NOT marked as CA\n")
				}
				inters.AddCert(cert)
				discoveredIntermediates = append(discoveredIntermediates, cert)
				poolList = append(poolList, cert)
			}
		}
	}

	// --- 5. Load Target Cert (File, HTTP, or HTTPS probe) ---
	// C-1 warning: HTTPS live probe without -dns/-sni skips hostname verification.
	// This tool is diagnostic; we keep the behavior but make the bypass loud.
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(*certPath)), "https://") &&
		strings.TrimSpace(*dnsName) == "" && sniOverride == "" {
		logNormal("\n⚠️  Hostname verification SKIPPED (no -dns/-sni provided for HTTPS probe). Chain validity only.\n")
	}

	targetCerts := loadAll(ctx, *certPath)
	if len(targetCerts) == 0 {
		exitErr(fmt.Errorf("no certificates loaded from -cert"))
	}
	leaf := targetCerts[0]
	targetLeaf = leaf

	// If using HTTPS probe, we might get the full chain from the server.
	if len(targetCerts) > 1 {
		logNormal("\nℹ️  Target URL returned %d certificates. Treating [1..n] as intermediates.\n", len(targetCerts))
		for i := 1; i < len(targetCerts); i++ {
			extra := targetCerts[i]
			printShortID("Server-Sent", extra)
			inters.AddCert(extra)
			discoveredIntermediates = append(discoveredIntermediates, extra)
			poolList = append(poolList, extra)
		}
	}

	printCertDetails("Target Certificate", leaf)
	highlightLeafIssues(leaf)

	// --- 6. AIA Fetching (Auto-Discovery, walk upward even if parent already known locally) ---
	if *enableAIA {
		logNormal("\n=== Automatic AIA Fetching ===\n")
		currentCert := leaf
		chainDepth := 0
		maxDepth := 12

		seen := make(map[string]bool)

		for chainDepth < maxDepth {
			curFP := sha256.Sum256(currentCert.Raw)
			curKey := hex.EncodeToString(curFP[:])
			if seen[curKey] {
				logNormal("⚠️  WARNING: AIA loop detected (already visited %s). Stopping fetch.\n", x509util.CnOrDN(currentCert))
				break
			}
			seen[curKey] = true

			if x509util.IsSelfSigned(currentCert) {
				logNormal("ℹ️  Reached Self-Signed Root (%s). Stopping fetch.\n", x509util.CnOrDN(currentCert))
				break
			}

			// 1) If parent is already in our local pool list, advance to it and keep walking.
			if parent, ok := x509util.FindParentInListCert(currentCert, poolList); ok && parent != nil {
				logNormal("ℹ️  Found parent locally: %s. Continuing walk.\n", x509util.CnOrDN(parent))
				currentCert = parent
				chainDepth++
				continue
			}

			// 2) Otherwise, try to fetch via AIA.
			if len(currentCert.IssuingCertificateURL) == 0 {
				logNormal("ℹ️  No AIA URL found for %s. Cannot fetch parent.\n", x509util.CnOrDN(currentCert))
				break
			}

			parentCert, err := fetchAIA(ctx, currentCert)
			if err != nil {
				logNormal("⚠️  AIA Fetch failed for %s: %v\n", x509util.CnOrDN(currentCert), err)
				break
			}

			parentFP := sha256.Sum256(parentCert.Raw)
			parentKey := hex.EncodeToString(parentFP[:])
			if seen[parentKey] {
				logNormal("⚠️  WARNING: AIA returned a previously seen certificate (%s). Stopping fetch.\n", x509util.CnOrDN(parentCert))
				break
			}

			if x509util.IsSelfSigned(parentCert) {
				logNormal("ℹ️  Fetched cert is Self-Signed Root (%s, Key=%s). Stopping fetch.\n",
					x509util.CnOrDN(parentCert), x509util.CertPublicKeySummary(parentCert))

				// Do NOT automatically trust it for verification. Only keep for optional bundling output.
				rootCerts = append(rootCerts, parentCert)
				// Note: not appending to poolList here; we break out of the AIA walk
				// immediately and poolList is not read again in this branch.

				break
			}

			inters.AddCert(parentCert)
			discoveredIntermediates = append(discoveredIntermediates, parentCert)
			poolList = append(poolList, parentCert)
			logNormal("✅ Added fetched certificate: %s (Key=%s)\n", parentCert.Subject, x509util.CertPublicKeySummary(parentCert))

			currentCert = parentCert
			chainDepth++
		}

		if chainDepth >= maxDepth {
			logNormal("⚠️  WARNING: AIA fetch stopped after max depth (%d).\n", maxDepth)
		}
	}

	// Behavior: if -sni is set and -dns is empty, use SNI as DNS verification target.
	effectiveDNS := strings.TrimSpace(*dnsName)
	if effectiveDNS == "" && sniOverride != "" {
		effectiveDNS = sniOverride
	}

	// --- 7. Verify Chain ---
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		DNSName:       effectiveDNS,
		CurrentTime:   currentTime,
		KeyUsages:     keyUsages,
	}

	logNormal("\n=== Verifying Chain ===\n")
	logNormal("Root Trust: %s\n", rootSourceLabel)
	// M-1: if system roots failed to load earlier, re-warn at verification time
	// so the user understands WHY "unknown authority" is about to happen.
	if rootSourceLabel == "Empty/Failed Store" {
		logNormal("\n⚠️  CRITICAL: Verifying against EMPTY trust pool (system roots failed to load). Verification WILL fail unless -root is provided.\n\n")
	}
	chains, err := leaf.Verify(opts)
	if err != nil {
		handleVerifyError(err, *certPath, *rootPath, *usage)
	}

	logNormal("✅ VALIDATION SUCCEEDED\n")

	// --- 8. Create CA Bundle (FROM VERIFIED CHAIN(S)) ---
	if *createBundlePath != "" {
		logNormal("\n=== Creating CA Bundle at %s ===\n", *createBundlePath)

		if *includeRoot && rootSourceLabel != "Explicit User Root" {
			logNormal("⚠️  WARNING: -includeRoot has no effect: roots come from %s (no explicit root file provided via -root).\n", rootSourceLabel)
			logNormal("   System root certificates cannot be exported into the bundle. Use -root <file> to provide an explicit root.\n")
		}

		toBundle := buildBundleFromVerifiedChains(chains, *includeRoot)

		// If for some reason Go didn't return anything to bundle, fall back to what we discovered locally.
		if len(toBundle) == 0 {
			toBundle = buildBundleFromDiscovered(discoveredIntermediates, rootCerts, *includeRoot)
		}

		if len(toBundle) == 0 {
			logNormal("⚠️  No certificates available to bundle.\n")
		} else {
			written, rootsWritten, err := writeBundlePEM(*createBundlePath, toBundle)
			if err != nil {
				logNormal("❌ Failed to create bundle file: %v\n", err)
			} else {
				if *includeRoot && rootsWritten > 0 {
					logNormal("ℹ️  Included %d Root/Anchor certificate(s) in bundle.\n", rootsWritten)
				}
				logNormal("✅ Successfully bundled %d certificates. (Root Trust: %s)\n", written, rootSourceLabel)
			}
		}
	}

	// --- 9. Print Verified Chain(s) ---
	for i, chain := range chains {
		logNormal("\n--- Verified Chain Path %d ---\n", i+1)
		if *showGraph {
			printChainGraph(chain)
		} else {
			for idx := len(chain) - 1; idx >= 0; idx-- {
				cert := chain[idx]
				displayIdx := len(chain) - 1 - idx
				prefix := strings.Repeat("  ", displayIdx)

				subCN := cert.Subject.CommonName
				if subCN == "" {
					subCN = "No-CN"
				}
				issCN := cert.Issuer.CommonName
				if issCN == "" {
					issCN = "No-CN"
				}

				self := ""
				if x509util.IsSelfSigned(cert) {
					self = " (self-signed)"
				}

				logNormal("%s[%d] Subject: %s%s\n", prefix, displayIdx, subCN, self)
				logNormal("%s    Issuer:  %s\n", prefix, issCN)
				if showAllFP {
					logNormal("%s    FP(md5):    %x\n", prefix, md5.Sum(cert.Raw)) // #nosec G401 -- diagnostic fingerprint, not used for cryptographic verification.
				}
				logNormal("%s    FP(sha1):   %x\n", prefix, sha1.Sum(cert.Raw)) // #nosec G401 -- diagnostic fingerprint (parity with openssl/certutil), not used for cryptographic verification.
				logNormal("%s    FP(sha256): %x\n", prefix, sha256.Sum256(cert.Raw))
				if showAllFP {
					logNormal("%s    FP(sha384): %x\n", prefix, sha512.Sum384(cert.Raw))
					logNormal("%s    FP(sha512): %x\n", prefix, sha512.Sum512(cert.Raw))
				}
				logNormal("%s    Serial: %s\n", prefix, x509util.SerialHex(cert))
				logNormal("%s    PubKey: %s\n", prefix, x509util.CertPublicKeySummary(cert))
				logNormal("%s    SigAlg: %s\n", prefix, cert.SignatureAlgorithm)

				// Name Constraints (requested)
				printNameConstraints(prefix, cert)

				// If issuer is in-chain, show issuer key type/length used to verify this cert's signature.
				if idx+1 < len(chain) {
					issuer := chain[idx+1]
					logNormal("%s    SignedByKey: %s\n", prefix, x509util.CertPublicKeySummary(issuer))
				} else if x509util.IsSelfSigned(cert) {
					logNormal("%s    SignedByKey: %s\n", prefix, x509util.CertPublicKeySummary(cert))
				}
			}
		}
	}

	// --- 10. CRL Check (Strict) ---
	if *enableCRL {
		logNormal("\n=== Checking CRLs ===\n")
		if err := checkCRL(ctx, chains, currentTime); err != nil {
			exitErr(fmt.Errorf("CRL CHECK FAILED: %v", err))
		}
		logNormal("✅ CRL CHECK PASSED\n")
	}

	exitSuccess()
}

// --- Bundle helpers ---

// Build bundle from verified chains: include intermediates always, and include trust anchor only if includeRoot.
// Never includes the leaf.
func buildBundleFromVerifiedChains(chains [][]*x509.Certificate, includeRoot bool) []*x509.Certificate {
	seen := make(map[string]bool)
	var out []*x509.Certificate

	for _, chain := range chains {
		// chain[0] is leaf
		for idx := 1; idx < len(chain); idx++ {
			c := chain[idx]
			// idx==len(chain)-1 is trust anchor (root/anchor)
			if idx == len(chain)-1 && !includeRoot {
				continue
			}
			fp := sha256.Sum256(c.Raw)
			k := hex.EncodeToString(fp[:])
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, c)
		}
	}
	return out
}

// Fallback bundle from what we discovered locally (server-sent + AIA fetched + CLI inters), plus optional roots list.
// Never includes leaf (not provided here).
func buildBundleFromDiscovered(inters []*x509.Certificate, roots []*x509.Certificate, includeRoot bool) []*x509.Certificate {
	seen := make(map[string]bool)
	var out []*x509.Certificate

	add := func(c *x509.Certificate) {
		if c == nil {
			return
		}
		fp := sha256.Sum256(c.Raw)
		k := hex.EncodeToString(fp[:])
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, c)
	}

	for _, c := range inters {
		add(c)
	}
	if includeRoot {
		for _, r := range roots {
			add(r)
		}
	}
	return out
}

func writeBundlePEM(path string, certs []*x509.Certificate) (written int, rootsWritten int, err error) {
	tmpPath := path + ".tmp"
	// M-4: explicit perms (0644) and named-return + deferred cleanup so we never
	// leave a stale .tmp file behind on partial failure.
	// #nosec G302 G304 -- bundle is a public PEM artifact (CA certificates); 0o644 is the intentional, documented file mode for distribution. Path is user-supplied by design (-createCAbundle <path>).
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, 0, err
	}
	committed := false
	defer func() {
		// Close (idempotent: ignore second-close errors via _ )
		_ = f.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	seen := make(map[string]bool)
	for _, c := range certs {
		if c == nil {
			continue
		}
		fp := sha256.Sum256(c.Raw)
		k := hex.EncodeToString(fp[:])
		if seen[k] {
			continue
		}
		seen[k] = true

		if err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return written, rootsWritten, err
		}
		written++
		if x509util.IsSelfSigned(c) {
			rootsWritten++
		}
	}

	if err = f.Close(); err != nil {
		return written, rootsWritten, err
	}

	if err = os.Rename(tmpPath, path); err != nil {
		return written, rootsWritten, err
	}

	committed = true
	return written, rootsWritten, nil
}

// --- Helpers ---

func flagUnsupportedIfNeeded(cert *x509.Certificate) {
	if cert == nil {
		return
	}
	if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm ||
		cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		hasUnsupportedAlgo = true
	}
}

func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int(d.Hours()) / 24
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d.Hours())
	d -= time.Duration(hours) * time.Hour
	minutes := int(d.Minutes())
	d -= time.Duration(minutes) * time.Minute
	seconds := int(d.Seconds())
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func handleVerifyError(err error, certPath, rootPath, usage string) {
	if x509util.LooksLikeUnsupportedAlgoErr(err) {
		hasUnsupportedAlgo = true
	}
	if x509util.LooksLikeInsecureAlgoErr(err) {
		hasInsecureAlgo = true
	}

	if hasUnsupportedAlgo {
		logNormal("\n⚠️  CRITICAL HINT: Go rejected this chain because it contains an unsupported algorithm/curve (e.g., GOST or unsupported EC curve).\n")
		logNormal("   Please try verifying with OpenSSL directly:\n")
		logNormal("   $ openssl x509 -in %s -noout -text\n", certPath)
		if rootPath != "" {
			logNormal("   $ openssl verify -CAfile %s %s\n\n", rootPath, certPath)
		} else {
			logNormal("   $ openssl verify %s\n\n", certPath)
		}
	} else if hasInsecureAlgo {
		logNormal("\n⚠️  CRITICAL HINT: Go refused to verify due to an insecure signature algorithm policy (e.g., SHA1/MD5).\n")
		if targetLeaf != nil {
			logNormal("   Leaf Signature Algorithm: %s\n", targetLeaf.SignatureAlgorithm)
			logNormal("   Leaf Public Key: %s\n", x509util.CertPublicKeySummary(targetLeaf))
		}
		logNormal("   Verify with OpenSSL to confirm the chain, then re-issue with a modern hash (SHA-256+):\n")
		logNormal("   $ openssl x509 -in %s -noout -text\n", certPath)
		if rootPath != "" {
			logNormal("   $ openssl verify -CAfile %s %s\n\n", rootPath, certPath)
		} else {
			logNormal("   $ openssl verify %s\n\n", certPath)
		}
	} else if strings.Contains(err.Error(), "authority") {
		if targetLeaf != nil && x509util.IsSelfSigned(targetLeaf) {
			logNormal("  (Tip: Certificate is self-signed and not in the system trust store. Use -root to trust it explicitly.)\n")
		} else {
			logNormal("  (Tip: Ensure intermediates are provided or use -aia)\n")
		}
	} else if strings.Contains(err.Error(), "KeyUsage") || strings.Contains(err.Error(), "key usage") {
		logNormal("  (Tip: Check if the certificate is valid for the requested type: %s)\n", usage)
	} else if strings.Contains(err.Error(), "x509") && strings.Contains(err.Error(), "valid for") {
		logNormal("  (Tip: Hostname mismatch; use -dns or -sni appropriately)\n")
	}

	exitErr(fmt.Errorf("VALIDATION FAILED: %v", err))
}

func highlightLeafIssues(cert *x509.Certificate) {
	logNormal("\n=== Heuristic Analysis ===\n")

	// Always show key type/size here (requested).
	logNormal("ℹ️  Leaf Public Key: %s\n", x509util.CertPublicKeySummary(cert))
	logNormal("ℹ️  Leaf Signature Algorithm: %s\n", cert.SignatureAlgorithm)

	if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
		hasUnsupportedAlgo = true
		logNormal("⚠️  WARNING: Signature Algorithm is UNKNOWN/UNSUPPORTED (Possible GOST or unknown).\n")
	}
	if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		hasUnsupportedAlgo = true
		logNormal("⚠️  WARNING: Public Key Algorithm is UNKNOWN.\n")
	}

	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		logNormal("⚠️  WARNING: Weak signature algorithm: %v\n", cert.SignatureAlgorithm)
	}

	now := time.Now()
	if now.After(cert.NotAfter) {
		logNormal("⚠️  WARNING: Certificate is EXPIRED (NotAfter: %s, %s ago).\n",
			cert.NotAfter.Format(time.RFC3339),
			humanDuration(now.Sub(cert.NotAfter)))
	} else if now.Before(cert.NotBefore) {
		logNormal("⚠️  WARNING: Certificate is NOT YET VALID (NotBefore: %s, starts in %s).\n",
			cert.NotBefore.Format(time.RFC3339),
			humanDuration(cert.NotBefore.Sub(now)))
	} else {
		remaining := cert.NotAfter.Sub(now)
		totalLifetime := cert.NotAfter.Sub(cert.NotBefore)
		threshold := totalLifetime / 10
		floor := 7 * 24 * time.Hour
		if floor > totalLifetime/2 {
			floor = totalLifetime / 2
		}
		if threshold < floor {
			threshold = floor
		}
		if remaining < threshold {
			logNormal("⚠️  NOTICE: Certificate expires soon (%s remaining, NotAfter: %s).\n",
				humanDuration(remaining), cert.NotAfter.Format(time.RFC3339))
		}
	}

	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		logNormal("⚠️  WARNING: Certificate has no SAN entries.\n")
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		logNormal("⚠️  WARNING: Leaf appears to be a CA certificate (IsCA=true).\n")
	}
}

type crlCacheEntry struct {
	rl *x509.RevocationList
}

// CRL policy:
// - PEM and DER supported.
// - If multiple CDPs exist: at least one must respond with a VALID CRL.
// - Missing ThisUpdate/NextUpdate => warning AND treated as invalid for -crl.
// - If multiple VALID CRLs respond: if ANY indicates revoked => FAIL with clear message.
func checkCRL(ctx context.Context, chains [][]*x509.Certificate, now time.Time) error {
	client := &http.Client{
		Timeout: DefaultHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= DefaultMaxHTTPRedirects {
				return fmt.Errorf("stopped after %d redirects", DefaultMaxHTTPRedirects)
			}
			return nil
		},
	}

	// Cache CRLs by URL (avoids repeated downloads across chains)
	crlCache := make(map[string]crlCacheEntry)

	// Dedupe per unique (child cert, parent cert) pair across all chain paths
	checkedPair := make(map[string]bool)

	for _, chain := range chains {
		for i := 0; i < len(chain)-1; i++ {
			child := chain[i]
			parent := chain[i+1]

			// Ensure Parent can Sign CRLs
			if (parent.KeyUsage & x509.KeyUsageCRLSign) == 0 {
				logNormal("⚠️  WARNING: Issuer '%s' does not have CRLSign usage. Skipping CRL check for this level.\n", x509util.CnOrDN(parent))
				continue
			}

			if len(child.CRLDistributionPoints) == 0 {
				logNormal("ℹ️  Skipping %s (No CDP defined)\n", x509util.CnOrDN(child))
				continue
			}

			// Pair dedupe (prevents duplicate checks across multiple verified chain paths)
			// Use full SHA-256 to avoid collision risk on truncated keys.
			childFP := sha256.Sum256(child.Raw)
			parentFP := sha256.Sum256(parent.Raw)
			pairKey := hex.EncodeToString(childFP[:]) + ":" + hex.EncodeToString(parentFP[:])

			if checkedPair[pairKey] {
				logNormal("ℹ️  Skipping CRL re-check (already checked) for '%s' issued by '%s'\n", x509util.CnOrDN(child), x509util.CnOrDN(parent))
				continue
			}
			checkedPair[pairKey] = true

			validCRLFound := false
			var errMsgs []string

			for idx, cdpURL := range child.CRLDistributionPoints {
				if !strings.HasPrefix(cdpURL, "http://") && !strings.HasPrefix(cdpURL, "https://") {
					// M-2: surface skipped non-http(s) CRL URLs.
					logNormal("⚠️  Skipping CRL URL with unsupported scheme [%d/%d] for '%s': %s\n", idx+1, len(child.CRLDistributionPoints), x509util.CnOrDN(child), cdpURL)
					continue
				}

				var crl *x509.RevocationList
				if cached, ok := crlCache[cdpURL]; ok && cached.rl != nil {
					crl = cached.rl
					logNormal("ℹ️  Using cached CRL for '%s' [%d/%d]: %s\n", x509util.CnOrDN(child), idx+1, len(child.CRLDistributionPoints), cdpURL)
				} else {
					logNormal("⬇️  Fetching CRL for '%s' [%d/%d]: %s\n", x509util.CnOrDN(child), idx+1, len(child.CRLDistributionPoints), cdpURL)

					// Per-fetch cap layered under the global ctx.
					fetchCtx, cancel := context.WithTimeout(ctx, DefaultHTTPTimeout)
					req, err := http.NewRequestWithContext(fetchCtx, "GET", cdpURL, nil)
					if err != nil {
						cancel()
						errMsgs = append(errMsgs, fmt.Sprintf("%s: bad request: %v", cdpURL, err))
						continue
					}
					req.Header.Set("User-Agent", "x509-cert-validator/1.0")

					resp, err := client.Do(req)
					if err != nil {
						cancel()
						errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", cdpURL, err))
						continue
					}

					if resp.StatusCode != 200 {
						_ = resp.Body.Close()
						cancel()
						errMsgs = append(errMsgs, fmt.Sprintf("%s: HTTP %d", cdpURL, resp.StatusCode))
						continue
					}

					data, err := readWithLimit(resp.Body, maxCRLDownloadBytes)
					_ = resp.Body.Close()
					cancel()
					if err != nil {
						errMsgs = append(errMsgs, fmt.Sprintf("%s: read failed (%v)", cdpURL, err))
						continue
					}

					parsed, err := x509util.ParseRevocationListFromData(data)
					if err != nil {
						if x509util.LooksLikeUnsupportedAlgoErr(err) {
							hasUnsupportedAlgo = true
						}
						if x509util.LooksLikeInsecureAlgoErr(err) {
							hasInsecureAlgo = true
						}
						errMsgs = append(errMsgs, fmt.Sprintf("%s: parse failed", cdpURL))
						continue
					}
					crl = parsed
					crlCache[cdpURL] = crlCacheEntry{rl: parsed}
				}

				// H-2: verify CRL Issuer DN matches parent CA Subject DN before signature check.
				// Catches the rare same-key-different-CA edge case earlier with a clearer error
				// (the subsequent sig check would also reject, but with a less informative message).
				if !bytes.Equal(crl.RawIssuer, parent.RawSubject) {
					logNormal("⚠️  CRL Issuer DN does not match parent CA Subject DN (CRL Issuer=%q vs Parent=%q). Treating CRL as invalid.\n",
						crl.Issuer.String(), parent.Subject.String())
					errMsgs = append(errMsgs, fmt.Sprintf("%s: CRL Issuer DN does not match parent CA Subject DN", cdpURL))
					continue
				}

				// Signature must validate against issuer
				if err := crl.CheckSignatureFrom(parent); err != nil {
					if x509util.LooksLikeUnsupportedAlgoErr(err) {
						hasUnsupportedAlgo = true
					}
					if x509util.LooksLikeInsecureAlgoErr(err) {
						hasInsecureAlgo = true
					}
					errMsgs = append(errMsgs, fmt.Sprintf("%s: invalid signature", cdpURL))
					continue
				}

				// Log key type/length used for CRL signature verification (requested).
				logNormal("   ℹ️  CRL Signature Verified: SigAlg=%s SignedByKey=%s Issuer=%s\n",
					crl.SignatureAlgorithm, x509util.CertPublicKeySummary(parent), x509util.CnOrDN(parent))

				// Missing ThisUpdate/NextUpdate => warning + treat as invalid for -crl
				if crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() {
					logNormal("⚠️  WARNING: CRL from %s missing ThisUpdate/NextUpdate; treating as invalid for -crl.\n", cdpURL)
					errMsgs = append(errMsgs, fmt.Sprintf("%s: missing ThisUpdate/NextUpdate", cdpURL))
					continue
				}

				if now.Before(crl.ThisUpdate) || now.After(crl.NextUpdate) {
					errMsgs = append(errMsgs, fmt.Sprintf("%s: CRL expired or future", cdpURL))
					continue
				}

				// This is a valid responding CRL
				validCRLFound = true

				// If any responding CRL reports revoked => fail (clear statement)
				for _, revoked := range crl.RevokedCertificateEntries {
					if child.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
						return fmt.Errorf("certificate '%s' (Serial=%s) is REVOKED according to CRL %s",
							x509util.CnOrDN(child), x509util.SerialHex(child), cdpURL)
					}
				}

				logNormal("   ✅ Valid CRL checked via %s\n", cdpURL)
				// Do NOT break: another responding CDP might still report revoked.
			}

			if !validCRLFound {
				return fmt.Errorf("failed to check CRL for %s. Errors: %v", x509util.CnOrDN(child), errMsgs)
			}
		}
	}
	return nil
}

func fetchAIA(ctx context.Context, cert *x509.Certificate) (*x509.Certificate, error) {
	client := &http.Client{
		Timeout: DefaultHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= DefaultMaxHTTPRedirects {
				return fmt.Errorf("stopped after %d redirects", DefaultMaxHTTPRedirects)
			}
			return nil
		},
	}
	var lastErr error

	for i, u := range cert.IssuingCertificateURL {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			// M-2: surface skipped non-http(s) AIA URLs instead of silently ignoring them.
			logNormal("⚠️  Skipping AIA URL with unsupported scheme [%d/%d]: %s\n", i+1, len(cert.IssuingCertificateURL), u)
			continue
		}
		logNormal("⬇️  Fetching Parent via AIA [%d/%d]: %s\n", i+1, len(cert.IssuingCertificateURL), u)

		// Per-fetch cap layered under the global ctx.
		fetchCtx, cancel := context.WithTimeout(ctx, DefaultHTTPTimeout)
		req, err := http.NewRequestWithContext(fetchCtx, "GET", u, nil)
		if err != nil {
			cancel()
			logNormal("   ⚠️  Bad Request: %v\n", err)
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "x509-cert-validator/1.0")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			logNormal("   ⚠️  Connection Failed: %v\n", err)
			lastErr = err
			continue
		}

		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			cancel()
			logNormal("   ⚠️  HTTP Error: %d\n", resp.StatusCode)
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		}

		data, err := readWithLimit(resp.Body, maxAIADownloadBytes)
		_ = resp.Body.Close()
		cancel()
		if err != nil {
			logNormal("   ⚠️  Read Failed: %v\n", err)
			lastErr = err
			continue
		}

		fetchedCerts := parseCertsFromDataSafe(data)
		if len(fetchedCerts) > 0 {
			fetched := fetchedCerts[0]
			flagUnsupportedIfNeeded(fetched)

			// H-1: verify name + signature binding between fetched cert and the child whose AIA we followed.
			// Diagnostic-friendly: on mismatch, WARN but still return the cert so the operator can SEE
			// what the AIA URL served. The final x509.Verify is the cryptographic safety net.
			nameOK := bytes.Equal(cert.RawIssuer, fetched.RawSubject)
			sigOK := cert.CheckSignatureFrom(fetched) == nil
			switch {
			case !nameOK && !sigOK:
				logNormal("   ⚠️  AIA cert from %s does NOT match expected issuer of '%s' (subject mismatch AND bad signature). Adding to pool anyway for diagnostic visibility.\n", u, x509util.CnOrDN(cert))
			case !nameOK:
				logNormal("   ⚠️  AIA cert from %s has Subject DN that does NOT match expected Issuer DN of '%s'. Adding to pool anyway for diagnostic visibility.\n", u, x509util.CnOrDN(cert))
			case !sigOK:
				logNormal("   ⚠️  AIA cert from %s did NOT sign '%s' (signature check failed). Adding to pool anyway for diagnostic visibility.\n", u, x509util.CnOrDN(cert))
			default:
				logNormal("   ✅ AIA cert verified against child issuer (name + signature OK).\n")
			}

			return fetched, nil
		}
		logNormal("   ⚠️  Parse Failed\n")
		lastErr = fmt.Errorf("unable to parse certificate data")
	}
	return nil, fmt.Errorf("all AIA URLs failed. Last error: %v", lastErr)
}

func readWithLimit(r io.Reader, limit int64) ([]byte, error) {
	// Read up to limit+1 so we can reliably detect truncation.
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeded size limit (%d bytes); increase the corresponding -max* flag if needed", limit)
	}
	return data, nil
}

func logNormal(format string, args ...any) {
	if verbosity == LevelNormal {
		fmt.Printf(format, args...)
	}
}

func exitErr(err error) {
	if verbosity == LevelUltraSilent {
		os.Exit(1)
	}
	if verbosity == LevelSilent {
		id := "UNKNOWN"
		sn := "?"
		if targetLeaf != nil {
			id = targetLeaf.Subject.CommonName
			if id == "" {
				id = "No-CN"
			}
			sn = x509util.SerialHex(targetLeaf)
		}
		fmt.Fprintf(os.Stderr, "FAIL [%s] Serial:%s : %v\n", id, sn, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "❌ ERROR: %v\n", err)
	os.Exit(1)
}

func exitSuccess() {
	if verbosity == LevelUltraSilent {
		os.Exit(0)
	}
	if verbosity == LevelSilent {
		id := "UNKNOWN"
		sn := "?"
		if targetLeaf != nil {
			id = targetLeaf.Subject.CommonName
			if id == "" {
				id = "No-CN"
			}
			sn = x509util.SerialHex(targetLeaf)
		}
		fmt.Printf("PASS [%s] Serial:%s\n", id, sn)
		os.Exit(0)
	}
	os.Exit(0)
}

func printShortID(role string, cert *x509.Certificate) {
	flagUnsupportedIfNeeded(cert)
	hash := sha256.Sum256(cert.Raw)
	logNormal("[%s] %s... (CN=%s, Key=%s)\n", role, hex.EncodeToString(hash[:])[:8], cert.Subject.CommonName, x509util.CertPublicKeySummary(cert))
}

func printCertDetails(label string, cert *x509.Certificate) {
	flagUnsupportedIfNeeded(cert)
	logNormal("\n=== %s Certificate Details ===\n", label)
	logNormal("Subject:     %s\n", cert.Subject)
	logNormal("Issuer:      %s\n", cert.Issuer)
	if showAllFP {
		logNormal("FP(md5):     %x\n", md5.Sum(cert.Raw)) // #nosec G401 -- diagnostic fingerprint, not used for cryptographic verification.
	}
	logNormal("FP(sha1):    %x\n", sha1.Sum(cert.Raw)) // #nosec G401 -- diagnostic fingerprint (parity with openssl/certutil), not used for cryptographic verification.
	logNormal("FP(sha256):  %x\n", sha256.Sum256(cert.Raw))
	if showAllFP {
		logNormal("FP(sha384):  %x\n", sha512.Sum384(cert.Raw))
		logNormal("FP(sha512):  %x\n", sha512.Sum512(cert.Raw))
	}
	logNormal("Serial:      %s\n", x509util.SerialHex(cert))
	logNormal("Validity:    %s to %s\n", cert.NotBefore, cert.NotAfter)

	// Requested: key type + length, plus signature algorithm
	logNormal("Public Key:  %s\n", x509util.CertPublicKeySummary(cert))
	logNormal("Sig Alg:     %s\n", cert.SignatureAlgorithm)

	if len(cert.DNSNames) > 0 {
		logNormal("SAN (DNS):   %v\n", cert.DNSNames)
	}
	if len(cert.IssuingCertificateURL) > 0 {
		logNormal("AIA (Issuer): %v\n", cert.IssuingCertificateURL)
	}
	if len(cert.CRLDistributionPoints) > 0 {
		logNormal("CRL DPs:     %v\n", cert.CRLDistributionPoints)
	}

	// Name Constraints (requested)
	printNameConstraints("", cert)
}

func loadAll(ctx context.Context, input string) []*x509.Certificate {
	s := strings.ToLower(strings.TrimSpace(input))
	if strings.HasPrefix(s, "file://") {
		exitErr(fmt.Errorf("unsupported path scheme: file:// is not accepted (%s)", input))
	}

	if strings.HasPrefix(s, "https://") {
		return fetchRemoteCert(ctx, input)
	}
	if strings.HasPrefix(s, "http://") {
		return downloadCertFile(ctx, input)
	}
	return loadLocalFile(input)
}

func fetchRemoteCert(ctx context.Context, urlStr string) []*x509.Certificate {
	u, err := url.Parse(urlStr)
	if err != nil {
		exitErr(fmt.Errorf("invalid url: %v", err))
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "443")
	}
	logNormal("⬇️  Connecting to remote server: %s ...\n", host)

	// #nosec G402 -- this tool is a TLS *diagnostic*; we deliberately disable Go's built-in chain verification so we can collect and analyze the server-presented chain ourselves via x509.Verify (with caller-controlled roots/intermediates and -dns/-sni hostname checks). Documented behavior, not an oversight.
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // we validate ourselves via x509.Verify
	if sniOverride != "" {
		cfg.ServerName = sniOverride
		logNormal("ℹ️  Using SNI override: %s\n", sniOverride)
	}

	// Per-fetch cap layered under the global ctx; whichever fires first wins.
	dialCtx, cancel := context.WithTimeout(ctx, DefaultTLSProbeTimeout)
	defer cancel()

	tlsDialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}
	rawConn, err := tlsDialer.DialContext(dialCtx, "tcp", host)
	if err != nil {
		exitErr(fmt.Errorf("failed to connect to %s: %v", host, err))
	}
	conn := rawConn.(*tls.Conn)
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		exitErr(fmt.Errorf("no certificates presented by %s", host))
	}
	logNormal("✅ Retrieved %d certificates from server.\n", len(state.PeerCertificates))
	for _, c := range state.PeerCertificates {
		flagUnsupportedIfNeeded(c)
	}
	return state.PeerCertificates
}

func downloadCertFile(ctx context.Context, urlStr string) []*x509.Certificate {
	u, err := url.Parse(urlStr)
	if err != nil {
		exitErr(fmt.Errorf("invalid url: %v", err))
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		exitErr(fmt.Errorf("unsupported protocol scheme: %s (only http/https allowed)", u.Scheme))
	}
	logNormal("⬇️  Downloading certificate file: %s ...\n", urlStr)

	client := &http.Client{
		Timeout: DefaultHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= DefaultMaxHTTPRedirects {
				return fmt.Errorf("stopped after %d redirects", DefaultMaxHTTPRedirects)
			}
			return nil
		},
	}

	// Per-fetch cap layered under the global ctx.
	fetchCtx, cancel := context.WithTimeout(ctx, DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, "GET", urlStr, nil)
	if err != nil {
		exitErr(fmt.Errorf("request creation failed: %v", err))
	}
	req.Header.Set("User-Agent", "x509-cert-validator/1.0")

	resp, err := client.Do(req)
	if err != nil {
		exitErr(fmt.Errorf("download failed: %v", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		exitErr(fmt.Errorf("download failed with status: %d", resp.StatusCode))
	}

	data, err := readWithLimit(resp.Body, maxRemoteCertFileSize)
	if err != nil {
		exitErr(fmt.Errorf("read failed: %v", err))
	}

	return parseCertsFromData(data, urlStr)
}

func loadLocalFile(path string) []*x509.Certificate {
	// #nosec G304 -- this tool's purpose is to read user-specified certificate files (-cert, -root); the path being a variable is by design.
	f, err := os.Open(path)
	if err != nil {
		exitErr(fmt.Errorf("read error (%s): %v", path, err))
	}
	defer f.Close()

	data, err := readWithLimit(f, maxLocalFileBytes)
	if err != nil {
		exitErr(fmt.Errorf("read error (%s): %v", path, err))
	}

	return parseCertsFromData(data, path)
}

func parseCertsFromData(data []byte, source string) []*x509.Certificate {
	var certs []*x509.Certificate
	blockData := data
	for {
		var block *pem.Block
		block, blockData = pem.Decode(blockData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				if x509util.LooksLikeUnsupportedAlgoErr(err) {
					hasUnsupportedAlgo = true
				}
				if x509util.LooksLikeInsecureAlgoErr(err) {
					hasInsecureAlgo = true
				}
				logNormal("Skipping unparsable block in %s: %v\n", source, err)
			} else {
				flagUnsupportedIfNeeded(c)
				certs = append(certs, c)
			}
		}
	}
	if len(certs) == 0 {
		c, err := x509.ParseCertificate(data)
		if err == nil {
			flagUnsupportedIfNeeded(c)
			return []*x509.Certificate{c}
		}
		if x509util.LooksLikeUnsupportedAlgoErr(err) {
			hasUnsupportedAlgo = true
		}
		if x509util.LooksLikeInsecureAlgoErr(err) {
			hasInsecureAlgo = true
		}
		exitErr(fmt.Errorf("no certificates found in %s", source))
	}
	return certs
}

func parseCertsFromDataSafe(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	blockData := data
	for {
		var block *pem.Block
		block, blockData = pem.Decode(blockData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				flagUnsupportedIfNeeded(c)
				certs = append(certs, c)
			} else {
				if x509util.LooksLikeUnsupportedAlgoErr(err) {
					hasUnsupportedAlgo = true
				}
				if x509util.LooksLikeInsecureAlgoErr(err) {
					hasInsecureAlgo = true
				}
			}
		}
	}
	if len(certs) == 0 {
		c, err := x509.ParseCertificate(data)
		if err == nil {
			flagUnsupportedIfNeeded(c)
			certs = append(certs, c)
		} else {
			if x509util.LooksLikeUnsupportedAlgoErr(err) {
				hasUnsupportedAlgo = true
			}
			if x509util.LooksLikeInsecureAlgoErr(err) {
				hasInsecureAlgo = true
			}
		}
	}
	return certs
}

// --- Graph view (updated to show full Name Constraints details) ---

func printChainGraph(chain []*x509.Certificate) {
	if verbosity == LevelUltraSilent {
		return
	}

	// First pass: collect fixed fields per cert and determine box width.
	type certInfo struct {
		role, subCN, issCN, key, sig, sn string
		cert                             *x509.Certificate
	}
	var infos []certInfo

	minW := 48
	maxLen := minW

	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		role := "INTERMEDIATE"
		if i == len(chain)-1 {
			role = "ROOT ANCHOR"
		}
		if i == 0 {
			role = "TARGET LEAF"
		}

		subCN := cert.Subject.CommonName
		if subCN == "" {
			subCN = "No-CN"
		}
		issCN := cert.Issuer.CommonName
		if issCN == "" {
			issCN = "No-CN"
		}

		info := certInfo{
			role:  role,
			subCN: subCN,
			issCN: issCN,
			key:   x509util.CertPublicKeySummary(cert),
			sig:   cert.SignatureAlgorithm.String(),
			sn:    x509util.SerialHex(cert),
			cert:  cert,
		}
		infos = append(infos, info)

		for _, s := range []string{role, "CN: " + subCN, "Issuer: " + issCN, "Key: " + info.key, "Sig: " + info.sig, "SN: " + info.sn} {
			if len(s) > maxLen {
				maxLen = len(s)
			}
		}
	}

	// Second pass: print with the computed width.
	w := maxLen
	border := "+" + strings.Repeat("-", w+2) + "+"
	boxLine := func(s string) {
		fmt.Printf("| %-*s |\n", w, truncate(s, w))
	}

	fmt.Println()
	for idx, info := range infos {
		ncLines := buildNameConstraintLines(info.cert, w)

		fmt.Println(border)
		boxLine(info.role)
		boxLine("CN: " + info.subCN)
		boxLine("Issuer: " + info.issCN)
		boxLine("Key: " + info.key)
		boxLine("Sig: " + info.sig)

		for _, l := range ncLines {
			boxLine(l)
		}

		boxLine("SN: " + info.sn)
		fmt.Println(border)

		if idx < len(infos)-1 {
			fmt.Println("      |")
			fmt.Println("      V")
		}
	}
	fmt.Println()
}

func truncate(s string, length int) string {
	if len(s) > length {
		return s[:length-3] + "..."
	}
	return s
}

// --- Name Constraints ---

func hasAnyNameConstraints(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return cert.PermittedDNSDomainsCritical ||
		len(cert.PermittedDNSDomains) > 0 ||
		len(cert.ExcludedDNSDomains) > 0 ||
		len(cert.PermittedIPRanges) > 0 ||
		len(cert.ExcludedIPRanges) > 0 ||
		len(cert.PermittedEmailAddresses) > 0 ||
		len(cert.ExcludedEmailAddresses) > 0 ||
		len(cert.PermittedURIDomains) > 0 ||
		len(cert.ExcludedURIDomains) > 0
}

func ipNetListToStrings(nets []*net.IPNet) []string {
	if len(nets) == 0 {
		return nil
	}
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		if n == nil {
			continue
		}
		out = append(out, n.String())
	}
	return out
}

// Wraps a list into multiple lines within a fixed width.
// First line starts with "Label: ", continuation lines align under it.
func wrapList(label string, items []string, width int) []string {
	if len(items) == 0 {
		return nil
	}
	prefix := label + ": "
	contPrefix := strings.Repeat(" ", len(prefix))

	var lines []string
	cur := prefix

	for _, it := range items {
		if it == "" {
			continue
		}

		sep := ""
		if cur != prefix && cur != contPrefix {
			sep = ", "
		}

		token := sep + it
		if len(cur)+len(token) <= width {
			cur += token
			continue
		}

		lines = append(lines, truncate(cur, width))

		cur = contPrefix + it
		if len(cur) > width {
			lines = append(lines, truncate(cur, width))
			cur = contPrefix
		}
	}

	if strings.TrimSpace(cur) != "" && cur != contPrefix {
		lines = append(lines, truncate(cur, width))
	}
	return lines
}

func buildNameConstraintLines(cert *x509.Certificate, width int) []string {
	if cert == nil {
		return []string{"NC: unknown"}
	}
	if !hasAnyNameConstraints(cert) {
		return []string{"NC: no"}
	}

	crit := ""
	if cert.PermittedDNSDomainsCritical {
		crit = " (critical)"
	}

	var out []string
	out = append(out, "NC: yes"+crit)

	out = append(out, wrapList("PermDNS", cert.PermittedDNSDomains, width)...)
	out = append(out, wrapList("ExclDNS", cert.ExcludedDNSDomains, width)...)

	out = append(out, wrapList("PermIP", ipNetListToStrings(cert.PermittedIPRanges), width)...)
	out = append(out, wrapList("ExclIP", ipNetListToStrings(cert.ExcludedIPRanges), width)...)

	out = append(out, wrapList("PermEmail", cert.PermittedEmailAddresses, width)...)
	out = append(out, wrapList("ExclEmail", cert.ExcludedEmailAddresses, width)...)

	out = append(out, wrapList("PermURI", cert.PermittedURIDomains, width)...)
	out = append(out, wrapList("ExclURI", cert.ExcludedURIDomains, width)...)

	return out
}

func printNameConstraints(prefix string, cert *x509.Certificate) {
	if verbosity != LevelNormal {
		return
	}
	if cert == nil {
		return
	}
	if !hasAnyNameConstraints(cert) {
		return
	}

	crit := ""
	if cert.PermittedDNSDomainsCritical {
		crit = " (critical)"
	}

	logNormal("%s    Name Constraints:%s\n", prefix, crit)

	if len(cert.PermittedDNSDomains) > 0 {
		logNormal("%s      Permitted DNS:   %v\n", prefix, cert.PermittedDNSDomains)
	}
	if len(cert.ExcludedDNSDomains) > 0 {
		logNormal("%s      Excluded DNS:    %v\n", prefix, cert.ExcludedDNSDomains)
	}

	if len(cert.PermittedIPRanges) > 0 {
		logNormal("%s      Permitted IP:    %v\n", prefix, ipNetListToStrings(cert.PermittedIPRanges))
	}
	if len(cert.ExcludedIPRanges) > 0 {
		logNormal("%s      Excluded IP:     %v\n", prefix, ipNetListToStrings(cert.ExcludedIPRanges))
	}

	if len(cert.PermittedEmailAddresses) > 0 {
		logNormal("%s      Permitted Email: %v\n", prefix, cert.PermittedEmailAddresses)
	}
	if len(cert.ExcludedEmailAddresses) > 0 {
		logNormal("%s      Excluded Email:  %v\n", prefix, cert.ExcludedEmailAddresses)
	}

	if len(cert.PermittedURIDomains) > 0 {
		logNormal("%s      Permitted URI:   %v\n", prefix, cert.PermittedURIDomains)
	}
	if len(cert.ExcludedURIDomains) > 0 {
		logNormal("%s      Excluded URI:    %v\n", prefix, cert.ExcludedURIDomains)
	}
}

// --- Key helpers ---

