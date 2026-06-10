package main

import (
	"context"
	"crypto/md5"  // #nosec G501 -- MD5 fingerprints are intentionally exposed (-fp-show-all) as a diagnostic identifier, not for cryptographic security.
	"crypto/sha1" // #nosec G505 -- SHA-1 fingerprints are a standard, intentional diagnostic identifier (parity with openssl x509 -fingerprint -sha1).
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/andrico21/x509-cert-validator/internal/aia"
	"github.com/andrico21/x509-cert-validator/internal/bundle"
	"github.com/andrico21/x509-cert-validator/internal/certload"
	"github.com/andrico21/x509-cert-validator/internal/cli"
	"github.com/andrico21/x509-cert-validator/internal/crl"
	"github.com/andrico21/x509-cert-validator/internal/display"
	"github.com/andrico21/x509-cert-validator/internal/errs"
	"github.com/andrico21/x509-cert-validator/internal/validator"
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

	// Effective limits (set from flags). MaxAIA/MaxCRL now live on
	// runValidator; only globals still referenced by stateful per-print
	// helpers remain here pending Step J.
	maxLocalFileBytes     int64 = DefaultMaxLocalFileBytes
	maxRemoteCertFileSize int64 = DefaultMaxRemoteCertFileSize
	showAllFP             bool

	// runValidator carries the run-scoped *http.Client + Logger + size
	// caps shared by every network caller (AIA, CRL). Built once in
	// main() from the parsed cli.Config; nil before main() initializes
	// it. Future Step J will move main() out of this package and this
	// global will become a parameter threaded through the call chain.
	runValidator *validator.Validator
)

func main() {
	cfg, err := cli.Parse(os.Args[1:], os.Args[0], os.Stderr)
	if err != nil {
		var perr *cli.ParseError
		if errors.As(err, &perr) {
			// Usage (when applicable) was already rendered by cli.Parse's
			// fs.Usage closure. Message is empty for -h (exit 0).
			if perr.Message != "" {
				fmt.Fprintln(os.Stderr, perr.Message)
			}
			os.Exit(perr.ExitCode)
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if cfg.ShowVersion {
		fmt.Printf("x509-cert-validator %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// --- Mirror cfg into legacy globals + locals so the rest of main()
	// continues to work unchanged. Future steps will hoist these into a
	// Validator struct and remove the globals entirely. ---
	maxLocalFileBytes = cfg.MaxLocal
	maxRemoteCertFileSize = cfg.MaxRemote
	showAllFP = cfg.FPShowAll
	verbosity = int(cfg.Verbosity)
	sniOverride = cfg.SNI

	// Build the run-scoped Validator: one *http.Client (connection pool
	// shared across AIA + CRL fetches in this run), one Logger, all
	// size caps captured up front. Subsequent network adapters read
	// from runValidator instead of allocating per-call.
	runValidator = validator.New(
		validator.Verbosity(verbosity),
		DefaultHTTPTimeout,
		DefaultMaxHTTPRedirects,
		cfg.MaxAIA, cfg.MaxCRL, cfg.MaxLocal, cfg.MaxRemote,
		nil, // logger=nil -> NewStderrLogger(level)
	)

	// Pointer locals preserve the legacy *string / *bool deref pattern
	// downstream without touching every call site.
	certPath := &cfg.CertPath
	rootPath := &cfg.RootPath
	dnsName := &cfg.DNSName
	enableCRL := &cfg.EnableCRL
	enableAIA := &cfg.EnableAIA
	createBundlePath := &cfg.CreateBundlePath
	includeRoot := &cfg.IncludeRoot
	usage := &cfg.Usage
	showGraph := &cfg.ShowGraph

	if *certPath == "" {
		if verbosity == LevelNormal {
			// Re-render usage to stderr exactly like the old flag.Usage call.
			_, _ = cli.Parse([]string{"-h"}, os.Args[0], os.Stderr)
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

	logNormal("Runtime: %s\n", runtime.Version())

	// --- 0. Root context with global wall-clock cap for all network operations.
	// Per-fetch caps (DefaultHTTPTimeout / DefaultTLSProbeTimeout) still apply
	// inside individual helpers; this umbrella prevents pathological worst-case
	// latency from a deep AIA walk + many CRL fetches stacking up.
	ctx, cancelCtx := context.WithTimeout(context.Background(), DefaultGlobalTimeout)
	defer cancelCtx()

	// --- 1. Setup Validation Time ---
	currentTime := time.Now()
	if !cfg.AtTime.IsZero() {
		currentTime = cfg.AtTime
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

	if len(cfg.IntermediateArgs) > 0 {
		logNormal("\n--- Loading Intermediates (CLI) ---\n")
		for _, path := range cfg.IntermediateArgs {
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
	highlightLeafIssues(leaf, currentTime)

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

		toBundle := bundle.FromVerifiedChains(chains, *includeRoot)

		// If for some reason Go didn't return anything to bundle, fall back to what we discovered locally.
		if len(toBundle) == 0 {
			toBundle = bundle.FromDiscovered(discoveredIntermediates, rootCerts, *includeRoot)
		}

		if len(toBundle) == 0 {
			logNormal("⚠️  No certificates available to bundle.\n")
		} else {
			written, rootsWritten, err := bundle.WritePEM(*createBundlePath, toBundle)
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

// verifyFailureHint returns the operator-facing hint lines (each ending in
// "\n") for a chain-verification failure. Ordering is deliberate: specific
// error content (hostname mismatch, key usage) takes precedence over the
// run-global algorithm flags so that an unrelated unsupported-algo cert
// observed during loading cannot mask the real cause. Algorithm hints
// still fire for generic errors (e.g. "unknown authority" caused by a
// GOST intermediate Go could not use) via the hasUnsupported/hasInsecure
// fallbacks.
func verifyFailureHint(err error, leaf *x509.Certificate, hasUnsupported, hasInsecure bool, certPath, rootPath, usage string) []string {
	var lines []string
	add := func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	msg := err.Error()

	switch {
	case strings.Contains(msg, "x509") && strings.Contains(msg, "valid for"):
		add("  (Tip: Hostname mismatch; use -dns or -sni appropriately)\n")

	case strings.Contains(msg, "KeyUsage") || strings.Contains(msg, "key usage"):
		add("  (Tip: Check if the certificate is valid for the requested type: %s)\n", usage)

	case errs.LooksLikeUnsupportedAlgoErr(err) || hasUnsupported:
		add("\n⚠️  CRITICAL HINT: Go rejected this chain because it contains an unsupported algorithm/curve (e.g., GOST or unsupported EC curve).\n")
		add("   Please try verifying with OpenSSL directly:\n")
		add("   $ openssl x509 -in %s -noout -text\n", certPath)
		if rootPath != "" {
			add("   $ openssl verify -CAfile %s %s\n\n", rootPath, certPath)
		} else {
			add("   $ openssl verify %s\n\n", certPath)
		}

	case errs.LooksLikeInsecureAlgoErr(err) || hasInsecure:
		add("\n⚠️  CRITICAL HINT: Go refused to verify due to an insecure signature algorithm policy (e.g., SHA1/MD5).\n")
		if leaf != nil {
			add("   Leaf Signature Algorithm: %s\n", leaf.SignatureAlgorithm)
			add("   Leaf Public Key: %s\n", x509util.CertPublicKeySummary(leaf))
		}
		add("   Verify with OpenSSL to confirm the chain, then re-issue with a modern hash (SHA-256+):\n")
		add("   $ openssl x509 -in %s -noout -text\n", certPath)
		if rootPath != "" {
			add("   $ openssl verify -CAfile %s %s\n\n", rootPath, certPath)
		} else {
			add("   $ openssl verify %s\n\n", certPath)
		}

	case strings.Contains(msg, "authority"):
		if x509util.IsSelfSigned(leaf) {
			add("  (Tip: Certificate is self-signed and not in the system trust store. Use -root to trust it explicitly.)\n")
		} else {
			add("  (Tip: Ensure intermediates are provided or use -aia)\n")
		}
	}
	return lines
}

func handleVerifyError(err error, certPath, rootPath, usage string) {
	if errs.LooksLikeUnsupportedAlgoErr(err) {
		hasUnsupportedAlgo = true
	}
	if errs.LooksLikeInsecureAlgoErr(err) {
		hasInsecureAlgo = true
	}

	for _, line := range verifyFailureHint(err, targetLeaf, hasUnsupportedAlgo, hasInsecureAlgo, certPath, rootPath, usage) {
		logNormal("%s", line)
	}

	exitErr(fmt.Errorf("VALIDATION FAILED: %v", err))
}

// highlightLeafIssues prints heuristic warnings about the leaf. now is the
// effective validation time (honors -at) so heuristics and x509.Verify
// agree on what "expired" means within a single run.
func highlightLeafIssues(cert *x509.Certificate, now time.Time) {
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

	if now.After(cert.NotAfter) {
		logNormal("⚠️  WARNING: Certificate is EXPIRED (NotAfter: %s, %s ago).\n",
			cert.NotAfter.Format(time.RFC3339),
			display.HumanDuration(now.Sub(cert.NotAfter)))
	} else if now.Before(cert.NotBefore) {
		logNormal("⚠️  WARNING: Certificate is NOT YET VALID (NotBefore: %s, starts in %s).\n",
			cert.NotBefore.Format(time.RFC3339),
			display.HumanDuration(cert.NotBefore.Sub(now)))
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
				display.HumanDuration(remaining), cert.NotAfter.Format(time.RFC3339))
		}
	}

	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		logNormal("⚠️  WARNING: Certificate has no SAN entries.\n")
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		logNormal("⚠️  WARNING: Leaf appears to be a CA certificate (IsCA=true).\n")
	}
}

// checkCRL adapts crl.Checker to the legacy global-flag contract used
// by main's CRL-check call site. Built around the run-scoped
// runValidator so the *http.Client connection pool is shared with
// every AIA fetch and remote-cert download in the same run.
func checkCRL(ctx context.Context, chains [][]*x509.Certificate, now time.Time) error {
	c := &crl.Checker{
		Client:          runValidator.HTTPClient,
		Logger:          runValidator.Logger,
		MaxBytes:        runValidator.MaxCRLBytes,
		PerFetchTimeout: runValidator.PerFetchTimeout,
	}
	res, err := c.Check(ctx, chains, now)
	if res.HasUnsupportedAlgo {
		hasUnsupportedAlgo = true
	}
	if res.HasInsecureAlgo {
		hasInsecureAlgo = true
	}
	return err
}

// fetchAIA adapts aia.Fetcher to the legacy global-flag contract used
// by main's chain-walk loop. Built around the run-scoped runValidator
// so the *http.Client connection pool is shared with every CRL fetch
// and remote-cert download in the same run.
func fetchAIA(ctx context.Context, cert *x509.Certificate) (*x509.Certificate, error) {
	f := &aia.Fetcher{
		Client:          runValidator.HTTPClient,
		Logger:          runValidator.Logger,
		MaxBytes:        runValidator.MaxAIABytes,
		PerFetchTimeout: runValidator.PerFetchTimeout,
	}
	res, err := f.Fetch(ctx, cert)
	if res.HasUnsupportedAlgo {
		hasUnsupportedAlgo = true
	}
	if res.HasInsecureAlgo {
		hasInsecureAlgo = true
	}
	if res.Parent != nil {
		flagUnsupportedIfNeeded(res.Parent)
	}
	return res.Parent, err
}

// readWithLimit is a thin wrapper around certload.ReadWithLimit kept
// for call-site brevity until certload is consumed directly by an
// extracted aia/crl subpackage in later PR5b steps.
func readWithLimit(r io.Reader, limit int64) ([]byte, error) {
	return certload.ReadWithLimit(r, limit)
}

// logNormal prints normal-verbosity diagnostics. The formatted output is
// passed through display.SanitizeTerminal so untrusted certificate fields
// (CNs, DNs, SANs, URLs) cannot inject terminal escape sequences.
func logNormal(format string, args ...any) {
	if verbosity == LevelNormal {
		fmt.Print(display.SanitizeTerminal(fmt.Sprintf(format, args...)))
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
		fmt.Fprint(os.Stderr, display.SanitizeTerminal(fmt.Sprintf("FAIL [%s] Serial:%s : %v\n", id, sn, err)))
		os.Exit(1)
	}
	fmt.Fprint(os.Stderr, display.SanitizeTerminal(fmt.Sprintf("❌ ERROR: %v\n", err)))
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
		fmt.Print(display.SanitizeTerminal(fmt.Sprintf("PASS [%s] Serial:%s\n", id, sn)))
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

// parseCertsFromData adapts certload.ParseCerts to the legacy
// exitErr/global-flag contract still used by main: it ORs the
// algorithm-rejection flags into the package globals, surfaces skipped
// PEM-block warnings via logNormal, and aborts via exitErr when no
// certificates were parsed. Helper certs returned by certload also flow
// through flagUnsupportedIfNeeded to catch unknown OIDs that x509.ParseCertificate
// accepted but we still want to flag.
func parseCertsFromData(data []byte, source string) []*x509.Certificate {
	res, err := certload.ParseCerts(data, source)
	if res.HasUnsupportedAlgo {
		hasUnsupportedAlgo = true
	}
	if res.HasInsecureAlgo {
		hasInsecureAlgo = true
	}
	for _, msg := range res.SkippedBlocks {
		logNormal("%s\n", msg)
	}
	if err != nil {
		exitErr(err)
	}
	for _, c := range res.Certs {
		flagUnsupportedIfNeeded(c)
	}
	return res.Certs
}

// --- Graph view (updated to show full Name Constraints details) ---

func printChainGraph(chain []*x509.Certificate) {
	// Graph output is normal-verbosity diagnostics; -silent promises
	// "only pass/fail status" and -ultra-silent promises nothing at all.
	if verbosity != LevelNormal {
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
		// Sanitize: box content embeds untrusted cert fields (CN/serial).
		fmt.Print(display.SanitizeTerminal(fmt.Sprintf("| %-*s |\n", w, display.Truncate(s, w))))
	}

	fmt.Println()
	for idx, info := range infos {
		ncLines := display.BuildNameConstraintLines(info.cert, w)

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

// --- Name Constraints ---

func printNameConstraints(prefix string, cert *x509.Certificate) {
	if verbosity != LevelNormal {
		return
	}
	if cert == nil {
		return
	}
	if !display.HasAnyNameConstraints(cert) {
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
		logNormal("%s      Permitted IP:    %v\n", prefix, display.IPNetListToStrings(cert.PermittedIPRanges))
	}
	if len(cert.ExcludedIPRanges) > 0 {
		logNormal("%s      Excluded IP:     %v\n", prefix, display.IPNetListToStrings(cert.ExcludedIPRanges))
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
