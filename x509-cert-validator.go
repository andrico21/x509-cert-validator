package main

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
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
	"strings"
	"time"
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
)

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
)

func main() {
	// --- Usage ---
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
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
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -aia -createCAbundle full-chain.crt")
		fmt.Fprintln(os.Stderr, "     Exporting Root CA (-includeRoot) requires explicit specification of root CA's certificate file (-root <filename>).")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -aia -createCAbundle bundle.crt -includeRoot -root custom-root-ca.crt")
		fmt.Fprintln(os.Stderr, "     (⚠️  SECURITY WARNING: This also exports the Root CA certificate.)")
		fmt.Fprintln(os.Stderr, "     (    Never install an unknown Root CA unless you know what you are doing)")
		fmt.Fprintln(os.Stderr, "     (    and have verified its fingerprint manually.)")
		fmt.Fprintln(os.Stderr, "     (    Trusting a malicious Root might lead to interception of your private data.)")

		fmt.Fprintln(os.Stderr, "\n  5. Visualization:")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -showGraph")

		fmt.Fprintln(os.Stderr, "\n  6. Silent Mode (Short status line only):")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -silent")
		fmt.Fprintln(os.Stderr, "     > PASS [github.com] Serial:12345...")

		fmt.Fprintln(os.Stderr, "\n  7. Ultra Silent (Exit code only):")
		fmt.Fprintln(os.Stderr, "     x509-cert-validator -cert leaf.pem -ultrasilent")
		fmt.Fprintln(os.Stderr, "     (echo $?)")
	}

	// --- CLI Arguments ---
	certPath := flag.String("cert", "", "Path to Certificate PEM/DER, HTTP URL (download), or HTTPS URL (live probe). Note: file:// is NOT supported.")
	rootPath := flag.String("root", "", "Path/URL to Root CA PEM/DER (optional; uses System Roots if empty). Supports local path, http(s) download, or https live-probe (same as -cert).")
	dnsName := flag.String("dns", "", "Optional: Verify specific DNS name")
	sni := flag.String("sni", "", "Optional: Override TLS SNI for live HTTPS probes (https://...)")
	atTime := flag.String("at", "", "Optional: Validate at RFC3339 time")
	enableCRL := flag.Bool("crl", false, "Enable certificate revocation checking (CRL)")
	enableAIA := flag.Bool("aia", false, "Enable automatic AIA fetching")
	createBundlePath := flag.String("createCAbundle", "", "Optional: Path to create/export CA bundle. On success, exports from verified chain(s).")
	includeRoot := flag.Bool("includeRoot", false, "Include Root/Trust-Anchor certificate(s) in the generated bundle")
	usage := flag.String("type", "any", "Validation type: server, client, or any")
	showGraph := flag.Bool("showGraph", false, "Display ASCII graph of the verified chain")
	silent := flag.Bool("silent", false, "Output only pass/fail status and cert ID")
	ultraSilent := flag.Bool("ultrasilent", false, "No output, exit code only (0=Pass, 1=Fail)")

	// --- Size limit flags ---
	maxAIA := flag.Int64("maxaia", DefaultMaxAIADownloadBytes, "Max bytes to download per AIA issuer fetch")
	maxCRL := flag.Int64("maxcrl", DefaultMaxCRLDownloadBytes, "Max bytes to download per CRL URL")
	maxLocal := flag.Int64("maxlocal", DefaultMaxLocalFileBytes, "Max bytes to read from local cert file")
	maxRemote := flag.Int64("maxcert", DefaultMaxRemoteCertFileSize, "Max bytes to download for remote cert file (http/https)")

	flag.Parse()

	// --- Apply size limits ---
	if *maxAIA <= 0 || *maxCRL <= 0 || *maxLocal <= 0 || *maxRemote <= 0 {
		exitErr(fmt.Errorf("size limits must be > 0 (got maxaia=%d maxcrl=%d maxlocal=%d maxcert=%d)", *maxAIA, *maxCRL, *maxLocal, *maxRemote))
	}
	maxAIADownloadBytes = *maxAIA
	maxCRLDownloadBytes = *maxCRL
	maxLocalFileBytes = *maxLocal
	maxRemoteCertFileSize = *maxRemote

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
		for _, cert := range loadAll(*rootPath) {
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
			for _, cert := range loadAll(path) {
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
	targetCerts := loadAll(*certPath)
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
				logNormal("⚠️  WARNING: AIA loop detected (already visited %s). Stopping fetch.\n", cnOrDN(currentCert))
				break
			}
			seen[curKey] = true

			if isSelfSigned(currentCert) {
				logNormal("ℹ️  Reached Self-Signed Root (%s). Stopping fetch.\n", cnOrDN(currentCert))
				break
			}

			// 1) If parent is already in our local pool list, advance to it and keep walking.
			if parent, ok := findParentInListCert(currentCert, poolList); ok && parent != nil {
				logNormal("ℹ️  Found parent locally: %s. Continuing walk.\n", cnOrDN(parent))
				currentCert = parent
				chainDepth++
				continue
			}

			// 2) Otherwise, try to fetch via AIA.
			if len(currentCert.IssuingCertificateURL) == 0 {
				logNormal("ℹ️  No AIA URL found for %s. Cannot fetch parent.\n", cnOrDN(currentCert))
				break
			}

			parentCert, err := fetchAIA(currentCert)
			if err != nil {
				logNormal("⚠️  AIA Fetch failed for %s: %v\n", cnOrDN(currentCert), err)
				break
			}

			parentFP := sha256.Sum256(parentCert.Raw)
			parentKey := hex.EncodeToString(parentFP[:])
			if seen[parentKey] {
				logNormal("⚠️  WARNING: AIA returned a previously seen certificate (%s). Stopping fetch.\n", cnOrDN(parentCert))
				break
			}

			if isSelfSigned(parentCert) {
				logNormal("ℹ️  Fetched cert is Self-Signed Root (%s, Key=%s). Stopping fetch.\n",
					cnOrDN(parentCert), certPublicKeySummary(parentCert))

				// Do NOT automatically trust it for verification. Only keep for optional bundling output.
				rootCerts = append(rootCerts, parentCert)
				poolList = append(poolList, parentCert)

				break
			}

			inters.AddCert(parentCert)
			discoveredIntermediates = append(discoveredIntermediates, parentCert)
			poolList = append(poolList, parentCert)
			logNormal("✅ Added fetched certificate: %s (Key=%s)\n", parentCert.Subject, certPublicKeySummary(parentCert))

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
			for depth, cert := range chain {
				prefix := strings.Repeat("  ", depth)

				subCN := cert.Subject.CommonName
				if subCN == "" {
					subCN = "No-CN"
				}
				issCN := cert.Issuer.CommonName
				if issCN == "" {
					issCN = "No-CN"
				}

				self := ""
				if isSelfSigned(cert) {
					self = " (self-signed)"
				}

				sum := sha256.Sum256(cert.Raw)
				logNormal("%s[%d] Subject: %s%s\n", prefix, depth, subCN, self)
				logNormal("%s    Issuer:  %s\n", prefix, issCN)
				logNormal("%s    FP(sha256): %x\n", prefix, sum[:8])
				logNormal("%s    PubKey: %s\n", prefix, certPublicKeySummary(cert))
				logNormal("%s    SigAlg: %s\n", prefix, cert.SignatureAlgorithm)

				// Name Constraints (requested)
				printNameConstraints(prefix, cert)

				// If issuer is in-chain, show issuer key type/length used to verify this cert's signature.
				if depth+1 < len(chain) {
					issuer := chain[depth+1]
					logNormal("%s    SignedByKey: %s\n", prefix, certPublicKeySummary(issuer))
				} else if isSelfSigned(cert) {
					logNormal("%s    SignedByKey: %s\n", prefix, certPublicKeySummary(cert))
				}
			}
		}
	}

	// --- 10. CRL Check (Strict) ---
	if *enableCRL {
		logNormal("\n=== Checking CRLs ===\n")
		if err := checkCRL(chains, currentTime); err != nil {
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
	f, err := os.Create(tmpPath)
	if err != nil {
		return 0, 0, err
	}

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

		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			_ = f.Close()
			_ = os.Remove(tmpPath)
			return written, rootsWritten, err
		}
		written++
		if isSelfSigned(c) {
			rootsWritten++
		}
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return written, rootsWritten, err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return written, rootsWritten, err
	}

	return written, rootsWritten, nil
}

// --- Helpers ---

func cnOrDN(c *x509.Certificate) string {
	if c == nil {
		return "UNKNOWN"
	}
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

func flagUnsupportedIfNeeded(cert *x509.Certificate) {
	if cert == nil {
		return
	}
	if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm ||
		cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		hasUnsupportedAlgo = true
	}
}

func looksLikeUnsupportedAlgoErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "algorithm unimplemented") ||
		strings.Contains(s, "unknown public key algorithm") ||
		strings.Contains(s, "unknown signature algorithm") ||
		strings.Contains(s, "unsupported elliptic curve") ||
		strings.Contains(s, "unsupported algorithm")
}

func looksLikeInsecureAlgoErr(err error) bool {
	if err == nil {
		return false
	}
	// Go returns errors like:
	//   x509: cannot verify signature: insecure algorithm SHA1-RSA
	return strings.Contains(err.Error(), "insecure algorithm")
}

func parseRevocationListFromData(data []byte) (*x509.RevocationList, error) {
	// Try PEM first (may contain multiple blocks)
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if strings.Contains(block.Type, "CRL") {
			return x509.ParseRevocationList(block.Bytes)
		}
	}
	// Fallback: assume DER
	return x509.ParseRevocationList(data)
}

// Returns the parent certificate if found locally (subject/issuer match + signature check).
func findParentInListCert(child *x509.Certificate, pool []*x509.Certificate) (*x509.Certificate, bool) {
	if child == nil {
		return nil, false
	}
	for _, parent := range pool {
		if parent == nil {
			continue
		}
		// Fast path: DER-equal issuer/subject
		if bytes.Equal(child.RawIssuer, parent.RawSubject) {
			if child.CheckSignatureFrom(parent) == nil {
				return parent, true
			}
			continue
		}
		// Fallback for rare DER encoding differences
		if child.Issuer.String() == parent.Subject.String() {
			if child.CheckSignatureFrom(parent) == nil {
				return parent, true
			}
		}
	}
	return nil, false
}

func isSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.CheckSignatureFrom(cert) != nil {
		return false
	}
	// Fast path
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return true
	}
	// Fallback for rare DER encoding differences
	return cert.Issuer.String() == cert.Subject.String()
}

func handleVerifyError(err error, certPath, rootPath, usage string) {
	if looksLikeUnsupportedAlgoErr(err) {
		hasUnsupportedAlgo = true
	}
	if looksLikeInsecureAlgoErr(err) {
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
			logNormal("   Leaf Public Key: %s\n", certPublicKeySummary(targetLeaf))
		}
		logNormal("   Verify with OpenSSL to confirm the chain, then re-issue with a modern hash (SHA-256+):\n")
		logNormal("   $ openssl x509 -in %s -noout -text\n", certPath)
		if rootPath != "" {
			logNormal("   $ openssl verify -CAfile %s %s\n\n", rootPath, certPath)
		} else {
			logNormal("   $ openssl verify %s\n\n", certPath)
		}
	} else if strings.Contains(err.Error(), "authority") {
		logNormal("  (Tip: Ensure intermediates are provided or use -aia)\n")
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
	logNormal("ℹ️  Leaf Public Key: %s\n", certPublicKeySummary(cert))
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
			now.Sub(cert.NotAfter).Truncate(time.Second))
	} else if now.Before(cert.NotBefore) {
		logNormal("⚠️  WARNING: Certificate is NOT YET VALID (NotBefore: %s, starts in %s).\n",
			cert.NotBefore.Format(time.RFC3339),
			cert.NotBefore.Sub(now).Truncate(time.Second))
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
				remaining.Truncate(time.Minute), cert.NotAfter.Format(time.RFC3339))
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
func checkCRL(chains [][]*x509.Certificate, now time.Time) error {
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
				logNormal("⚠️  WARNING: Issuer '%s' does not have CRLSign usage. Skipping CRL check for this level.\n", cnOrDN(parent))
				continue
			}

			if len(child.CRLDistributionPoints) == 0 {
				logNormal("ℹ️  Skipping %s (No CDP defined)\n", cnOrDN(child))
				continue
			}

			// Pair dedupe (prevents duplicate checks across multiple verified chain paths)
			childFP := sha256.Sum256(child.Raw)
			parentFP := sha256.Sum256(parent.Raw)
			pairKey := hex.EncodeToString(childFP[:8]) + ":" + hex.EncodeToString(parentFP[:8])

			if checkedPair[pairKey] {
				logNormal("ℹ️  Skipping CRL re-check (already checked) for '%s' issued by '%s'\n", cnOrDN(child), cnOrDN(parent))
				continue
			}
			checkedPair[pairKey] = true

			validCRLFound := false
			var errMsgs []string

			for idx, cdpURL := range child.CRLDistributionPoints {
				if !strings.HasPrefix(cdpURL, "http://") && !strings.HasPrefix(cdpURL, "https://") {
					continue
				}

				var crl *x509.RevocationList
				if cached, ok := crlCache[cdpURL]; ok && cached.rl != nil {
					crl = cached.rl
					logNormal("ℹ️  Using cached CRL for '%s' [%d/%d]: %s\n", cnOrDN(child), idx+1, len(child.CRLDistributionPoints), cdpURL)
				} else {
					logNormal("⬇️  Fetching CRL for '%s' [%d/%d]: %s\n", cnOrDN(child), idx+1, len(child.CRLDistributionPoints), cdpURL)

					req, err := http.NewRequest("GET", cdpURL, nil)
					if err != nil {
						errMsgs = append(errMsgs, fmt.Sprintf("%s: bad request: %v", cdpURL, err))
						continue
					}
					req.Header.Set("User-Agent", "x509-cert-validator/1.0")

					resp, err := client.Do(req)
					if err != nil {
						errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", cdpURL, err))
						continue
					}

					if resp.StatusCode != 200 {
						_ = resp.Body.Close()
						errMsgs = append(errMsgs, fmt.Sprintf("%s: HTTP %d", cdpURL, resp.StatusCode))
						continue
					}

					data, err := readWithLimit(resp.Body, maxCRLDownloadBytes)
					_ = resp.Body.Close()
					if err != nil {
						errMsgs = append(errMsgs, fmt.Sprintf("%s: read failed (%v)", cdpURL, err))
						continue
					}

					parsed, err := parseRevocationListFromData(data)
					if err != nil {
						if looksLikeUnsupportedAlgoErr(err) {
							hasUnsupportedAlgo = true
						}
						if looksLikeInsecureAlgoErr(err) {
							hasInsecureAlgo = true
						}
						errMsgs = append(errMsgs, fmt.Sprintf("%s: parse failed", cdpURL))
						continue
					}
					crl = parsed
					crlCache[cdpURL] = crlCacheEntry{rl: parsed}
				}

				// Signature must validate against issuer
				if err := crl.CheckSignatureFrom(parent); err != nil {
					if looksLikeUnsupportedAlgoErr(err) {
						hasUnsupportedAlgo = true
					}
					if looksLikeInsecureAlgoErr(err) {
						hasInsecureAlgo = true
					}
					errMsgs = append(errMsgs, fmt.Sprintf("%s: invalid signature", cdpURL))
					continue
				}

				// Log key type/length used for CRL signature verification (requested).
				logNormal("   ℹ️  CRL Signature Verified: SigAlg=%s SignedByKey=%s Issuer=%s\n",
					crl.SignatureAlgorithm, certPublicKeySummary(parent), cnOrDN(parent))

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
							cnOrDN(child), child.SerialNumber.String(), cdpURL)
					}
				}

				logNormal("   ✅ Valid CRL checked via %s\n", cdpURL)
				// Do NOT break: another responding CDP might still report revoked.
			}

			if !validCRLFound {
				return fmt.Errorf("failed to check CRL for %s. Errors: %v", cnOrDN(child), errMsgs)
			}
		}
	}
	return nil
}

func fetchAIA(cert *x509.Certificate) (*x509.Certificate, error) {
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
			continue
		}
		logNormal("⬇️  Fetching Parent via AIA [%d/%d]: %s\n", i+1, len(cert.IssuingCertificateURL), u)

		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			logNormal("   ⚠️  Bad Request: %v\n", err)
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "x509-cert-validator/1.0")

		resp, err := client.Do(req)
		if err != nil {
			logNormal("   ⚠️  Connection Failed: %v\n", err)
			lastErr = err
			continue
		}

		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			logNormal("   ⚠️  HTTP Error: %d\n", resp.StatusCode)
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		}

		data, err := readWithLimit(resp.Body, maxAIADownloadBytes)
		_ = resp.Body.Close()
		if err != nil {
			logNormal("   ⚠️  Read Failed: %v\n", err)
			lastErr = err
			continue
		}

		fetchedCerts := parseCertsFromDataSafe(data)
		if len(fetchedCerts) > 0 {
			flagUnsupportedIfNeeded(fetchedCerts[0])
			return fetchedCerts[0], nil
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

func logNormal(format string, args ...interface{}) {
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
			sn = targetLeaf.SerialNumber.String()
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
			sn = targetLeaf.SerialNumber.String()
		}
		fmt.Printf("PASS [%s] Serial:%s\n", id, sn)
		os.Exit(0)
	}
	os.Exit(0)
}

func printShortID(role string, cert *x509.Certificate) {
	flagUnsupportedIfNeeded(cert)
	hash := sha256.Sum256(cert.Raw)
	logNormal("[%s] %s... (CN=%s, Key=%s)\n", role, hex.EncodeToString(hash[:])[:8], cert.Subject.CommonName, certPublicKeySummary(cert))
}

func printCertDetails(label string, cert *x509.Certificate) {
	flagUnsupportedIfNeeded(cert)
	logNormal("\n=== %s Certificate Details ===\n", label)
	logNormal("Subject:     %s\n", cert.Subject)
	logNormal("Issuer:      %s\n", cert.Issuer)
	logNormal("Fingerprint: %x\n", sha256.Sum256(cert.Raw))
	logNormal("Serial:      %s\n", cert.SerialNumber)
	logNormal("Validity:    %s to %s\n", cert.NotBefore, cert.NotAfter)

	// Requested: key type + length, plus signature algorithm
	logNormal("Public Key:  %s\n", certPublicKeySummary(cert))
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

func loadAll(input string) []*x509.Certificate {
	s := strings.ToLower(strings.TrimSpace(input))
	if strings.HasPrefix(s, "file://") {
		exitErr(fmt.Errorf("unsupported path scheme: file:// is not accepted (%s)", input))
	}

	if strings.HasPrefix(s, "https://") {
		return fetchRemoteCert(input)
	}
	if strings.HasPrefix(s, "http://") {
		return downloadCertFile(input)
	}
	return loadLocalFile(input)
}

func fetchRemoteCert(urlStr string) []*x509.Certificate {
	u, err := url.Parse(urlStr)
	if err != nil {
		exitErr(fmt.Errorf("invalid url: %v", err))
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "443")
	}
	logNormal("⬇️  Connecting to remote server: %s ...\n", host)

	cfg := &tls.Config{InsecureSkipVerify: true} // we validate ourselves via x509.Verify
	if sniOverride != "" {
		cfg.ServerName = sniOverride
		logNormal("ℹ️  Using SNI override: %s\n", sniOverride)
	}

	dialer := &net.Dialer{Timeout: DefaultTLSProbeTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, cfg)
	if err != nil {
		exitErr(fmt.Errorf("failed to connect to %s: %v", host, err))
	}
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

func downloadCertFile(urlStr string) []*x509.Certificate {
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

	req, err := http.NewRequest("GET", urlStr, nil)
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
				if looksLikeUnsupportedAlgoErr(err) {
					hasUnsupportedAlgo = true
				}
				if looksLikeInsecureAlgoErr(err) {
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
		if looksLikeUnsupportedAlgoErr(err) {
			hasUnsupportedAlgo = true
		}
		if looksLikeInsecureAlgoErr(err) {
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
				if looksLikeUnsupportedAlgoErr(err) {
					hasUnsupportedAlgo = true
				}
				if looksLikeInsecureAlgoErr(err) {
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
			if looksLikeUnsupportedAlgoErr(err) {
				hasUnsupportedAlgo = true
			}
			if looksLikeInsecureAlgoErr(err) {
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

	const w = 48
	border := "+--------------------------------------------------+"

	boxLine := func(s string) {
		fmt.Printf("| %-48s |\n", truncate(s, w))
	}

	fmt.Println()
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

		ncLines := buildNameConstraintLines(cert, w)

		fmt.Println(border)
		boxLine(role)
		boxLine("CN: " + subCN)
		boxLine("Issuer: " + issCN)
		boxLine("Key: " + certPublicKeySummary(cert))
		boxLine("Sig: " + cert.SignatureAlgorithm.String())

		for _, l := range ncLines {
			boxLine(l)
		}

		boxLine("SN: " + cert.SerialNumber.String())
		fmt.Println(border)

		if i > 0 {
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

func certPublicKeySummary(cert *x509.Certificate) string {
	if cert == nil {
		return "UNKNOWN"
	}
	return publicKeySummary(cert.PublicKey)
}

func publicKeySummary(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return "RSA-?"
		}
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil || k.Curve.Params() == nil {
			return "ECDSA-?"
		}
		name := k.Curve.Params().Name
		bits := k.Curve.Params().BitSize
		if name == "" && bits > 0 {
			return fmt.Sprintf("ECDSA-%d", bits)
		}
		if name != "" && bits > 0 {
			return fmt.Sprintf("ECDSA-%s(%d)", name, bits)
		}
		if name != "" {
			return fmt.Sprintf("ECDSA-%s", name)
		}
		return "ECDSA-?"
	case ed25519.PublicKey:
		return "Ed25519-256"
	case *dsa.PublicKey:
		if k == nil || k.P == nil {
			return "DSA-?"
		}
		return fmt.Sprintf("DSA-%d", k.P.BitLen())
	default:
		return fmt.Sprintf("Unknown(%T)", pub)
	}
}
