package main

import (
	"bytes"
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

var (
	verbosity       int
	targetLeaf      *x509.Certificate // Global reference for error reporting
	rootSourceLabel string            // Tracks where the Root Trust came from (System vs File)
)

func main() {
	// --- Custom Usage / Help Section ---
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nEXAMPLES:")
		fmt.Fprintln(os.Stderr, "  1. Live HTTPS Probe (Check server's current chain):")
		fmt.Fprintln(os.Stderr, "     cert-validate -cert https://github.com")

		fmt.Fprintln(os.Stderr, "\n  2. Validate a Remote Certificate File (e.g., from an AIA URL):")
		fmt.Fprintln(os.Stderr, "     cert-validate -cert http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt")

		fmt.Fprintln(os.Stderr, "\n  3. Validation with Specific Constraints (-dns, -at, -type, -crl):")
		fmt.Fprintln(os.Stderr, "     cert-validate -cert leaf.pem -dns example.com -at \"2025-12-25T12:00:00Z\"")
		fmt.Fprintln(os.Stderr, "     cert-validate -cert client-cert.pem -type client")
		fmt.Fprintln(os.Stderr, "     cert-validate -cert leaf.pem -crl")

		fmt.Fprintln(os.Stderr, "\n  4. Fix Local Chain & Export Bundle:")
		fmt.Fprintln(os.Stderr, "     cert-validate -cert leaf.pem -aia -createCAbundle full-chain.crt")

		fmt.Fprintln(os.Stderr, "\n  5. Exporting Root CA (-includeRoot):")
		fmt.Fprintln(os.Stderr, "     cert-validate -cert leaf.pem -aia -createCAbundle bundle.crt -includeRoot")
		fmt.Fprintln(os.Stderr, "     (⚠️  SECURITY WARNING: This also exports the Root CA certificate.)")
		fmt.Fprintln(os.Stderr, "     (    Never install an unknown Root CA unless you know what you are doing)")
		fmt.Fprintln(os.Stderr, "     (    and have verified its fingerprint manually.)")
		fmt.Fprintln(os.Stderr, "     (    Trusting a malicious Root might lead to interception of your private data.)")

		fmt.Fprintln(os.Stderr, "\n  6. Visualization:")
		fmt.Fprintln(os.Stderr, "     cert-validate -cert leaf.pem -showGraph")

		fmt.Fprintln(os.Stderr, "\n  7. Silent Mode (Short status line only):")
		fmt.Fprintln(os.Stderr, "     cert-validate -cert leaf.pem -silent")
		fmt.Fprintln(os.Stderr, "     > PASS [github.com] Serial:12345...")

		fmt.Fprintln(os.Stderr, "\n  8. Ultra Silent (Exit code only):")
		fmt.Fprintln(os.Stderr, "     cert-validate -cert leaf.pem -ultrasilent")
		fmt.Fprintln(os.Stderr, "     (echo $?)")
	}

	// --- CLI Arguments ---
	certPath := flag.String("cert", "", "Path to Certificate PEM, HTTP URL (download), or HTTPS URL (live probe)")
	rootPath := flag.String("root", "", "Path to Root CA PEM (optional; uses System Roots if empty)")
	dnsName := flag.String("dns", "", "Optional: Verify specific DNS name")
	atTime := flag.String("at", "", "Optional: Validate at RFC3339 time")
	enableCRL := flag.Bool("crl", false, "Enable CRL revocation checking")
	enableAIA := flag.Bool("aia", false, "Enable automatic AIA fetching")
	createBundlePath := flag.String("createCAbundle", "", "Optional: Path to create/export the discovered CA bundle")
	includeRoot := flag.Bool("includeRoot", false, "Include Root CA in the generated bundle")
	usage := flag.String("type", "any", "Validation type: server, client, or any")
	showGraph := flag.Bool("showGraph", false, "Display ASCII graph of the verified chain")

	silent := flag.Bool("silent", false, "Output only pass/fail status and cert ID")
	ultraSilent := flag.Bool("ultrasilent", false, "No output, exit code only (0=Pass, 1=Fail)")

	flag.Parse()

	// --- Determine Verbosity ---
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

	// --- 3. Load Roots (File or System) ---
	var roots *x509.CertPool
	var rootCerts []*x509.Certificate
	knownSubjects := make(map[string]bool)

	if *rootPath != "" {
		// User provided explicit roots
		rootSourceLabel = "Explicit User File"
		logNormal("--- Loading Roots (File) ---\n")
		roots = x509.NewCertPool()
		for _, cert := range loadAll(*rootPath) {
			printShortID("Root", cert)
			if !cert.IsCA {
				logNormal("  ⚠️ WARNING: Root is NOT marked as CA\n")
			}
			roots.AddCert(cert)
			rootCerts = append(rootCerts, cert)
			knownSubjects[string(cert.RawSubject)] = true
		}
	} else {
		// User defaulted to system roots
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

	// --- 4. Load Intermediates ---
	inters := x509.NewCertPool()
	var bundleCerts []*x509.Certificate

	if len(flag.Args()) > 0 {
		logNormal("\n--- Loading Intermediates (CLI) ---\n")
		for _, path := range flag.Args() {
			for _, cert := range loadAll(path) {
				printShortID("Inter", cert)
				if !cert.IsCA {
					logNormal("  ⚠️ WARNING: Intermediate is NOT marked as CA\n")
				}
				inters.AddCert(cert)
				bundleCerts = append(bundleCerts, cert)
				knownSubjects[string(cert.RawSubject)] = true
			}
		}
	}

	// --- 5. Load Target Cert (File, HTTP, or HTTPS) ---
	targetCerts := loadAll(*certPath)
	leaf := targetCerts[0]
	targetLeaf = leaf // Set global context for error reporting

	// If using HTTPS probe, we might get the full chain from the server.
	if len(targetCerts) > 1 {
		logNormal("\nℹ️  Target URL returned %d certificates. Treating [1..n] as intermediates.\n", len(targetCerts))
		for i := 1; i < len(targetCerts); i++ {
			extra := targetCerts[i]
			printShortID("Server-Sent", extra)
			inters.AddCert(extra)
			bundleCerts = append(bundleCerts, extra)
			knownSubjects[string(extra.RawSubject)] = true
		}
	}

	printCertDetails("Target Certificate", leaf)
	highlightLeafIssues(leaf)

	// --- 6. AIA Fetching (Auto-Discovery) ---
	if *enableAIA {
		logNormal("\n=== Automatic AIA Fetching ===\n")

		currentCert := leaf
		chainDepth := 0
		maxDepth := 10

		for chainDepth < maxDepth {
			if knownSubjects[string(currentCert.RawIssuer)] {
				logNormal("ℹ️  Parent '%s' found locally (File/CLI/Server). Stopping fetch.\n", currentCert.Issuer.CommonName)
				break
			}

			if bytes.Equal(currentCert.RawIssuer, currentCert.RawSubject) {
				logNormal("ℹ️  Reached Self-Signed Root. Stopping fetch.\n")
				break
			}

			if len(currentCert.IssuingCertificateURL) == 0 {
				logNormal("ℹ️  No AIA URL found. Cannot fetch parent.\n")
				break
			}

			parentCert, err := fetchAIA(currentCert)
			if err != nil {
				logNormal("⚠️  AIA Fetch failed: %v\n", err)
				break
			}

			if bytes.Equal(parentCert.RawIssuer, parentCert.RawSubject) {
				logNormal("ℹ️  Fetched cert is Root CA (%s). Stopping fetch.\n", parentCert.Subject.CommonName)
				if *includeRoot && *createBundlePath != "" && *rootPath == "" {
					rootCerts = append(rootCerts, parentCert)
					logNormal("   (Added to export list as Root)\n")
				}
				break
			}

			inters.AddCert(parentCert)
			bundleCerts = append(bundleCerts, parentCert)
			knownSubjects[string(parentCert.RawSubject)] = true

			logNormal("✅ Added fetched certificate: %s\n", parentCert.Subject)

			currentCert = parentCert
			chainDepth++
		}
	}

	// --- 7. Create CA Bundle (Optional) ---
	if *createBundlePath != "" {
		logNormal("\n=== Creating CA Bundle at %s ===\n", *createBundlePath)
		if len(bundleCerts) == 0 && (!*includeRoot || len(rootCerts) == 0) {
			logNormal("⚠️  No certificates available to bundle.\n")
		} else {
			f, err := os.Create(*createBundlePath)
			if err != nil {
				logNormal("❌ Failed to create bundle file: %v\n", err)
			} else {
				count := 0
				for _, cert := range bundleCerts {
					if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
						logNormal("❌ Error writing cert: %v\n", err)
					}
					count++
				}
				if *includeRoot {
					for _, root := range rootCerts {
						if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}); err != nil {
							logNormal("❌ Error writing root: %v\n", err)
						}
						count++
					}
					logNormal("ℹ️  Included Root CA(s) in bundle.\n")
				}
				f.Close()
				logNormal("✅ Successfully bundled %d certificates.\n", count)
			}
		}
	}

	// --- 8. Verify Chain ---
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		DNSName:       *dnsName,
		CurrentTime:   currentTime,
		KeyUsages:     keyUsages,
	}

	logNormal("\n=== Verifying Chain ===\n")
	chains, err := leaf.Verify(opts)
	if err != nil {
		if strings.Contains(err.Error(), "authority") {
			logNormal("  (Tip: Ensure intermediates are provided or use -aia)\n")
		}
		exitErr(fmt.Errorf("VALIDATION FAILED: %v", err))
	}

	logNormal("✅ VALIDATION SUCCEEDED\n")

	for i, chain := range chains {
		logNormal("\n--- Verified Chain Path %d ---\n", i+1)
		
		if *showGraph {
			printChainGraph(chain)
		} else {
			// Standard output
			for depth, cert := range chain {
				prefix := strings.Repeat("  ", depth)
				logNormal("%s[%d] Subject: %s\n", prefix, depth, cert.Subject)
				sum := sha256.Sum256(cert.Raw)
				logNormal("%s    Fingerprint: %x\n", prefix, sum[:8])
			}
		}
	}

	// --- 9. CRL Check ---
	if *enableCRL {
		logNormal("\n=== Checking CRLs ===\n")
		if err := checkCRL(chains, currentTime); err != nil {
			exitErr(fmt.Errorf("CRL CHECK FAILED: %v", err))
		}
		logNormal("✅ CRL CHECK PASSED\n")
	}

	exitSuccess()
}

// --- Output Helpers ---

func logNormal(format string, args ...interface{}) {
	if verbosity == LevelNormal {
		fmt.Printf(format, args...)
	}
}

func printChainGraph(chain []*x509.Certificate) {
	// Suppress graph ONLY if UltraSilent. 
	// If Silent (Level 1) or Normal (Level 0), show it if requested.
	if verbosity == LevelUltraSilent {
		return
	}
	fmt.Println()
	// Chain comes as [Leaf, Inter, Root]. We want to print Root -> Leaf.
	for i := len(chain) - 1; i >= 0; i-- {
		cert := chain[i]
		
		// Determine role and status
		role := "INTERMEDIATE"
		if i == len(chain)-1 { role = "ROOT ANCHOR" }
		if i == 0 { role = "TARGET LEAF" }

		// Dynamic Width Box
		boxWidth := 50
		lineChar := "-"
		
		// Print Top Border
		fmt.Printf("+%s+\n", strings.Repeat(lineChar, boxWidth))
		
		// Print Content
		fmt.Printf("| %-48s |\n", role)
		fmt.Printf("| CN: %-44s |\n", truncate(cert.Subject.CommonName, 44))
		
		// Extra info based on role
		if i == len(chain)-1 {
			// Use the global label we determined in main()
			fmt.Printf("| ✅ TRUSTED (%-30s) |\n", rootSourceLabel)
		} else {
			fmt.Printf("| 📅 Exp: %-39s |\n", cert.NotAfter.Format("2006-01-02"))
		}
		
		// Serial (Short)
		serial := cert.SerialNumber.String()
		if len(serial) > 16 { serial = serial[:16] + "..." }
		fmt.Printf("| SN: %-44s |\n", serial)

		// Print Bottom Border
		fmt.Printf("+%s+\n", strings.Repeat(lineChar, boxWidth))

		// Draw Arrow (if not the last one)
		if i > 0 {
			fmt.Println("      |")
			fmt.Println("      | [Signed by above]")
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

func exitErr(err error) {
	if verbosity == LevelUltraSilent {
		os.Exit(1)
	}

	if verbosity == LevelSilent {
		// Concise Error: FAIL [CN] Serial:<SN>: Error
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

	// Normal
	fmt.Fprintf(os.Stderr, "❌ ERROR: %v\n", err)
	os.Exit(1)
}

func exitSuccess() {
	if verbosity == LevelUltraSilent {
		os.Exit(0)
	}

	if verbosity == LevelSilent {
		// Concise Success: PASS [CN] Serial:<SN>
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
	
	// Normal mode falls through to natural exit
	os.Exit(0)
}

// --- Loading Helpers ---

func loadAll(input string) []*x509.Certificate {
	if strings.HasPrefix(input, "https://") {
		return fetchRemoteCert(input)
	}
	if strings.HasPrefix(input, "http://") {
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

	conn, err := tls.Dial("tcp", host, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		exitErr(fmt.Errorf("failed to connect to %s: %v", host, err))
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		exitErr(fmt.Errorf("no certificates presented by %s", host))
	}

	logNormal("✅ Retrieved %d certificates from server.\n", len(state.PeerCertificates))
	return state.PeerCertificates
}

func downloadCertFile(urlStr string) []*x509.Certificate {
	logNormal("⬇️  Downloading certificate file: %s ...\n", urlStr)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		exitErr(fmt.Errorf("download failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		exitErr(fmt.Errorf("download failed with status: %d", resp.StatusCode))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		exitErr(fmt.Errorf("read failed: %v", err))
	}

	return parseCertsFromData(data, urlStr)
}

func loadLocalFile(path string) []*x509.Certificate {
	data, err := os.ReadFile(path)
	if err != nil {
		exitErr(fmt.Errorf("read error (%s): %v", path, err))
	}
	return parseCertsFromData(data, path)
}

func parseCertsFromData(data []byte, source string) []*x509.Certificate {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				logNormal("Skipping unparsable block in %s: %v\n", source, err)
			} else {
				certs = append(certs, cert)
			}
		}
		data = rest
	}
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			return []*x509.Certificate{cert}
		}
		exitErr(fmt.Errorf("no certificates found in %s", source))
	}
	return certs
}

func fetchAIA(cert *x509.Certificate) (*x509.Certificate, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error

	for i, url := range cert.IssuingCertificateURL {
		if !strings.HasPrefix(url, "http") {
			continue
		}

		logNormal("⬇️  Fetching Parent via AIA [%d/%d]: %s\n", i+1, len(cert.IssuingCertificateURL), url)

		resp, err := client.Get(url)
		if err != nil {
			logNormal("   ⚠️  Connection Failed: %v\n", err)
			lastErr = err
			continue
		}

		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			logNormal("   ⚠️  Read Failed: %v\n", err)
			lastErr = err
			continue
		}

		if resp.StatusCode != 200 {
			logNormal("   ⚠️  HTTP Error: %d\n", resp.StatusCode)
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		}

		fetchedCerts := parseCertsFromDataSafe(data)
		if len(fetchedCerts) > 0 {
			return fetchedCerts[0], nil
		}
		
		logNormal("   ⚠️  Parse Failed\n")
		lastErr = fmt.Errorf("unable to parse certificate data")
	}

	return nil, fmt.Errorf("all AIA URLs failed. Last error: %v", lastErr)
}

func parseCertsFromDataSafe(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	blockData := data
	for {
		block, rest := pem.Decode(blockData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, c)
			}
		}
		blockData = rest
	}
	if len(certs) == 0 {
		c, err := x509.ParseCertificate(data)
		if err == nil {
			certs = append(certs, c)
		}
	}
	return certs
}

func printShortID(role string, cert *x509.Certificate) {
	hash := sha256.Sum256(cert.Raw)
	logNormal("[%s] %s... (CN=%s)\n", role, hex.EncodeToString(hash[:])[:8], cert.Subject.CommonName)
}

func highlightLeafIssues(cert *x509.Certificate) {
	logNormal("\n=== Heuristic Analysis ===\n")

	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		logNormal("⚠️  WARNING: Weak signature algorithm: %v\n", cert.SignatureAlgorithm)
	}

	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
		logNormal("⚠️  WARNING: Certificate has no SAN entries.\n")
	}

	if cert.BasicConstraintsValid && cert.IsCA {
		logNormal("⚠️  WARNING: Leaf appears to be a CA certificate (IsCA=true).\n")
	}
}

func checkCRL(chains [][]*x509.Certificate, now time.Time) error {
	client := &http.Client{Timeout: 5 * time.Second}

	for _, chain := range chains {
		for i := 0; i < len(chain)-1; i++ {
			child := chain[i]
			parent := chain[i+1]

			if len(child.CRLDistributionPoints) == 0 {
				logNormal("ℹ️  Skipping %s (No CDP defined)\n", child.Subject.CommonName)
				continue
			}

			success := false
			var errMsgs []string

			for idx, url := range child.CRLDistributionPoints {
				if !strings.HasPrefix(url, "http") {
					continue
				}

				logNormal("⬇️  Fetching CRL for '%s' [%d/%d]: %s\n",
					child.Subject.CommonName, idx+1, len(child.CRLDistributionPoints), url)

				resp, err := client.Get(url)
				if err != nil {
					errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", url, err))
					continue
				}

				data, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					errMsgs = append(errMsgs, fmt.Sprintf("%s: read failed", url))
					continue
				}

				crl, err := x509.ParseCRL(data)
				if err != nil {
					errMsgs = append(errMsgs, fmt.Sprintf("%s: parse failed", url))
					continue
				}

				if err := parent.CheckCRLSignature(crl); err != nil {
					errMsgs = append(errMsgs, fmt.Sprintf("%s: invalid signature", url))
					continue
				}

				if now.Before(crl.TBSCertList.ThisUpdate) || now.After(crl.TBSCertList.NextUpdate) {
					errMsgs = append(errMsgs, fmt.Sprintf("%s: CRL expired or future", url))
					continue
				}

				for _, revoked := range crl.TBSCertList.RevokedCertificates {
					if child.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
						return fmt.Errorf("certificate %s is REVOKED", child.Subject)
					}
				}

				success = true
				logNormal("   ✅ Valid CRL found via %s\n", url)
				break
			}

			if !success {
				return fmt.Errorf("failed to check CRL for %s. Errors: %v", child.Subject.CommonName, errMsgs)
			}
		}
	}
	return nil
}

func printCertDetails(label string, cert *x509.Certificate) {
	logNormal("\n=== %s Certificate Details ===\n", label)
	logNormal("Subject:     %s\n", cert.Subject)
	logNormal("Issuer:      %s\n", cert.Issuer)
	logNormal("Fingerprint: %x\n", sha256.Sum256(cert.Raw))
	logNormal("Serial:      %s\n", cert.SerialNumber)
	logNormal("Validity:    %s to %s\n", cert.NotBefore, cert.NotAfter)
	if len(cert.DNSNames) > 0 {
		logNormal("SAN (DNS):   %v\n", cert.DNSNames)
	}
	if len(cert.IssuingCertificateURL) > 0 {
		logNormal("AIA (Issuer): %v\n", cert.IssuingCertificateURL)
	}
	if len(cert.CRLDistributionPoints) > 0 {
		logNormal("CRL DPs:     %v\n", cert.CRLDistributionPoints)
	}
}