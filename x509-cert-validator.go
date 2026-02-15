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
        verbosity          int
        targetLeaf         *x509.Certificate
        rootSourceLabel    string
        hasUnsupportedAlgo bool
)

func main() {
        // --- Usage ---
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
        enableCRL := flag.Bool("crl", false, "Enable certificate revocation checking")
        enableAIA := flag.Bool("aia", false, "Enable automatic AIA fetching")
        createBundlePath := flag.String("createCAbundle", "", "Optional: Path to create/export the discovered CA bundle")
        includeRoot := flag.Bool("includeRoot", false, "Include Root CA in the generated bundle")
        usage := flag.String("type", "any", "Validation type: server, client, or any")
        showGraph := flag.Bool("showGraph", false, "Display ASCII graph of the verified chain")
        silent := flag.Bool("silent", false, "Output only pass/fail status and cert ID")
        ultraSilent := flag.Bool("ultrasilent", false, "No output, exit code only (0=Pass, 1=Fail)")

        flag.Parse()

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
        // We use a pool list to check signatures later
        var poolList []*x509.Certificate
		
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
                        poolList = append(poolList, cert)
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
                                poolList = append(poolList, cert)
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
                        poolList = append(poolList, extra)
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
                        // Signature-based Check. Do we already have a valid issuer?
                        if findParentInList(currentCert, poolList) {
                                logNormal("ℹ️  Valid parent found locally. Stopping fetch.\n")
                                break
                        }

                        // Stronger Self-Signed Check
                        if isSelfSigned(currentCert) {
                                logNormal("ℹ️  Reached Self-Signed Root. Stopping fetch.\n")
                                break
                        }

                        if len(currentCert.IssuingCertificateURL) == 0 {
                                logNormal("ℹ️  No AIA URL found. Cannot fetch parent.\n")
                                break
                        }

                        // DoS Protection in Fetch
                        parentCert, err := fetchAIA(currentCert)
                        if err != nil {
                                logNormal("⚠️  AIA Fetch failed: %v\n", err)
                                break
                        }

                        // Re-check self-signed on fetched cert
                        if isSelfSigned(parentCert) {
                                logNormal("ℹ️  Fetched cert is Root CA (%s). Stopping fetch.\n", parentCert.Subject.CommonName)
                                if *includeRoot && *createBundlePath != "" && *rootPath == "" {
                                        rootCerts = append(rootCerts, parentCert)
                                        logNormal("   (Added to export list as Root)\n")
                                }
                                break
                        }

                        inters.AddCert(parentCert)
                        bundleCerts = append(bundleCerts, parentCert)
                        poolList = append(poolList, parentCert)
                        logNormal("✅ Added fetched certificate: %s\n", parentCert.Subject)

                        currentCert = parentCert
                        chainDepth++
                }
        }

        // --- 7. Create CA Bundle ---
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
                                // Deduplication Map
                                seen := make(map[string]bool)

                                writeCert := func(c *x509.Certificate) {
                                        fp := fmt.Sprintf("%x", sha256.Sum256(c.Raw))
                                        if seen[fp] {
                                                return
                                        }
                                        if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
                                                logNormal("❌ Error writing cert: %v\n", err)
                                        }
                                        seen[fp] = true
                                        count++
                                }

                                for _, cert := range bundleCerts {
                                        writeCert(cert)
                                }
                                if *includeRoot {
                                        for _, root := range rootCerts {
                                                writeCert(root)
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
                handleVerifyError(err, *certPath, *rootPath, *usage)
        }

        logNormal("✅ VALIDATION SUCCEEDED\n")

        for i, chain := range chains {
                logNormal("\n--- Verified Chain Path %d ---\n", i+1)
                if *showGraph {
                        printChainGraph(chain)
                } else {
                        for depth, cert := range chain {
                                prefix := strings.Repeat("  ", depth)
                                logNormal("%s[%d] Subject: %s\n", prefix, depth, cert.Subject)
                                sum := sha256.Sum256(cert.Raw)
                                logNormal("%s    Fingerprint: %x\n", prefix, sum[:8])
                        }
                }
        }

        // --- 9. CRL Check (Strict) ---
        if *enableCRL {
                logNormal("\n=== Checking CRLs ===\n")
                if err := checkCRL(chains, currentTime); err != nil {
                        exitErr(fmt.Errorf("CRL CHECK FAILED: %v", err))
                }
                logNormal("✅ CRL CHECK PASSED\n")
        }

        exitSuccess()
}

// --- Helpers ---

func findParentInList(child *x509.Certificate, pool []*x509.Certificate) bool {
        for _, parent := range pool {
                // Optimization: Check Subject/Issuer match first
                if bytes.Equal(child.RawIssuer, parent.RawSubject) {
                        // Strong Check: Verify Signature
                        if child.CheckSignatureFrom(parent) == nil {
                                return true
                        }
                }
        }
        return false
}

func isSelfSigned(cert *x509.Certificate) bool {
        if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
                return false
        }
        return cert.CheckSignatureFrom(cert) == nil
}

func handleVerifyError(err error, certPath, rootPath, usage string) {
        if hasUnsupportedAlgo {
                logNormal("\n⚠️  CRITICAL HINT: This certificate uses an algorithm unsupported by Go (e.g., GOST).\n")
                logNormal("   Please try verifying with OpenSSL directly:\n")
                logNormal("   $ openssl x509 -in %s -noout -text\n", certPath)
                if rootPath != "" {
                        logNormal("   $ openssl verify -CAfile %s %s\n\n", rootPath, certPath)
                } else {
                        logNormal("   $ openssl verify %s\n\n", certPath)
                }
        } else if strings.Contains(err.Error(), "authority") {
                logNormal("  (Tip: Ensure intermediates are provided or use -aia)\n")
        } else if strings.Contains(err.Error(), "KeyUsage") {
                logNormal("  (Tip: Check if the certificate is valid for the requested type: %s)\n", usage)
        }
        exitErr(fmt.Errorf("VALIDATION FAILED: %v", err))
}

func highlightLeafIssues(cert *x509.Certificate) {
        logNormal("\n=== Heuristic Analysis ===\n")
        if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
                hasUnsupportedAlgo = true
                logNormal("⚠️  WARNING: Signature Algorithm is UNKNOWN/UNSUPPORTED (Possible GOST).\n")
        }
        if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
                hasUnsupportedAlgo = true
                logNormal("⚠️  WARNING: Public Key Algorithm is UNKNOWN.\n")
        }
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

                        // FIX 5: Ensure Parent can Sign CRLs
                        if (parent.KeyUsage & x509.KeyUsageCRLSign) == 0 {
                                logNormal("⚠️  WARNING: Issuer '%s' does not have CRLSign usage. Skipping CRL check for this level.\n", parent.Subject.CommonName)
                                continue
                        }

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
                                logNormal("⬇️  Fetching CRL for '%s' [%d/%d]: %s\n", child.Subject.CommonName, idx+1, len(child.CRLDistributionPoints), url)

                                resp, err := client.Get(url)
                                if err != nil {
                                        errMsgs = append(errMsgs, fmt.Sprintf("%s: %v", url, err))
                                        continue
                                }

                                // Limit CRL size as well (e.g. 10MB to be safe for large CRLs)
                                data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
                                resp.Body.Close()
                                if err != nil {
                                        errMsgs = append(errMsgs, fmt.Sprintf("%s: read failed", url))
                                        continue
                                }

                                // FIX 4: Use ParseRevocationList (Modern)
                                crl, err := x509.ParseRevocationList(data)
                                if err != nil {
                                        errMsgs = append(errMsgs, fmt.Sprintf("%s: parse failed", url))
                                        continue
                                }

                                if err := crl.CheckSignatureFrom(parent); err != nil {
                                        errMsgs = append(errMsgs, fmt.Sprintf("%s: invalid signature", url))
                                        continue
                                }

                                if now.Before(crl.ThisUpdate) || now.After(crl.NextUpdate) {
                                        errMsgs = append(errMsgs, fmt.Sprintf("%s: CRL expired or future", url))
                                        continue
                                }

                                for _, revoked := range crl.RevokedCertificateEntries {
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

                // FIX 3: DoS Protection on AIA
                const AIAMaxSize = 5 * 1024 * 1024 // 5MB
                data, err := io.ReadAll(io.LimitReader(resp.Body, AIAMaxSize))
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

// ... (Rest of helpers: printCertDetails, etc. unchanged from previous working blocks)

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
        hash := sha256.Sum256(cert.Raw)
        logNormal("[%s] %s... (CN=%s)\n", role, hex.EncodeToString(hash[:])[:8], cert.Subject.CommonName)
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
        u, err := url.Parse(urlStr)
        if err != nil {
                exitErr(fmt.Errorf("invalid url: %v", err))
        }
        if u.Scheme != "http" && u.Scheme != "https" {
                exitErr(fmt.Errorf("unsupported protocol scheme: %s", u.Scheme))
        }
        logNormal("⬇️  Downloading certificate file: %s ...\n", urlStr)
        client := &http.Client{
                Timeout: 10 * time.Second,
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        if len(via) >= 3 {
                                return fmt.Errorf("stopped after 3 redirects")
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

        const MaxSize = 0.5 * 1024 * 1024 // 0.5 MB
        data, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize))
        if err != nil {
                exitErr(fmt.Errorf("read failed: %v", err))
        }
        if int64(len(data)) == MaxSize {
                logNormal("⚠️  WARNING: File reached size limit (%d bytes). It may be truncated.\n", MaxSize)
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
                                logNormal("Skipping unparsable block in %s: %v\n", source, err)
                        } else {
                                certs = append(certs, c)
                        }
                }
        }
        if len(certs) == 0 {
                c, err := x509.ParseCertificate(data)
                if err == nil {
                        return []*x509.Certificate{c}
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
                                certs = append(certs, c)
                        }
                }
        }
        if len(certs) == 0 {
                c, err := x509.ParseCertificate(data)
                if err == nil {
                        certs = append(certs, c)
                }
        }
        return certs
}

func printChainGraph(chain []*x509.Certificate) {
        if verbosity == LevelUltraSilent {
                return
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
                fmt.Printf("+--------------------------------------------------+\n")
                fmt.Printf("| %-48s |\n", role)
                fmt.Printf("| CN: %-44s |\n", truncate(cert.Subject.CommonName, 44))
                fmt.Printf("| SN: %-44s |\n", truncate(cert.SerialNumber.String(), 44))
                fmt.Printf("+--------------------------------------------------+\n")
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