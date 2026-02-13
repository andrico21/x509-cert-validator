package main

import (
    "bytes"
    "crypto/sha256"
    "crypto/x509"
    "encoding/hex"
    "encoding/pem"
    "flag"
    "fmt"
    "io"
    "net/http"
    "os"
    "runtime"
    "strings"
    "time"
)

func main() {
    // --- CLI Arguments ---
    certPath := flag.String("cert", "", "Path to Certificate PEM (required)")
    rootPath := flag.String("root", "", "Path to Root CA PEM (optional; uses System Roots if empty)")
    dnsName := flag.String("dns", "", "Optional: Verify specific DNS name")
    atTime := flag.String("at", "", "Optional: Validate at RFC3339 time")
    enableCRL := flag.Bool("crl", false, "Enable CRL revocation checking")
    enableAIA := flag.Bool("aia", false, "Enable automatic AIA fetching")
    createBundlePath := flag.String("createCAbundle", "", "Optional: Path to create/export the discovered CA bundle")
    includeRoot := flag.Bool("includeRoot", false, "Include Root CA in the generated bundle")
    usage := flag.String("type", "any", "Validation type: server, client, or any")
    flag.Parse()

    if *certPath == "" {
        fmt.Println("Usage: go run validate.go -cert <cert.pem> [-root <root.pem>] [-aia] [-createCAbundle <path>] ...")
        os.Exit(1)
    }

    fmt.Printf("Runtime: %s\n", runtime.Version())

    // --- 1. Setup Validation Time ---
    currentTime := time.Now()
    if *atTime != "" {
        t, err := time.Parse(time.RFC3339, *atTime)
        if err != nil {
            exitErr(fmt.Errorf("invalid -at time: %v", err))
        }
        currentTime = t
    }
    fmt.Printf("Validation Time: %s\n", currentTime.Format(time.RFC3339))

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
    var rootCerts []*x509.Certificate // Keep track for export
    knownSubjects := make(map[string]bool)

    if *rootPath != "" {
        fmt.Println("--- Loading Roots (File) ---")
        roots = x509.NewCertPool()
        for _, cert := range loadAll(*rootPath) {
            printShortID("Root", cert)
            if !cert.IsCA {
                fmt.Printf("  ⚠️ WARNING: Root is NOT marked as CA\n")
            }
            roots.AddCert(cert)
            rootCerts = append(rootCerts, cert)
            knownSubjects[string(cert.RawSubject)] = true
        }
    } else {
        fmt.Println("--- Loading Roots (System) ---")
        var err error
        roots, err = x509.SystemCertPool()
        if err != nil {
            fmt.Printf("⚠️  Failed to load system roots: %v. Using empty pool.\n", err)
            roots = x509.NewCertPool()
        } else {
            fmt.Println("ℹ️  Loaded System Root Store.")
        }
    }

    // --- 4. Load Intermediates ---
    inters := x509.NewCertPool()
    var bundleCerts []*x509.Certificate // All intermediates (CLI + Fetched)

    if len(flag.Args()) > 0 {
        fmt.Println("\n--- Loading Intermediates (CLI) ---")
        for _, path := range flag.Args() {
            for _, cert := range loadAll(path) {
                printShortID("Inter", cert)
                if !cert.IsCA {
                    fmt.Printf("  ⚠️ WARNING: Intermediate is NOT marked as CA\n")
                }
                inters.AddCert(cert)
                bundleCerts = append(bundleCerts, cert)
                knownSubjects[string(cert.RawSubject)] = true
            }
        }
    }

    // --- 5. Load Target Cert ---
    targetCerts := loadAll(*certPath)
    leaf := targetCerts[0]

    printCertDetails("Target Certificate", leaf)
    highlightLeafIssues(leaf)

    // --- 6. AIA Fetching (Auto-Discovery) ---
    if *enableAIA {
        fmt.Println("\n=== Automatic AIA Fetching ===")

        currentCert := leaf
        chainDepth := 0
        maxDepth := 10

        for chainDepth < maxDepth {
            // 1. Check if Issuer is known
            if knownSubjects[string(currentCert.RawIssuer)] {
                fmt.Printf("ℹ️  Parent '%s' found locally (File/CLI). Stopping fetch.\n", currentCert.Issuer.CommonName)
                break
            }

            // 2. Check for Self-Signed
            if bytes.Equal(currentCert.RawIssuer, currentCert.RawSubject) {
                fmt.Println("ℹ️  Reached Self-Signed Root. Stopping fetch.")
                break
            }

            // 3. Check for AIA URL
            if len(currentCert.IssuingCertificateURL) == 0 {
                fmt.Println("ℹ️  No AIA URL found. Cannot fetch parent.")
                break
            }

            // 4. Fetch
            parentCert, err := fetchAIA(currentCert)
            if err != nil {
                fmt.Printf("⚠️  AIA Fetch failed: %v\n", err)
                break
            }

            // 5. Check if Root (Subject == Issuer)
            // If we didn't provide a root file, we might want to see if this fetched root matches system roots
            // But generally we don't add fetched roots to the "Intermediates" pool.
            if bytes.Equal(parentCert.RawIssuer, parentCert.RawSubject) {
                fmt.Printf("ℹ️  Fetched cert is Root CA (%s). Stopping fetch.\n", parentCert.Subject.CommonName)
                // If we are strictly exporting a bundle, we might want this if includeRoot is true?
                // For now, we follow standard practice: Don't treat fetched root as intermediate.
                if *includeRoot && *createBundlePath != "" && *rootPath == "" {
                    // Edge case: No root file provided, but we fetched a root via AIA.
                    // We add it to rootCerts for export purposes only.
                    rootCerts = append(rootCerts, parentCert)
                    fmt.Println("   (Added to export list as Root)")
                }
                break
            }

            // 6. Add to pools
            inters.AddCert(parentCert)
            bundleCerts = append(bundleCerts, parentCert) // Add to export list
            knownSubjects[string(parentCert.RawSubject)] = true

            fmt.Printf("✅ Added fetched certificate: %s\n", parentCert.Subject)

            currentCert = parentCert
            chainDepth++
        }
    }

    // --- 7. Create CA Bundle (Optional) ---
    if *createBundlePath != "" {
        fmt.Printf("\n=== Creating CA Bundle at %s ===\n", *createBundlePath)
        if len(bundleCerts) == 0 && (!*includeRoot || len(rootCerts) == 0) {
            fmt.Println("⚠️  No certificates available to bundle.")
        } else {
            f, err := os.Create(*createBundlePath)
            if err != nil {
                fmt.Printf("❌ Failed to create bundle file: %v\n", err)
            } else {
                count := 0
                // Write Intermediates (CLI + AIA)
                for _, cert := range bundleCerts {
                    if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
                        fmt.Printf("❌ Error writing cert: %v\n", err)
                    }
                    count++
                }

                // Write Roots (if requested)
                if *includeRoot {
                    if len(rootCerts) > 0 {
                        for _, root := range rootCerts {
                            if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}); err != nil {
                                fmt.Printf("❌ Error writing root: %v\n", err)
                            }
                            count++
                        }
                        fmt.Println("ℹ️  Included Root CA(s) in bundle.")
                    } else {
                        fmt.Println("⚠️  -includeRoot requested but no Root CA file provided or fetched.")
                    }
                }

                f.Close()
                fmt.Printf("✅ Successfully bundled %d certificates.\n", count)
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

    fmt.Println("\n=== Verifying Chain ===")
    chains, err := leaf.Verify(opts)
    if err != nil {
        fmt.Printf("❌ VALIDATION FAILED: %v\n", err)
        if strings.Contains(err.Error(), "authority") {
            fmt.Println("  (Tip: Ensure intermediates are provided or use -aia)")
        }
        // We do NOT exit here anymore if we just wanted to create a bundle.
        // But usually validation failure is the end of the road for the "test".
        // We'll exit with error code 1, but the bundle was already written above.
        os.Exit(1)
    }

    fmt.Println("✅ VALIDATION SUCCEEDED")

    for i, chain := range chains {
        fmt.Printf("\n--- Verified Chain Path %d ---\n", i+1)
        for depth, cert := range chain {
            prefix := strings.Repeat("  ", depth)
            fmt.Printf("%s[%d] Subject: %s\n", prefix, depth, cert.Subject)
            sum := sha256.Sum256(cert.Raw)
            fmt.Printf("%s    Fingerprint: %x\n", prefix, sum[:8])
        }
    }

    // --- 9. CRL Check ---
    if *enableCRL {
        fmt.Println("\n=== Checking CRLs ===")
        if err := checkCRL(chains, currentTime); err != nil {
            exitErr(fmt.Errorf("❌ CRL CHECK FAILED: %v", err))
        }
        fmt.Println("✅ CRL CHECK PASSED")
    }
}

// --- Helpers ---

func fetchAIA(cert *x509.Certificate) (*x509.Certificate, error) {
    client := &http.Client{Timeout: 5 * time.Second}
    var lastErr error

    for i, url := range cert.IssuingCertificateURL {
        if !strings.HasPrefix(url, "http") {
            continue
        }

        fmt.Printf("⬇️  Fetching Parent via AIA [%d/%d]: %s\n", i+1, len(cert.IssuingCertificateURL), url)

        resp, err := client.Get(url)
        if err != nil {
            fmt.Printf("   ⚠️  Connection Failed: %v\n", err)
            lastErr = err
            continue
        }

        data, err := io.ReadAll(resp.Body)
        resp.Body.Close()
        if err != nil {
            fmt.Printf("   ⚠️  Read Failed: %v\n", err)
            lastErr = err
            continue
        }

        if resp.StatusCode != 200 {
            fmt.Printf("   ⚠️  HTTP Error: %d\n", resp.StatusCode)
            lastErr = fmt.Errorf("status %d", resp.StatusCode)
            continue
        }

        fetchedCert, err := x509.ParseCertificate(data)
        if err == nil {
            return fetchedCert, nil
        }

        block, _ := pem.Decode(data)
        if block != nil && block.Type == "CERTIFICATE" {
            fetchedCert, err = x509.ParseCertificate(block.Bytes)
            if err == nil {
                return fetchedCert, nil
            }
        }

        fmt.Printf("   ⚠️  Parse Failed (tried DER and PEM)\n")
        lastErr = fmt.Errorf("unable to parse certificate data")
    }

    return nil, fmt.Errorf("all AIA URLs failed. Last error: %v", lastErr)
}

func printShortID(role string, cert *x509.Certificate) {
    hash := sha256.Sum256(cert.Raw)
    fmt.Printf("[%s] %s... (CN=%s)\n", role, hex.EncodeToString(hash[:])[:8], cert.Subject.CommonName)
}

func highlightLeafIssues(cert *x509.Certificate) {
    fmt.Println("\n=== Heuristic Analysis ===")

    switch cert.SignatureAlgorithm {
    case x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
        fmt.Printf("⚠️  WARNING: Weak signature algorithm: %v\n", cert.SignatureAlgorithm)
    }

    if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
        fmt.Println("⚠️  WARNING: Certificate has no SAN entries.")
    }

    if cert.BasicConstraintsValid && cert.IsCA {
        fmt.Println("⚠️  WARNING: Leaf appears to be a CA certificate (IsCA=true).")
    }
}

func checkCRL(chains [][]*x509.Certificate, now time.Time) error {
    client := &http.Client{Timeout: 5 * time.Second}

    for _, chain := range chains {
        for i := 0; i < len(chain)-1; i++ {
            child := chain[i]
            parent := chain[i+1]

            if len(child.CRLDistributionPoints) == 0 {
                fmt.Printf("ℹ️  Skipping %s (No CDP defined)\n", child.Subject.CommonName)
                continue
            }

            success := false
            var errMsgs []string

            for idx, url := range child.CRLDistributionPoints {
                if !strings.HasPrefix(url, "http") {
                    continue
                }

                fmt.Printf("⬇️  Fetching CRL for '%s' [%d/%d]: %s\n",
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
                fmt.Printf("   ✅ Valid CRL found via %s\n", url)
                break
            }

            if !success {
                return fmt.Errorf("failed to check CRL for %s. Errors: %v", child.Subject.CommonName, errMsgs)
            }
        }
    }
    return nil
}

func loadAll(path string) []*x509.Certificate {
    data, err := os.ReadFile(path)
    if err != nil {
        exitErr(fmt.Errorf("read error (%s): %v", path, err))
    }

    var certs []*x509.Certificate
    for {
        block, rest := pem.Decode(data)
        if block == nil {
            break
        }
        if block.Type == "CERTIFICATE" {
            cert, err := x509.ParseCertificate(block.Bytes)
            if err != nil {
                fmt.Printf("Skipping unparsable block in %s: %v\n", path, err)
            } else {
                certs = append(certs, cert)
            }
        }
        data = rest
    }
    if len(certs) == 0 {
        exitErr(fmt.Errorf("no certificates found in %s", path))
    }
    return certs
}

func printCertDetails(label string, cert *x509.Certificate) {
    fmt.Printf("\n=== %s Certificate Details ===\n", label)
    fmt.Printf("Subject:     %s\n", cert.Subject)
    fmt.Printf("Issuer:      %s\n", cert.Issuer)
    fmt.Printf("Fingerprint: %x\n", sha256.Sum256(cert.Raw))
    fmt.Printf("Serial:      %s\n", cert.SerialNumber)
    fmt.Printf("Validity:    %s to %s\n", cert.NotBefore, cert.NotAfter)
    if len(cert.DNSNames) > 0 {
        fmt.Printf("SAN (DNS):   %v\n", cert.DNSNames)
    }
    if len(cert.IssuingCertificateURL) > 0 {
        fmt.Printf("AIA (Issuer): %v\n", cert.IssuingCertificateURL)
    }
    if len(cert.CRLDistributionPoints) > 0 {
        fmt.Printf("CRL DPs:     %v\n", cert.CRLDistributionPoints)
    }
}

func exitErr(err error) {
    fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
    os.Exit(1)
}