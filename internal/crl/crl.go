// Package crl implements RFC 5280 §5 Certificate Revocation List
// checking against the CRLDistributionPoints extension on each
// non-self-signed certificate in a verified chain.
//
// The Checker type wraps a configurable *http.Client, a Logger for
// progress diagnostics, and per-fetch byte/time caps. Each call to
// Check walks every (child, parent) pair across the supplied chains,
// downloads + parses + verifies CRLs, and reports a strict pass/fail
// outcome together with any algorithm-rejection flags surfaced during
// parsing or signature verification.
//
// Policy (preserved verbatim from the legacy in-main implementation):
//   - PEM and DER inputs are both supported (delegated to x509util).
//   - Per (child, parent) pair: at least one CDP must respond with a
//     VALID CRL or the pair is treated as a hard failure for -crl.
//   - Multiple responding CRLs: if ANY indicates revoked => fail.
//   - Missing ThisUpdate/NextUpdate => warning AND treated as invalid.
//   - Parent must carry KeyUsageCRLSign or the level is skipped with a
//     warning (no failure).
//   - H-2: CRL Issuer DN must match parent CA Subject DN before the
//     signature check; mismatch is logged and treated as invalid.
//   - M-2: non-http(s) CDP URLs are surfaced as warnings and skipped.
//   - Pair dedupe across chain paths uses full SHA-256(child.Raw) +
//     SHA-256(parent.Raw) to avoid collision risk on truncated keys.
//   - URL-keyed cache avoids repeated downloads across chains.
package crl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/andrico21/x509-cert-validator/internal/certload"
	"github.com/andrico21/x509-cert-validator/internal/errs"
	"github.com/andrico21/x509-cert-validator/internal/validator"
	"github.com/andrico21/x509-cert-validator/internal/x509util"
)

// DefaultPerFetchTimeout is applied to each individual CRL HTTP request
// when Checker.PerFetchTimeout is zero.
const DefaultPerFetchTimeout = 10 * time.Second

// Checker performs CRL revocation checking. Construct with NewChecker;
// reuse across a single validation run so the URL-keyed CRL cache and
// the underlying *http.Client connection pool benefit accrue.
type Checker struct {
	Client          *http.Client     // required; supplies CheckRedirect + connection pool
	Logger          validator.Logger // optional; nil disables progress output
	MaxBytes        int64            // per-fetch download cap; <=0 means unlimited (NOT recommended)
	PerFetchTimeout time.Duration    // applied per URL; zero means DefaultPerFetchTimeout
}

// NewChecker constructs a Checker with the supplied dependencies.
func NewChecker(client *http.Client, logger validator.Logger, maxBytes int64) *Checker {
	return &Checker{Client: client, Logger: logger, MaxBytes: maxBytes}
}

// CheckResult bundles algorithm-rejection findings discovered during
// CRL parsing or signature verification. Callers OR the flags into
// their run-scoped state.
//
// A non-nil error from Check means the run MUST fail-the error message
// is operator-facing and includes either the revocation evidence or the
// per-CDP failure list for the offending (child, parent) pair.
type CheckResult struct {
	HasUnsupportedAlgo bool
	HasInsecureAlgo    bool
}

type cacheEntry struct {
	rl *x509.RevocationList
}

// Check evaluates every chain in chains against the revocation status
// surface declared by each non-leaf certificate's CRLDistributionPoints
// extension. Returns nil error iff every (child, parent) pair either
// (a) had no CDPs, (b) had a parent without CRLSign usage, or (c)
// surfaced at least one VALID, non-revoking CRL.
func (c *Checker) Check(ctx context.Context, chains [][]*x509.Certificate, now time.Time) (CheckResult, error) {
	var res CheckResult

	timeout := c.PerFetchTimeout
	if timeout <= 0 {
		timeout = DefaultPerFetchTimeout
	}

	// Cache CRLs by URL (avoids repeated downloads across chains)
	crlCache := make(map[string]cacheEntry)

	// Dedupe per unique (child cert, parent cert) pair across all chain paths
	checkedPair := make(map[string]bool)

	for _, chain := range chains {
		for i := 0; i < len(chain)-1; i++ {
			child := chain[i]
			parent := chain[i+1]

			// Ensure Parent can Sign CRLs
			if (parent.KeyUsage & x509.KeyUsageCRLSign) == 0 {
				c.log("⚠️  WARNING: Issuer '%s' does not have CRLSign usage. Skipping CRL check for this level.\n", x509util.CnOrDN(parent))
				continue
			}

			if len(child.CRLDistributionPoints) == 0 {
				c.log("ℹ️  Skipping %s (No CDP defined)\n", x509util.CnOrDN(child))
				continue
			}

			// Pair dedupe (prevents duplicate checks across multiple verified chain paths)
			// Use full SHA-256 to avoid collision risk on truncated keys.
			childFP := sha256.Sum256(child.Raw)
			parentFP := sha256.Sum256(parent.Raw)
			pairKey := hex.EncodeToString(childFP[:]) + ":" + hex.EncodeToString(parentFP[:])

			if checkedPair[pairKey] {
				c.log("ℹ️  Skipping CRL re-check (already checked) for '%s' issued by '%s'\n", x509util.CnOrDN(child), x509util.CnOrDN(parent))
				continue
			}
			checkedPair[pairKey] = true

			validCRLFound := false
			var errMsgs []string

			for idx, cdpURL := range child.CRLDistributionPoints {
				if !strings.HasPrefix(cdpURL, "http://") && !strings.HasPrefix(cdpURL, "https://") {
					// M-2: surface skipped non-http(s) CRL URLs.
					c.log("⚠️  Skipping CRL URL with unsupported scheme [%d/%d] for '%s': %s\n", idx+1, len(child.CRLDistributionPoints), x509util.CnOrDN(child), cdpURL)
					continue
				}

				var rl *x509.RevocationList
				if cached, ok := crlCache[cdpURL]; ok && cached.rl != nil {
					rl = cached.rl
					c.log("ℹ️  Using cached CRL for '%s' [%d/%d]: %s\n", x509util.CnOrDN(child), idx+1, len(child.CRLDistributionPoints), cdpURL)
				} else {
					c.log("⬇️  Fetching CRL for '%s' [%d/%d]: %s\n", x509util.CnOrDN(child), idx+1, len(child.CRLDistributionPoints), cdpURL)

					// Per-fetch cap layered under the global ctx.
					fetchCtx, cancel := context.WithTimeout(ctx, timeout)
					req, err := http.NewRequestWithContext(fetchCtx, "GET", cdpURL, nil)
					if err != nil {
						cancel()
						errMsgs = append(errMsgs, fmt.Sprintf("%s: bad request: %v", cdpURL, err))
						continue
					}
					req.Header.Set("User-Agent", "x509-cert-validator/1.0")

					resp, err := c.Client.Do(req)
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

					data, err := certload.ReadWithLimit(resp.Body, c.MaxBytes)
					_ = resp.Body.Close()
					cancel()
					if err != nil {
						errMsgs = append(errMsgs, fmt.Sprintf("%s: read failed (%v)", cdpURL, err))
						continue
					}

					parsed, err := x509util.ParseRevocationListFromData(data)
					if err != nil {
						if errs.LooksLikeUnsupportedAlgoErr(err) {
							res.HasUnsupportedAlgo = true
						}
						if errs.LooksLikeInsecureAlgoErr(err) {
							res.HasInsecureAlgo = true
						}
						errMsgs = append(errMsgs, fmt.Sprintf("%s: parse failed", cdpURL))
						continue
					}
					rl = parsed
					crlCache[cdpURL] = cacheEntry{rl: parsed}
				}

				// H-2: verify CRL Issuer DN matches parent CA Subject DN before signature check.
				// Catches the rare same-key-different-CA edge case earlier with a clearer error
				// (the subsequent sig check would also reject, but with a less informative message).
				if !bytes.Equal(rl.RawIssuer, parent.RawSubject) {
					c.log("⚠️  CRL Issuer DN does not match parent CA Subject DN (CRL Issuer=%q vs Parent=%q). Treating CRL as invalid.\n",
						rl.Issuer.String(), parent.Subject.String())
					errMsgs = append(errMsgs, fmt.Sprintf("%s: CRL Issuer DN does not match parent CA Subject DN", cdpURL))
					continue
				}

				// Signature must validate against issuer
				if err := rl.CheckSignatureFrom(parent); err != nil {
					if errs.LooksLikeUnsupportedAlgoErr(err) {
						res.HasUnsupportedAlgo = true
					}
					if errs.LooksLikeInsecureAlgoErr(err) {
						res.HasInsecureAlgo = true
					}
					errMsgs = append(errMsgs, fmt.Sprintf("%s: invalid signature", cdpURL))
					continue
				}

				// Log key type/length used for CRL signature verification (requested).
				c.log("   ℹ️  CRL Signature Verified: SigAlg=%s SignedByKey=%s Issuer=%s\n",
					rl.SignatureAlgorithm, x509util.CertPublicKeySummary(parent), x509util.CnOrDN(parent))

				// Missing ThisUpdate/NextUpdate => warning + treat as invalid for -crl
				if rl.ThisUpdate.IsZero() || rl.NextUpdate.IsZero() {
					c.log("⚠️  WARNING: CRL from %s missing ThisUpdate/NextUpdate; treating as invalid for -crl.\n", cdpURL)
					errMsgs = append(errMsgs, fmt.Sprintf("%s: missing ThisUpdate/NextUpdate", cdpURL))
					continue
				}

				if now.Before(rl.ThisUpdate) || now.After(rl.NextUpdate) {
					errMsgs = append(errMsgs, fmt.Sprintf("%s: CRL expired or future", cdpURL))
					continue
				}

				// This is a valid responding CRL
				validCRLFound = true

				// If any responding CRL reports revoked => fail (clear statement)
				for _, revoked := range rl.RevokedCertificateEntries {
					if child.SerialNumber.Cmp(revoked.SerialNumber) == 0 {
						return res, fmt.Errorf("certificate '%s' (Serial=%s) is REVOKED according to CRL %s",
							x509util.CnOrDN(child), x509util.SerialHex(child), cdpURL)
					}
				}

				c.log("   ✅ Valid CRL checked via %s\n", cdpURL)
				// Do NOT break: another responding CDP might still report revoked.
			}

			if !validCRLFound {
				return res, fmt.Errorf("failed to check CRL for %s. Errors: %v", x509util.CnOrDN(child), errMsgs)
			}
		}
	}
	return res, nil
}

func (c *Checker) log(format string, args ...any) {
	if c.Logger == nil {
		return
	}
	c.Logger.Normal(format, args...)
}
