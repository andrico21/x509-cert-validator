// Package aia implements RFC 5280 §4.2.2.1 Authority Information Access
// "caIssuers" parent-certificate fetching.
//
// The Fetcher type wraps a configurable *http.Client, a Logger for
// progress diagnostics, and a per-fetch byte cap. Each call to Fetch
// walks the candidate URLs on a certificate, downloads + parses the
// first responding parent, and returns it together with any
// algorithm-rejection flags surfaced during parsing so callers can OR
// them into run-scoped state.
//
// Network behavior:
//   - Per-fetch context derived from the caller's ctx, capped at
//     PerFetchTimeout (default DefaultPerFetchTimeout if zero).
//   - HTTP redirects bounded by client.CheckRedirect (caller-configured).
//   - Non-http(s) URLs are surfaced as warnings and skipped (M-2 parity).
//
// Verification behavior (H-1 parity):
//   - Issuer/subject name binding (RawIssuer == RawSubject) is checked
//     for visibility but never blocks the fetch.
//   - cert.CheckSignatureFrom(fetched) is checked for visibility but
//     never blocks the fetch.
//   - Mismatches are logged as warnings; the fetched cert is still
//     returned so the operator can see what the URL served. The final
//     x509.Verify on the assembled chain remains the cryptographic
//     safety net.
package aia

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/andrico21/x509-cert-validator/internal/certload"
	"github.com/andrico21/x509-cert-validator/internal/validator"
	"github.com/andrico21/x509-cert-validator/internal/x509util"
)

// DefaultPerFetchTimeout is applied to each individual AIA HTTP request
// when Fetcher.PerFetchTimeout is zero.
const DefaultPerFetchTimeout = 10 * time.Second

// Fetcher performs AIA caIssuers parent-certificate retrieval. Construct
// with NewFetcher; reuse across multiple Fetch calls in a single
// validation run so connection-pool benefits accrue.
type Fetcher struct {
	Client          *http.Client     // required; supplies CheckRedirect + connection pool
	Logger          validator.Logger // required; progress diagnostics
	MaxBytes        int64            // per-fetch download cap; <=0 means unlimited (NOT recommended)
	PerFetchTimeout time.Duration    // applied per URL; zero means DefaultPerFetchTimeout
}

// NewFetcher constructs a Fetcher with the supplied dependencies.
// Pass logger=nil only in tests that don't care about progress output.
func NewFetcher(client *http.Client, logger validator.Logger, maxBytes int64) *Fetcher {
	return &Fetcher{Client: client, Logger: logger, MaxBytes: maxBytes}
}

// FetchResult bundles the fetched parent certificate (or nil on
// failure) with algorithm-rejection findings discovered during parsing.
// Callers OR the flags into their run-scoped state.
type FetchResult struct {
	Parent             *x509.Certificate
	HasUnsupportedAlgo bool
	HasInsecureAlgo    bool
}

// Fetch walks cert.IssuingCertificateURL in order and returns the first
// successfully parsed parent certificate. Returns a non-nil error only
// when every URL failed; the error wraps the last underlying cause for
// operator visibility.
//
// FetchResult.HasUnsupportedAlgo / HasInsecureAlgo are populated even on
// the success path so the caller can surface algorithm-rejection
// diagnostic hints alongside otherwise-OK fetches.
func (f *Fetcher) Fetch(ctx context.Context, cert *x509.Certificate) (FetchResult, error) {
	var res FetchResult
	var lastErr error

	timeout := f.PerFetchTimeout
	if timeout <= 0 {
		timeout = DefaultPerFetchTimeout
	}

	for i, u := range cert.IssuingCertificateURL {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			// M-2: surface skipped non-http(s) AIA URLs instead of silently ignoring them.
			f.log("⚠️  Skipping AIA URL with unsupported scheme [%d/%d]: %s\n", i+1, len(cert.IssuingCertificateURL), u)
			continue
		}
		f.log("⬇️  Fetching Parent via AIA [%d/%d]: %s\n", i+1, len(cert.IssuingCertificateURL), u)

		// Per-fetch cap layered under the global ctx.
		fetchCtx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(fetchCtx, "GET", u, nil)
		if err != nil {
			cancel()
			f.log("   ⚠️  Bad Request: %v\n", err)
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "x509-cert-validator/1.0")

		resp, err := f.Client.Do(req)
		if err != nil {
			cancel()
			f.log("   ⚠️  Connection Failed: %v\n", err)
			lastErr = err
			continue
		}

		if resp.StatusCode != 200 {
			_ = resp.Body.Close()
			cancel()
			f.log("   ⚠️  HTTP Error: %d\n", resp.StatusCode)
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			continue
		}

		data, err := certload.ReadWithLimit(resp.Body, f.MaxBytes)
		_ = resp.Body.Close()
		cancel()
		if err != nil {
			f.log("   ⚠️  Read Failed: %v\n", err)
			lastErr = err
			continue
		}

		parsed := certload.ParseCertsSafe(data)
		// Always surface flags, even on parse-fail paths below: an
		// unsupported algorithm encountered on URL 1 is still useful
		// context if URL 2 ultimately succeeds.
		if parsed.HasUnsupportedAlgo {
			res.HasUnsupportedAlgo = true
		}
		if parsed.HasInsecureAlgo {
			res.HasInsecureAlgo = true
		}

		if len(parsed.Certs) > 0 {
			fetched := parsed.Certs[0]

			// H-1: verify name + signature binding between fetched cert and the child whose AIA we followed.
			// Diagnostic-friendly: on mismatch, WARN but still return the cert so the operator can SEE
			// what the AIA URL served. The final x509.Verify is the cryptographic safety net.
			nameOK := bytes.Equal(cert.RawIssuer, fetched.RawSubject)
			sigOK := cert.CheckSignatureFrom(fetched) == nil
			switch {
			case !nameOK && !sigOK:
				f.log("   ⚠️  AIA cert from %s does NOT match expected issuer of '%s' (subject mismatch AND bad signature). Adding to pool anyway for diagnostic visibility.\n", u, x509util.CnOrDN(cert))
			case !nameOK:
				f.log("   ⚠️  AIA cert from %s has Subject DN that does NOT match expected Issuer DN of '%s'. Adding to pool anyway for diagnostic visibility.\n", u, x509util.CnOrDN(cert))
			case !sigOK:
				f.log("   ⚠️  AIA cert from %s did NOT sign '%s' (signature check failed). Adding to pool anyway for diagnostic visibility.\n", u, x509util.CnOrDN(cert))
			default:
				f.log("   ✅ AIA cert verified against child issuer (name + signature OK).\n")
			}

			res.Parent = fetched
			return res, nil
		}
		f.log("   ⚠️  Parse Failed\n")
		lastErr = fmt.Errorf("unable to parse certificate data")
	}
	return res, fmt.Errorf("all AIA URLs failed. Last error: %v", lastErr)
}

func (f *Fetcher) log(format string, args ...any) {
	if f.Logger == nil {
		return
	}
	f.Logger.Normal(format, args...)
}
