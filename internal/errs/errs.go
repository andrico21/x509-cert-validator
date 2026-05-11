// Package errs defines typed sentinel errors and classifiers for x509
// parse/verify failures we surface as user-facing diagnostics.
//
// Two sentinels are exported:
//
//   - ErrUnsupportedAlgo: Go's x509 package rejected an algorithm/curve
//     we expect to be diagnostic-visible (GOST, unknown OIDs, unsupported
//     EC curves, etc.).
//   - ErrInsecureAlgo: Go refused to verify due to its insecure-algorithm
//     policy (e.g., SHA1-RSA chains under modern verification).
//
// Both can be detected with errors.Is. The Looks*Err helpers also accept
// raw, unwrapped errors from crypto/x509 by falling back to substring
// matching, so callers can use a single check regardless of the error
// origin.
package errs

import (
	"errors"
	"strings"
)

// Sentinel errors. Use errors.Is to detect; wrap with fmt.Errorf("%s: %w", origMsg, ErrXxx)
// when surfacing parse failures.
var (
	ErrUnsupportedAlgo = errors.New("unsupported algorithm or curve")
	ErrInsecureAlgo    = errors.New("insecure algorithm")
)

// LooksLikeUnsupportedAlgoErr reports whether err is (or wraps) an
// unsupported-algorithm rejection from crypto/x509. Falls back to
// substring matching for unwrapped errors returned directly by the
// standard library.
func LooksLikeUnsupportedAlgoErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrUnsupportedAlgo) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "algorithm unimplemented") ||
		strings.Contains(s, "unknown public key algorithm") ||
		strings.Contains(s, "unknown signature algorithm") ||
		strings.Contains(s, "unsupported elliptic curve") ||
		strings.Contains(s, "unsupported algorithm")
}

// LooksLikeInsecureAlgoErr reports whether err is (or wraps) Go's
// "insecure algorithm" verification rejection. Falls back to substring
// matching for unwrapped errors returned directly by the standard
// library (e.g., "x509: cannot verify signature: insecure algorithm SHA1-RSA").
func LooksLikeInsecureAlgoErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrInsecureAlgo) {
		return true
	}
	return strings.Contains(err.Error(), "insecure algorithm")
}
