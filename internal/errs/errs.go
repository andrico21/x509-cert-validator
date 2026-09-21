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
// Both can be detected with errors.Is.
//
// Classification is deliberately type-first. The error text reaching these
// helpers can contain certificate-controlled bytes - crypto/x509 echoes field
// values into messages such as `x509: cannot parse URI %q` - so matching on a
// phrase inside the text lets a certificate author steer the classification.
// The one place a text comparison remains is the parse-stage pair below, whose
// messages are untyped errors.New in crypto/x509 and therefore unreachable by
// errors.Is/As; those are matched by exact equality, which an echoed field
// value cannot satisfy.
package errs

import (
	"crypto/x509"
	"errors"
)

// Sentinel errors. Use errors.Is to detect; wrap with fmt.Errorf("%s: %w", origMsg, ErrXxx)
// when surfacing parse failures.
var (
	ErrUnsupportedAlgo = errors.New("unsupported algorithm or curve")
	ErrInsecureAlgo    = errors.New("insecure algorithm")
)

// parseStageUnsupportedAlgos are the two messages crypto/x509 returns for an
// unsupported curve or public-key algorithm while PARSING. They are plain
// errors.New values, not x509.ErrUnsupportedAlgorithm (which is a verify-stage
// sentinel), so no typed check can reach them. Matched by exact equality on
// purpose: an attacker who echoes text into a parse error cannot make the whole
// message equal one of these.
//
// If a future Go release wraps or rewords them, this degrades to "no hint"
// rather than a "wrong" hint, which is the safe direction.
var parseStageUnsupportedAlgos = map[string]bool{
	"x509: unsupported elliptic curve":   true,
	"x509: unknown public key algorithm": true,
}

// LooksLikeUnsupportedAlgoErr reports whether err is an unsupported-algorithm
// rejection from crypto/x509, at either stage.
func LooksLikeUnsupportedAlgoErr(err error) bool {
	if err == nil {
		return false
	}
	// Verify stage: "x509: cannot verify signature: algorithm unimplemented".
	if errors.Is(err, x509.ErrUnsupportedAlgorithm) {
		return true
	}
	// Callers that wrap a rejection in our own sentinel.
	if errors.Is(err, ErrUnsupportedAlgo) {
		return true
	}
	// Parse stage: untyped, so exact-match the known messages.
	return parseStageUnsupportedAlgos[err.Error()]
}

// LooksLikeInsecureAlgoErr reports whether err is Go's insecure-algorithm
// verification rejection.
//
// This is type-only. There is no text fallback because there is no legitimate
// parse-stage producer: x509.InsecureAlgorithmError is returned exclusively from
// the signature check, so a parse error can never be one, and a substring test
// would classify on text a certificate can influence.
func LooksLikeInsecureAlgoErr(err error) bool {
	if err == nil {
		return false
	}
	// InsecureAlgorithmError is an integer type with a value receiver, so the
	// target is a pointer to the value, not to a struct.
	var insecure x509.InsecureAlgorithmError
	return errors.As(err, &insecure) || errors.Is(err, ErrInsecureAlgo)
}
