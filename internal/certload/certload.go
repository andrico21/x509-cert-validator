// Package certload provides primitives for reading certificate bytes
// from io.Reader sources with a hard size cap, and for parsing PEM/DER
// certificate data.
//
// Functions in this package never call os.Exit and never log; they
// return errors and out-of-band algorithm-rejection flags so callers
// (currently the main package) can decide how to surface them.
package certload

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math"

	"github.com/andrico21/x509-cert-validator/internal/errs"
)

// ReadWithLimit reads from r up to limit bytes. It reads limit+1 bytes
// internally so that exceeding the cap is reliably detected and reported
// as an error rather than silently truncated.
func ReadWithLimit(r io.Reader, limit int64) ([]byte, error) {
	// Guard the limit+1 below against integer overflow for pathological
	// flag values (e.g. -max-local 9223372036854775807): a wrapped
	// negative LimitReader count would read zero bytes and surface a
	// confusing "no certificates found" error.
	if limit > math.MaxInt64-1 {
		limit = math.MaxInt64 - 1
	}
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

// ParseResult bundles the certificates parsed from a blob with the
// algorithm-rejection flags discovered along the way. Callers OR these
// flags into their run-scoped state to surface diagnostic hints later
// (e.g., the "GOST/SHA1" tips emitted by handleVerifyError).
type ParseResult struct {
	Certs              []*x509.Certificate
	HasUnsupportedAlgo bool
	HasInsecureAlgo    bool
	// SkippedBlocks holds messages for PEM blocks that failed to parse;
	// callers may surface these as warnings. One entry per skipped block.
	SkippedBlocks []string
}

// ParseCerts parses certificate data from bytes, accepting either one
// or more PEM CERTIFICATE blocks or a single raw DER blob (as a fallback
// when no PEM block matches). Returns a non-nil error only when no
// certificates could be parsed at all; the source label is included in
// the error and skip messages so callers can identify the input.
//
// The HasUnsupportedAlgo / HasInsecureAlgo flags reflect rejections seen
// during parsing and are populated even on the success path so callers
// can show diagnostic hints alongside successful loads.
func ParseCerts(data []byte, source string) (ParseResult, error) {
	var res ParseResult
	blockData := data
	for {
		var block *pem.Block
		block, blockData = pem.Decode(blockData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			if errs.LooksLikeUnsupportedAlgoErr(err) {
				res.HasUnsupportedAlgo = true
			}
			if errs.LooksLikeInsecureAlgoErr(err) {
				res.HasInsecureAlgo = true
			}
			res.SkippedBlocks = append(res.SkippedBlocks, fmt.Sprintf("Skipping unparsable block in %s: %v", source, err))
			continue
		}
		res.Certs = append(res.Certs, c)
	}

	if len(res.Certs) == 0 {
		c, err := x509.ParseCertificate(data)
		if err == nil {
			res.Certs = []*x509.Certificate{c}
			return res, nil
		}
		if errs.LooksLikeUnsupportedAlgoErr(err) {
			res.HasUnsupportedAlgo = true
		}
		if errs.LooksLikeInsecureAlgoErr(err) {
			res.HasInsecureAlgo = true
		}
		return res, fmt.Errorf("no certificates found in %s", source)
	}
	return res, nil
}

// ParseCertsSafe is the no-error variant used by best-effort parsers
// (e.g., AIA-fetched bodies that may legitimately contain garbage).
// It returns whatever certificates parsed cleanly plus the algorithm
// flags; an empty Certs slice is not an error condition.
func ParseCertsSafe(data []byte) ParseResult {
	var res ParseResult
	blockData := data
	for {
		var block *pem.Block
		block, blockData = pem.Decode(blockData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			res.Certs = append(res.Certs, c)
			continue
		}
		if errs.LooksLikeUnsupportedAlgoErr(err) {
			res.HasUnsupportedAlgo = true
		}
		if errs.LooksLikeInsecureAlgoErr(err) {
			res.HasInsecureAlgo = true
		}
	}
	if len(res.Certs) == 0 {
		c, err := x509.ParseCertificate(data)
		if err == nil {
			res.Certs = append(res.Certs, c)
			return res
		}
		if errs.LooksLikeUnsupportedAlgoErr(err) {
			res.HasUnsupportedAlgo = true
		}
		if errs.LooksLikeInsecureAlgoErr(err) {
			res.HasInsecureAlgo = true
		}
	}
	return res
}
