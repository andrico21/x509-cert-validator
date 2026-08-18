// Package bundle assembles and writes CA-bundle PEM artifacts from
// verified certificate chains or discovered intermediates/roots.
//
// All helpers are pure (no package-level state, no logging) and treat
// the leaf certificate as out-of-scope: callers are responsible for
// ensuring the leaf is never passed to writers.
package bundle

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/andrico21/x509-cert-validator/internal/x509util"
)

// FromVerifiedChains returns a deduplicated list of intermediate (and
// optionally trust-anchor) certificates harvested from one or more
// verified chains. The leaf (chain[0]) is always excluded.
func FromVerifiedChains(chains [][]*x509.Certificate, includeRoot bool) []*x509.Certificate {
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

// FromDiscovered returns a deduplicated list of intermediates discovered
// outside of x509.Verify (server-sent, AIA-fetched, CLI-provided), with
// optional trust roots appended when includeRoot is true. The leaf is
// not part of either input slice and so is never included.
func FromDiscovered(inters []*x509.Certificate, roots []*x509.Certificate, includeRoot bool) []*x509.Certificate {
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

// WritePEM atomically writes a deduplicated PEM bundle to path. Writes go
// to a randomly named temp file in the same directory (so the final
// os.Rename stays on one volume and cannot clobber an unrelated
// pre-existing "<path>.tmp" file); the temp file is renamed on success and
// removed on any failure (named-return + deferred cleanup), so callers
// never see stale partial output. Returns the count of certificates
// written and the subset of those that were self-signed (roots).
func WritePEM(path string, certs []*x509.Certificate) (written int, rootsWritten int, err error) {
	// #nosec G304 -- the output path is user-supplied by design (-export <path>).
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return 0, 0, err
	}
	tmpPath := f.Name()
	committed := false
	defer func() {
		// Close (idempotent: ignore second-close errors via _ )
		_ = f.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	// os.CreateTemp opens 0600; the bundle is a public PEM artifact (CA
	// certificates), so restore the documented 0644 distribution mode.
	// #nosec G302 -- intentional, documented file mode.
	if err = f.Chmod(0o644); err != nil {
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

		if err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return written, rootsWritten, err
		}
		written++
		if x509util.IsSelfSigned(c) {
			rootsWritten++
		}
	}

	if err = f.Close(); err != nil {
		return written, rootsWritten, err
	}

	if err = os.Rename(tmpPath, path); err != nil {
		return written, rootsWritten, err
	}

	committed = true
	return written, rootsWritten, nil
}
