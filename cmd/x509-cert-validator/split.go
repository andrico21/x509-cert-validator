package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/andrico21/x509-cert-validator/internal/certinfo"
	"github.com/andrico21/x509-cert-validator/internal/cli"
	"github.com/andrico21/x509-cert-validator/internal/display"
	"github.com/andrico21/x509-cert-validator/internal/x509util"
)

// splitEntryJSON describes one written certificate in split -json output.
type splitEntryJSON struct {
	File              string `json:"file"`
	Index             int    `json:"index"`
	SubjectCN         string `json:"subject_cn,omitempty"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

// splitJSON is the -json document emitted by the split operation.
type splitJSON struct {
	Input   string           `json:"input"`
	OutDir  string           `json:"outdir"`
	Count   int              `json:"count"`
	Written []splitEntryJSON `json:"written"`
}

// runSplit implements the -split operation: decompose the certificate(s)
// loaded from -cert (file, directory, bundle, "-" for stdin, or URL) into one
// PEM file per certificate under -outdir. File naming follows -split-name
// ("index" -> NN_subject.crt, "subject" -> subject.crt with -N disambiguation).
//
// Returns the process exit code: 0 normally, 2 when -fail-expired is set and
// at least one certificate is expired. Load/write failures abort via exitErr.
func runSplit(ctx context.Context, cfg *cli.Config) int {
	certs := loadAll(ctx, cfg.CertPath)
	if len(certs) == 0 {
		exitErr(fmt.Errorf("no certificates loaded from -cert"))
	}

	// #nosec G703 -- creating the user-specified -outdir is the tool's purpose; the path is operator-provided by design.
	if err := os.MkdirAll(cfg.OutDir, 0o750); err != nil {
		exitErr(fmt.Errorf("mkdir %s: %v", cfg.OutDir, err))
	}

	written := make([]splitEntryJSON, 0, len(certs))
	used := map[string]int{}
	for i, c := range certs {
		name := splitFileName(c, i, cfg.SplitName, used)
		p := filepath.Join(cfg.OutDir, name)
		if err := writeCertPEM(p, c); err != nil {
			exitErr(fmt.Errorf("write %s: %v", p, err))
		}
		info := certinfo.FromCert(c, i, validationTime, cfg.Days)
		written = append(written, splitEntryJSON{
			File:              p,
			Index:             i,
			SubjectCN:         info.SubjectCN,
			FingerprintSHA256: info.FingerprintSHA256,
		})
		if !cfg.JSON && verbosity == LevelNormal {
			fmt.Printf("saved  %s\n", display.SanitizeTerminal(p))
		}
	}

	if cfg.JSON {
		res := splitJSON{Input: cfg.CertPath, OutDir: cfg.OutDir, Count: len(written), Written: written}
		if err := emitJSON(res); err != nil {
			exitErr(fmt.Errorf("json encode failed: %v", err))
		}
	}

	if cfg.FailExpired || cfg.FailExpiring {
		for i, c := range certs {
			info := certinfo.FromCert(c, i, validationTime, cfg.Days)
			if (cfg.FailExpired && info.Expired) || (cfg.FailExpiring && (info.Expired || info.Expiring)) {
				return 2
			}
		}
	}
	return 0
}

// writeCertPEM writes a single certificate as a PEM CERTIFICATE block. File
// mode is 0600 (owner-only): these are public certificates, but a tight
// default is harmless and keeps the security linter satisfied.
func writeCertPEM(path string, c *x509.Certificate) error {
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	// #nosec G306 G703 -- 0600 is already tight, and the destination is the user-chosen -outdir joined with a slugified (path-separator-free) filename; writing there is the tool's purpose.
	return os.WriteFile(path, b, 0o600)
}

// splitFileName derives a filesystem-safe name for cert idx under the chosen
// naming mode. "index" prefixes the ordinal for stable ordering; "subject"
// uses the slugified CN, disambiguating collisions with a -N suffix.
func splitFileName(c *x509.Certificate, idx int, mode string, used map[string]int) string {
	base := slug(x509util.CnOrDN(c))
	if mode == "subject" {
		n := used[base]
		used[base] = n + 1
		if n == 0 {
			return base + ".crt"
		}
		return fmt.Sprintf("%s-%d.crt", base, n+1)
	}
	return fmt.Sprintf("%02d_%s.crt", idx, base)
}

// slug turns an arbitrary string (e.g. a certificate CN) into a lower-case,
// filesystem-safe name fragment. Only [a-z0-9] survive; every other run
// collapses to a single dash. Because path separators never survive, a
// hostile subject cannot cause writes outside -outdir.
func slug(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "cert"
	}
	return out
}
