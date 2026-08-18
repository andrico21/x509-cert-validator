package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/andrico21/x509-cert-validator/internal/bundle"
	"github.com/andrico21/x509-cert-validator/internal/cli"
	"github.com/andrico21/x509-cert-validator/internal/display"
	"github.com/andrico21/x509-cert-validator/internal/x509util"
)

// exportCerts writes the supplied certificates to disk per cfg.ExportFormat:
// "bundle" concatenates them into the single file cfg.Export; "split" writes
// one PEM file per certificate into the directory cfg.Export, named per
// cfg.ExportName. The caller has already applied -export-scope. Certificates
// are de-duplicated (a leaf can appear in several verified paths). Write
// failures abort via exitErr.
func exportCerts(certs []*x509.Certificate, cfg *cli.Config) {
	certs = dedupeCerts(certs)
	if len(certs) == 0 {
		logNormal("⚠️  Export: no certificates matched -export-scope %s; nothing written.\n", cfg.ExportScope)
		return
	}
	if cfg.ExportFormat == "split" {
		exportSplit(certs, cfg)
		return
	}
	exportBundle(certs, cfg)
}

// exportBundle writes all certs as one concatenated PEM file at cfg.Export,
// reusing the atomic bundle writer.
func exportBundle(certs []*x509.Certificate, cfg *cli.Config) {
	written, _, err := bundle.WritePEM(cfg.Export, certs)
	if err != nil {
		exitErr(fmt.Errorf("write bundle %s: %v", cfg.Export, err))
	}
	if !cfg.JSON && verbosity == LevelNormal {
		fmt.Printf("saved  %s (%d certificate(s))\n", display.SanitizeTerminal(cfg.Export), written)
	}
}

// exportSplit writes one PEM file per certificate into the directory cfg.Export.
func exportSplit(certs []*x509.Certificate, cfg *cli.Config) {
	// #nosec G703 -- creating the user-specified -export directory is the tool's purpose; the path is operator-provided by design.
	if err := os.MkdirAll(cfg.Export, 0o750); err != nil {
		exitErr(fmt.Errorf("mkdir %s: %v", cfg.Export, err))
	}
	used := map[string]int{}
	for i, c := range certs {
		name := splitFileName(c, i, cfg.ExportName, used)
		p := filepath.Join(cfg.Export, name)
		if err := writeCertPEM(p, c); err != nil {
			exitErr(fmt.Errorf("write %s: %v", p, err))
		}
		if !cfg.JSON && verbosity == LevelNormal {
			fmt.Printf("saved  %s\n", display.SanitizeTerminal(p))
		}
	}
}

// writeCertPEM writes a single certificate as a PEM CERTIFICATE block. File
// mode is 0600 (owner-only): these are public certificates, but a tight
// default is harmless and keeps the security linter satisfied.
func writeCertPEM(path string, c *x509.Certificate) error {
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	// #nosec G306 G703 -- 0600 is already tight, and the destination is the user-chosen -export directory joined with a slugified (path-separator-free) filename; writing there is the tool's purpose.
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
// hostile subject cannot cause writes outside the export directory.
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

// dedupeCerts removes duplicate certificates by raw DER, preserving first-seen
// order.
func dedupeCerts(certs []*x509.Certificate) []*x509.Certificate {
	seen := map[string]bool{}
	out := make([]*x509.Certificate, 0, len(certs))
	for _, c := range certs {
		k := string(c.Raw)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
	}
	return out
}
