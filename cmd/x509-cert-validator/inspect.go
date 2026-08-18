package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/andrico21/x509-cert-validator/internal/certinfo"
	"github.com/andrico21/x509-cert-validator/internal/cli"
	"github.com/andrico21/x509-cert-validator/internal/display"
)

// runInspect implements the -inspect operation: describe the certificate(s)
// loaded from -cert (file, directory, multi-cert bundle, "-" for stdin, or
// http(s) URL) WITHOUT building or validating a chain. Output is a summary
// table (default), full per-certificate detail (-full), or JSON (-json).
//
// Returns the process exit code: 0 normally, 2 when -fail-expired is set and
// at least one certificate is expired. Load failures abort earlier via
// exitErr (exit 1). validationTime honors -at; cfg.Days is the expiry window.
func runInspect(ctx context.Context, cfg *cli.Config) int {
	certs := loadAll(ctx, cfg.CertPath)
	if len(certs) == 0 {
		exitErr(fmt.Errorf("no certificates loaded from -cert"))
	}

	infos := make([]certinfo.CertInfo, 0, len(certs))
	for i, c := range certs {
		infos = append(infos, certinfo.FromCert(c, i, validationTime, cfg.Days))
	}

	switch {
	case cfg.JSON:
		if err := emitJSON(infos); err != nil {
			exitErr(fmt.Errorf("json encode failed: %v", err))
		}
	case verbosity == LevelNormal:
		// Table output is already per-cell sanitized by the renderer; print
		// it directly (re-sanitizing would strip the ANSI color codes).
		fmt.Print(display.RenderSummaryTable(infos, shouldColor(cfg.NoColor)))
		if cfg.Full {
			for _, in := range infos {
				fmt.Print(renderFullDetail(in))
			}
		}
		// verbosity Silent/UltraSilent: no descriptive output, exit code only
		// (useful as a pure -fail-expired gate).
	}

	if (cfg.FailExpired && anyExpiredInfo(infos)) || (cfg.FailExpiring && anyExpiringInfo(infos)) {
		return 2
	}
	return 0
}

func anyExpiredInfo(infos []certinfo.CertInfo) bool {
	for _, in := range infos {
		if in.Expired {
			return true
		}
	}
	return false
}

// anyExpiringInfo reports whether any certificate is within the -days window
// (Expiring) or already past due (Expired) - the trigger for -fail-expiring,
// which is a strict superset of -fail-expired.
func anyExpiringInfo(infos []certinfo.CertInfo) bool {
	for _, in := range infos {
		if in.Expired || in.Expiring {
			return true
		}
	}
	return false
}

// shouldColor decides whether ANSI color is emitted for the inspect table:
// disabled by -no-color, by the NO_COLOR environment variable, or when
// stdout is not a character device (piped/redirected).
func shouldColor(noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// renderFullDetail renders one certificate's full field set as an aligned
// key/value block. Certificate-derived values are sanitized (this is not
// JSON output) so untrusted fields cannot inject terminal escapes.
func renderFullDetail(in certinfo.CertInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s\n", display.SanitizeTerminal(fmt.Sprintf("== Certificate %d (%s) ==", in.Index, cnOrSubject(in))))
	kv := func(k, v string) {
		if v == "" {
			return
		}
		fmt.Fprintf(&b, "%-18s%s\n", k, display.SanitizeTerminal(v))
	}
	kv("Index", fmt.Sprintf("%d", in.Index))
	kv("Role", in.Role)
	kv("Source", in.Source)
	kv("Subject", in.Subject)
	kv("Issuer", in.Issuer)
	kv("Serial", in.SerialNumber)
	kv("Not Before", in.NotBefore.Format("2006-01-02 15:04:05 MST"))
	kv("Not After", in.NotAfter.Format("2006-01-02 15:04:05 MST"))
	kv("Validity", validityLabel(in))
	kv("Is CA", fmt.Sprintf("%t", in.IsCA))
	kv("Self-signed", fmt.Sprintf("%t", in.SelfSigned))
	kv("Public key", fmt.Sprintf("%s %d bits", in.PublicKeyAlgorithm, in.PublicKeyBits))
	kv("Signature", in.SignatureAlgorithm)
	kv("DNS names", strings.Join(in.DNSNames, ", "))
	kv("IP addresses", strings.Join(in.IPAddresses, ", "))
	kv("Email", strings.Join(in.EmailAddresses, ", "))
	kv("URIs", strings.Join(in.URIs, ", "))
	kv("Key usage", strings.Join(in.KeyUsage, ", "))
	kv("Ext key usage", strings.Join(in.ExtKeyUsage, ", "))
	kv("SHA-256", in.FingerprintSHA256)
	kv("SHA-1", in.FingerprintSHA1)
	kv("AIA CA issuers", strings.Join(in.AIACAIssuers, ", "))
	kv("CRL distribution", strings.Join(in.CRLDistribution, ", "))
	return b.String()
}

func cnOrSubject(in certinfo.CertInfo) string {
	if in.SubjectCN != "" {
		return in.SubjectCN
	}
	return in.Subject
}

func validityLabel(in certinfo.CertInfo) string {
	if in.Expired {
		return fmt.Sprintf("EXPIRED (%d days ago)", -in.DaysRemaining)
	}
	return fmt.Sprintf("%d days remaining", in.DaysRemaining)
}
