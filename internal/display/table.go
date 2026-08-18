// This file adds the -inspect summary-table renderer. It lives in
// display alongside the other pure formatting helpers and returns a
// string (no I/O) so the caller owns stdout and the TTY/-no-color
// decision. Certificate-derived text is passed through SanitizeTerminal
// per-cell BEFORE any ANSI color is applied, so untrusted fields cannot
// inject escape sequences while the color codes we add remain intact.
// Callers MUST print the returned string directly and MUST NOT re-run it
// through SanitizeTerminal (that would strip the color codes).

package display

import (
	"fmt"
	"strings"

	"github.com/andrico21/x509-cert-validator/internal/certinfo"
)

// ANSI color codes used only by the inspect summary table, and only when
// the caller passes useColor=true.
const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
)

// ExpiryLabel returns the coarse expiry state: "expired", "expiring", or
// "valid".
func ExpiryLabel(info certinfo.CertInfo) string {
	switch {
	case info.Expired:
		return "expired"
	case info.Expiring:
		return "expiring"
	default:
		return "valid"
	}
}

func expiryColor(info certinfo.CertInfo) string {
	switch {
	case info.Expired:
		return ansiRed
	case info.Expiring:
		return ansiYellow
	default:
		return ansiGreen
	}
}

// RemainingLabel renders days-remaining compactly ("73d", "EXPIRED").
func RemainingLabel(info certinfo.CertInfo) string {
	if info.Expired {
		return "EXPIRED"
	}
	return fmt.Sprintf("%dd", info.DaysRemaining)
}

// RenderSummaryTable formats infos as an aligned, optionally-colored
// summary table and returns it as a string. A "Source" column is added
// only when at least one entry carries provenance. All cert-derived text
// is sanitized per-cell; color is applied around sanitized content only.
func RenderSummaryTable(infos []certinfo.CertInfo, useColor bool) string {
	hasSource := false
	for _, in := range infos {
		if in.Source != "" {
			hasSource = true
			break
		}
	}

	headers := []string{"#", "Role", "Subject", "Issuer", "Not After", "Remaining", "Status", "SHA-256"}
	if hasSource {
		headers = append([]string{"Source"}, headers...)
	}

	type cell struct {
		text  string
		color string
	}
	var rows [][]cell
	for _, in := range infos {
		clr := ""
		if useColor {
			clr = expiryColor(in)
		}
		row := []cell{
			{text: fmt.Sprintf("%d", in.Index)},
			{text: SanitizeTerminal(in.Role)},
			{text: SanitizeTerminal(cnOr(in.SubjectCN, in.Subject))},
			{text: SanitizeTerminal(cnOr(in.IssuerCN, in.Issuer))},
			{text: in.NotAfter.Format("2006-01-02 15:04")},
			{text: RemainingLabel(in), color: clr},
			{text: ExpiryLabel(in), color: clr},
			{text: certinfo.ShortFP(in.FingerprintSHA256)},
		}
		if hasSource {
			row = append([]cell{{text: SanitizeTerminal(in.Source)}}, row...)
		}
		rows = append(rows, row)
	}

	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(widths) && len(c.text) > widths[i] {
				widths[i] = len(c.text)
			}
		}
	}

	var b strings.Builder
	writeLine := func(cells []string) {
		b.WriteString(strings.TrimRight(strings.Join(cells, "  "), " "))
		b.WriteByte('\n')
	}

	hdr := make([]string, len(headers))
	sep := make([]string, len(headers))
	for i, h := range headers {
		hdr[i] = padRight(h, widths[i])
		sep[i] = strings.Repeat("-", widths[i])
	}
	writeLine(hdr)
	writeLine(sep)

	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			padded := padRight(c.text, widths[i])
			if c.color != "" {
				padded = c.color + padded + ansiReset
			}
			cells[i] = padded
		}
		writeLine(cells)
	}
	return b.String()
}

func cnOr(cn, dn string) string {
	if cn != "" {
		return cn
	}
	return dn
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
