// Package display contains pure formatting helpers for human-readable
// certificate output (durations, text wrapping, name constraints rendering).
//
// Helpers in this package MUST remain free of package-level mutable state and
// MUST NOT perform I/O. Stateful printers (printCertDetails, printChainGraph,
// printNameConstraints, etc.) live in the main package until the Validator
// struct + Logger interface are introduced (PR5b Step E).
package display

import (
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

// HumanDuration renders a time.Duration as a coarse, human-friendly string
// (e.g. "3d 4h 5m 6s"). Negative durations are reported as their absolute
// value; the sign is the caller's responsibility.
func HumanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int(d.Hours()) / 24
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d.Hours())
	d -= time.Duration(hours) * time.Hour
	minutes := int(d.Minutes())
	d -= time.Duration(minutes) * time.Minute
	seconds := int(d.Seconds())
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// Truncate returns s shortened to at most length bytes, replacing the tail
// with "..." when truncation occurs. Cuts happen only at rune boundaries so
// multibyte characters are never split. For length <= 3 the result is a
// plain rune-safe prefix without an ellipsis (never panics, unlike the
// previous implementation). Inputs already within length are returned
// unchanged.
func Truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	if length <= 0 {
		return ""
	}
	if length <= 3 {
		return truncToRuneBoundary(s, length)
	}
	return truncToRuneBoundary(s, length-3) + "..."
}

// truncToRuneBoundary returns the longest prefix of s that is at most n
// bytes long and does not split a multibyte rune.
func truncToRuneBoundary(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// SanitizeTerminal replaces C0 control characters (except '\n', '\r' and
// '\t') and DEL (0x7F) with U+FFFD so untrusted certificate fields (CNs,
// DNs, SANs, URLs) cannot inject terminal escape sequences (e.g. ANSI
// color/title/clipboard codes) into diagnostic output. Printable text,
// including emoji and non-ASCII names, passes through unchanged.
func SanitizeTerminal(s string) string {
	// Fast path: control characters are single-byte in UTF-8, so a byte
	// scan is exact and avoids allocation for clean strings.
	dirty := false
	for i := 0; i < len(s); i++ {
		if isDisallowedControl(s[i]) {
			dirty = true
			break
		}
	}
	if !dirty {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		b := s[i]
		if isDisallowedControl(b) {
			sb.WriteRune('\uFFFD')
			continue
		}
		sb.WriteByte(b)
	}
	return sb.String()
}

func isDisallowedControl(b byte) bool {
	if b == '\n' || b == '\r' || b == '\t' {
		return false
	}
	return b < 0x20 || b == 0x7F
}

// HasAnyNameConstraints reports whether cert declares any RFC 5280 §4.2.1.10
// Name Constraints (permitted or excluded subtrees of any supported type).
func HasAnyNameConstraints(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return cert.PermittedDNSDomainsCritical ||
		len(cert.PermittedDNSDomains) > 0 ||
		len(cert.ExcludedDNSDomains) > 0 ||
		len(cert.PermittedIPRanges) > 0 ||
		len(cert.ExcludedIPRanges) > 0 ||
		len(cert.PermittedEmailAddresses) > 0 ||
		len(cert.ExcludedEmailAddresses) > 0 ||
		len(cert.PermittedURIDomains) > 0 ||
		len(cert.ExcludedURIDomains) > 0
}

// IPNetListToStrings renders a slice of *net.IPNet as their CIDR string
// forms, dropping nil entries. Returns nil for empty/nil input.
func IPNetListToStrings(nets []*net.IPNet) []string {
	if len(nets) == 0 {
		return nil
	}
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		if n == nil {
			continue
		}
		out = append(out, n.String())
	}
	return out
}

// WrapList formats a labeled list of items into one-or-more fixed-width
// lines. The first line begins with "label: "; continuation lines are
// indented to align under the items. Tokens longer than width are truncated
// with an ellipsis via Truncate.
func WrapList(label string, items []string, width int) []string {
	if len(items) == 0 {
		return nil
	}
	prefix := label + ": "
	contPrefix := strings.Repeat(" ", len(prefix))

	var lines []string
	cur := prefix

	for _, it := range items {
		if it == "" {
			continue
		}

		sep := ""
		if cur != prefix && cur != contPrefix {
			sep = ", "
		}

		token := sep + it
		if len(cur)+len(token) <= width {
			cur += token
			continue
		}

		lines = append(lines, Truncate(cur, width))

		cur = contPrefix + it
		if len(cur) > width {
			lines = append(lines, Truncate(cur, width))
			cur = contPrefix
		}
	}

	if strings.TrimSpace(cur) != "" && cur != contPrefix {
		lines = append(lines, Truncate(cur, width))
	}
	return lines
}

// BuildNameConstraintLines renders a certificate's Name Constraints as a
// list of width-bounded text lines suitable for ASCII box rendering.
// Returns sentinel lines ("NC: unknown" / "NC: no") when the cert is nil
// or carries no constraints.
func BuildNameConstraintLines(cert *x509.Certificate, width int) []string {
	if cert == nil {
		return []string{"NC: unknown"}
	}
	if !HasAnyNameConstraints(cert) {
		return []string{"NC: no"}
	}

	crit := ""
	if cert.PermittedDNSDomainsCritical {
		crit = " (critical)"
	}

	var out []string
	out = append(out, "NC: yes"+crit)

	out = append(out, WrapList("PermDNS", cert.PermittedDNSDomains, width)...)
	out = append(out, WrapList("ExclDNS", cert.ExcludedDNSDomains, width)...)

	out = append(out, WrapList("PermIP", IPNetListToStrings(cert.PermittedIPRanges), width)...)
	out = append(out, WrapList("ExclIP", IPNetListToStrings(cert.ExcludedIPRanges), width)...)

	out = append(out, WrapList("PermEmail", cert.PermittedEmailAddresses, width)...)
	out = append(out, WrapList("ExclEmail", cert.ExcludedEmailAddresses, width)...)

	out = append(out, WrapList("PermURI", cert.PermittedURIDomains, width)...)
	out = append(out, WrapList("ExclURI", cert.ExcludedURIDomains, width)...)

	return out
}
