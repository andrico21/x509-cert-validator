// Package certinfo provides a normalized, machine-readable view of an
// x509 certificate (CertInfo) plus a builder that derives it from a
// *x509.Certificate.
//
// CertInfo is the single source of truth for both the -json output and
// the -inspect summary table: rendering code reads these fields rather
// than re-deriving them from crypto/x509 so the human and machine views
// never drift. The struct's json tags define the stable, documented
// JSON schema; do not rename or drop a tag without treating it as a
// breaking change to that contract.
//
// Functions here are pure: no I/O, no package-level state, no os.Exit.
// Fingerprints intentionally include SHA-1 (a standard diagnostic
// identifier, parity with `openssl x509 -fingerprint -sha1`); it is
// never used for cryptographic verification.
package certinfo

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- SHA-1 fingerprint is a standard diagnostic identifier (parity with openssl), not used for cryptographic security.
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"

	"github.com/andrico21/x509-cert-validator/internal/x509util"
)

// CertInfo is the normalized, machine-readable view of one certificate.
// The json tags define the documented output schema.
type CertInfo struct {
	Source             string    `json:"source,omitempty"`
	Index              int       `json:"index"`
	Role               string    `json:"role"`
	Subject            string    `json:"subject"`
	SubjectCN          string    `json:"subject_cn,omitempty"`
	Issuer             string    `json:"issuer"`
	IssuerCN           string    `json:"issuer_cn,omitempty"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	DaysRemaining      int       `json:"days_remaining"`
	Expired            bool      `json:"expired"`
	Expiring           bool      `json:"expiring"`
	IsCA               bool      `json:"is_ca"`
	SelfSigned         bool      `json:"self_signed"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PublicKeyBits      int       `json:"public_key_bits"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	IPAddresses        []string  `json:"ip_addresses,omitempty"`
	EmailAddresses     []string  `json:"email_addresses,omitempty"`
	URIs               []string  `json:"uris,omitempty"`
	KeyUsage           []string  `json:"key_usage,omitempty"`
	ExtKeyUsage        []string  `json:"ext_key_usage,omitempty"`
	FingerprintSHA1    string    `json:"fingerprint_sha1"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	AIACAIssuers       []string  `json:"aia_ca_issuers,omitempty"`
	CRLDistribution    []string  `json:"crl_distribution_points,omitempty"`
}

// FromCert builds a CertInfo from cert. idx is the certificate's position
// in the input set (0 == first/leaf). now is the effective evaluation time
// (honors -at); daysThreshold is the -days expiry warning window. A cert is
// Expired when now is past NotAfter, and Expiring when it is not expired but
// falls due within daysThreshold days.
func FromCert(cert *x509.Certificate, idx int, now time.Time, daysThreshold int) CertInfo {
	if cert == nil {
		return CertInfo{Index: idx, Role: "unknown"}
	}

	daysRemaining := int(cert.NotAfter.Sub(now).Hours() / 24)
	expired := now.After(cert.NotAfter)
	expiring := !expired && daysRemaining <= daysThreshold

	sha256sum := sha256.Sum256(cert.Raw)
	sha1sum := sha1.Sum(cert.Raw) // #nosec G401 -- diagnostic fingerprint (parity with openssl), not used for cryptographic verification.

	return CertInfo{
		Index:              idx,
		Role:               roleFor(cert, idx),
		Subject:            cert.Subject.String(),
		SubjectCN:          cert.Subject.CommonName,
		Issuer:             cert.Issuer.String(),
		IssuerCN:           cert.Issuer.CommonName,
		SerialNumber:       x509util.SerialHex(cert),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		DaysRemaining:      daysRemaining,
		Expired:            expired,
		Expiring:           expiring,
		IsCA:               cert.IsCA,
		SelfSigned:         x509util.IsSelfSigned(cert),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:      pubKeyBits(cert),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		DNSNames:           cert.DNSNames,
		IPAddresses:        ipStrings(cert),
		EmailAddresses:     cert.EmailAddresses,
		URIs:               uriStrings(cert),
		KeyUsage:           keyUsages(cert),
		ExtKeyUsage:        extKeyUsages(cert),
		FingerprintSHA1:    strings.ToUpper(hex.EncodeToString(sha1sum[:])),
		FingerprintSHA256:  strings.ToUpper(hex.EncodeToString(sha256sum[:])),
		AIACAIssuers:       cert.IssuingCertificateURL,
		CRLDistribution:    cert.CRLDistributionPoints,
	}
}

// ShortFP returns the first 16 hex chars of a fingerprint for compact
// tabular display; shorter inputs are returned unchanged.
func ShortFP(fp string) string {
	if len(fp) >= 16 {
		return fp[:16]
	}
	return fp
}

// roleFor returns a best-effort role label. The first certificate is the
// server/leaf (or root when self-issued CA); later certificates are roots
// when self-signed, otherwise intermediates. This is a display heuristic
// for a loose set of certs, not an assertion about a verified chain.
func roleFor(c *x509.Certificate, idx int) string {
	if idx == 0 {
		if c.IsCA && x509util.IsSelfSigned(c) {
			return "root"
		}
		return "server"
	}
	if x509util.IsSelfSigned(c) {
		return "root"
	}
	return "intermediate"
}

// pubKeyBits returns the public key size in bits (0 when not applicable).
func pubKeyBits(c *x509.Certificate) int {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub == nil || pub.N == nil {
			return 0
		}
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		if pub == nil || pub.Curve == nil {
			return 0
		}
		return pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	}
	return 0
}

func ipStrings(c *x509.Certificate) []string {
	if len(c.IPAddresses) == 0 {
		return nil
	}
	out := make([]string, len(c.IPAddresses))
	for i, ip := range c.IPAddresses {
		out[i] = ip.String()
	}
	return out
}

func uriStrings(c *x509.Certificate) []string {
	if len(c.URIs) == 0 {
		return nil
	}
	out := make([]string, len(c.URIs))
	for i, u := range c.URIs {
		out[i] = u.String()
	}
	return out
}

// keyUsages decodes the KeyUsage bitmask into stable string names.
func keyUsages(c *x509.Certificate) []string {
	if c.KeyUsage == 0 {
		return nil
	}
	names := []struct {
		bit x509.KeyUsage
		s   string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "certSign"},
		{x509.KeyUsageCRLSign, "crlSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	}
	var out []string
	for _, n := range names {
		if c.KeyUsage&n.bit != 0 {
			out = append(out, n.s)
		}
	}
	return out
}

// extKeyUsages decodes ExtKeyUsage values into stable string names.
func extKeyUsages(c *x509.Certificate) []string {
	if len(c.ExtKeyUsage) == 0 {
		return nil
	}
	names := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                        "any",
		x509.ExtKeyUsageServerAuth:                 "serverAuth",
		x509.ExtKeyUsageClientAuth:                 "clientAuth",
		x509.ExtKeyUsageCodeSigning:                "codeSigning",
		x509.ExtKeyUsageEmailProtection:            "emailProtection",
		x509.ExtKeyUsageIPSECEndSystem:             "ipsecEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                "ipsecTunnel",
		x509.ExtKeyUsageIPSECUser:                  "ipsecUser",
		x509.ExtKeyUsageTimeStamping:               "timeStamping",
		x509.ExtKeyUsageOCSPSigning:                "ocspSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto: "msServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:  "netscapeServerGatedCrypto",
	}
	var out []string
	for _, u := range c.ExtKeyUsage {
		if s, ok := names[u]; ok {
			out = append(out, s)
		}
	}
	return out
}
