// Package x509util provides pure, stateless helpers for inspecting and
// comparing crypto/x509 values. None of these touch package-level state,
// perform I/O, or depend on the surrounding application's logger; they are
// safe to call from anywhere.
package x509util

import (
	"bytes"
	"crypto/dsa" // intentionally retained for diagnostic-only DSA key-type reporting on legacy certs; SA1019 suppressed via staticcheck.conf.
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// CnOrDN returns the certificate's CommonName, falling back to its full
// Subject DN if CN is empty. Returns "UNKNOWN" for nil input.
func CnOrDN(c *x509.Certificate) string {
	if c == nil {
		return "UNKNOWN"
	}
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

// SerialHex returns the certificate serial number in plain hex. Returns "?"
// for nil input or nil serial; "00" when the serial encodes to zero bytes.
func SerialHex(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return "?"
	}
	b := cert.SerialNumber.Bytes()
	if len(b) == 0 {
		return "00"
	}
	return hex.EncodeToString(b)
}

// ParseRevocationListFromData parses a CRL from PEM (any block whose Type
// contains "CRL") or falls back to assuming raw DER.
func ParseRevocationListFromData(data []byte) (*x509.RevocationList, error) {
	// Try PEM first (may contain multiple blocks)
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if strings.Contains(block.Type, "CRL") {
			return x509.ParseRevocationList(block.Bytes)
		}
	}
	// Fallback: assume DER
	return x509.ParseRevocationList(data)
}

// FindParentInListCert returns the parent certificate of child if found in
// pool (subject/issuer match plus successful signature check). The DER-equal
// fast path avoids re-parsing; a String() fallback covers rare DER encoding
// differences between otherwise-identical DNs.
func FindParentInListCert(child *x509.Certificate, pool []*x509.Certificate) (*x509.Certificate, bool) {
	if child == nil {
		return nil, false
	}
	for _, parent := range pool {
		if parent == nil {
			continue
		}
		// Fast path: DER-equal issuer/subject
		if bytes.Equal(child.RawIssuer, parent.RawSubject) {
			if child.CheckSignatureFrom(parent) == nil {
				return parent, true
			}
			continue
		}
		// Fallback for rare DER encoding differences
		if child.Issuer.String() == parent.Subject.String() {
			if child.CheckSignatureFrom(parent) == nil {
				return parent, true
			}
		}
	}
	return nil, false
}

// IsSelfSigned reports whether cert is self-signed (signature verifies under
// its own public key AND issuer DN matches subject DN).
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.CheckSignatureFrom(cert) != nil {
		return false
	}
	// Fast path
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return true
	}
	// Fallback for rare DER encoding differences
	return cert.Issuer.String() == cert.Subject.String()
}

// CertPublicKeySummary returns a short human-readable description of a
// certificate's public key (e.g., "RSA-2048", "ECDSA-P-256(256)").
func CertPublicKeySummary(cert *x509.Certificate) string {
	if cert == nil {
		return "UNKNOWN"
	}
	return PublicKeySummary(cert.PublicKey)
}

// PublicKeySummary returns a short human-readable description of any
// supported public-key value. Diagnostic-only; not used to gate verification.
func PublicKeySummary(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil {
			return "RSA-?"
		}
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		if k == nil || k.Curve == nil || k.Curve.Params() == nil {
			return "ECDSA-?"
		}
		name := k.Curve.Params().Name
		bits := k.Curve.Params().BitSize
		if name == "" && bits > 0 {
			return fmt.Sprintf("ECDSA-%d", bits)
		}
		if name != "" && bits > 0 {
			return fmt.Sprintf("ECDSA-%s(%d)", name, bits)
		}
		if name != "" {
			return fmt.Sprintf("ECDSA-%s", name)
		}
		return "ECDSA-?"
	case ed25519.PublicKey:
		return "Ed25519-256"
	case *dsa.PublicKey:
		if k == nil || k.P == nil {
			return "DSA-?"
		}
		return fmt.Sprintf("DSA-%d", k.P.BitLen())
	default:
		return fmt.Sprintf("Unknown(%T)", pub)
	}
}
