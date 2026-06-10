package x509util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// genCert creates a test certificate. If issuer/issuerKey are nil the cert
// is self-signed with its own fresh key.
func genCert(t *testing.T, tmpl *x509.Certificate, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	parent := issuer
	parentKey := issuerKey
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, key
}

func caTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

func TestIsSelfSignedNil(t *testing.T) {
	if IsSelfSigned(nil) {
		t.Error("nil cert: want false")
	}
}

func TestIsSelfSignedCARoot(t *testing.T) {
	root, _ := genCert(t, caTemplate("Root"), nil, nil)
	if !IsSelfSigned(root) {
		t.Error("self-signed CA root: want true")
	}
}

func TestIsSelfSignedIssuedLeaf(t *testing.T) {
	root, rootKey := genCert(t, caTemplate("Root"), nil, nil)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leaf, _ := genCert(t, leafTmpl, root, rootKey)
	if IsSelfSigned(leaf) {
		t.Error("CA-issued leaf: want false")
	}
}

// Regression for the Fix 5 bug: a self-signed NON-CA certificate (the
// classic `openssl req -x509` leaf with CA:FALSE or no BasicConstraints at
// all) must classify as self-signed. The old CheckSignatureFrom-based
// implementation returned false because the cert lacks the CA bit and
// KeyUsageCertSign.
func TestIsSelfSignedNonCALeaf(t *testing.T) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "standalone.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		// Deliberately NOT a CA: no IsCA, no BasicConstraintsValid,
		// no KeyUsage.
		DNSNames: []string{"standalone.local"},
	}
	cert, _ := genCert(t, tmpl, nil, nil)
	if cert.IsCA {
		t.Fatal("fixture error: cert must not be a CA")
	}
	if !IsSelfSigned(cert) {
		t.Error("self-signed non-CA cert: want true (Fix 5 regression)")
	}
}

func TestIsSelfSignedDifferentSubject(t *testing.T) {
	// Two distinct self-signed roots: neither is "self-signed" relative
	// to a name mismatch path; sanity-check name gate short-circuits.
	a, _ := genCert(t, caTemplate("A"), nil, nil)
	b, _ := genCert(t, caTemplate("B"), nil, nil)
	if a.Issuer.String() == b.Subject.String() {
		t.Fatal("fixture error")
	}
	// Forge: cert with A's content is still self-signed; b unrelated.
	if !IsSelfSigned(a) || !IsSelfSigned(b) {
		t.Error("independent roots must both be self-signed")
	}
}
