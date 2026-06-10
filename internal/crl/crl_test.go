package crl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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

func rootTemplate(cn string, keyUsage x509.KeyUsage) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
	}
}

func leafTemplate(cn string, serial int64, cdps []string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		CRLDistributionPoints: cdps,
	}
}

// makeCRL builds a DER CRL signed by issuer/issuerKey. CreateRevocationList
// insists on the cRLSign bit in the issuer struct, so a shallow copy with
// the bit OR'd in is used for signing; the caller's cert (and its Raw DER)
// is untouched.
func makeCRL(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, revoked []x509.RevocationListEntry) []byte {
	t.Helper()
	signer := *issuer
	signer.KeyUsage |= x509.KeyUsageCRLSign
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: revoked,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, &signer, issuerKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}
	return der
}

func serveCRL(t *testing.T, der []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(der)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newChecker(client *http.Client) *Checker {
	return &Checker{
		Client:          client,
		Logger:          nil, // log() is nil-safe
		MaxBytes:        1 << 20,
		PerFetchTimeout: 5 * time.Second,
	}
}

// Regression for Fix 3 (hard-fail): parent HAS a KeyUsage extension but
// without cRLSign, child declares CDPs => strict -crl must FAIL, and no
// HTTP fetch may be attempted (CDP host is unresolvable on purpose).
func TestCheckFailsWhenKeyUsagePresentWithoutCRLSign(t *testing.T) {
	root, rootKey := genCert(t, rootTemplate("No-CRLSign Root", x509.KeyUsageCertSign), nil, nil)
	if !hasKeyUsageExtension(root) {
		t.Fatal("fixture error: KeyUsage extension must be present")
	}
	leaf, _ := genCert(t, leafTemplate("leaf", 2, []string{"http://invalid.invalid/x.crl"}), root, rootKey)

	c := newChecker(&http.Client{Timeout: 2 * time.Second})
	_, err := c.Check(context.Background(), [][]*x509.Certificate{{leaf, root}}, time.Now())
	if err == nil {
		t.Fatal("expected hard failure for cRLSign-less issuer")
	}
	if !strings.Contains(err.Error(), "cRLSign") {
		t.Errorf("error should mention cRLSign, got: %v", err)
	}
}

// Regression for the Fix 3 RFC 5280 carve-out: parent WITHOUT any KeyUsage
// extension is treated as CRL-sign capable; the check proceeds and passes
// against a valid served CRL.
func TestCheckPassesWhenKeyUsageExtensionAbsent(t *testing.T) {
	root, rootKey := genCert(t, rootTemplate("Legacy Root", 0 /* no KeyUsage ext */), nil, nil)
	if hasKeyUsageExtension(root) {
		t.Fatal("fixture error: KeyUsage extension must be absent")
	}

	srv := serveCRL(t, makeCRL(t, root, rootKey, nil))
	leaf, _ := genCert(t, leafTemplate("leaf", 2, []string{srv.URL + "/test.crl"}), root, rootKey)

	c := newChecker(srv.Client())
	_, err := c.Check(context.Background(), [][]*x509.Certificate{{leaf, root}}, time.Now())
	if err != nil {
		t.Fatalf("expected pass for legacy issuer without KeyUsage extension, got: %v", err)
	}
}

// Child without CDPs is skipped regardless of parent key usage.
func TestCheckSkipsChildWithoutCDPs(t *testing.T) {
	root, rootKey := genCert(t, rootTemplate("Root", x509.KeyUsageCertSign|x509.KeyUsageCRLSign), nil, nil)
	leaf, _ := genCert(t, leafTemplate("leaf", 2, nil), root, rootKey)

	c := newChecker(&http.Client{Timeout: 2 * time.Second})
	_, err := c.Check(context.Background(), [][]*x509.Certificate{{leaf, root}}, time.Now())
	if err != nil {
		t.Fatalf("expected nil error for CDP-less child, got: %v", err)
	}
}

// Happy path + revocation detection with a proper cRLSign parent.
func TestCheckDetectsRevokedSerial(t *testing.T) {
	root, rootKey := genCert(t, rootTemplate("Root", x509.KeyUsageCertSign|x509.KeyUsageCRLSign), nil, nil)
	leaf, _ := genCert(t, leafTemplate("leaf", 42, nil), root, rootKey)

	revoked := []x509.RevocationListEntry{{
		SerialNumber:   leaf.SerialNumber,
		RevocationTime: time.Now().Add(-time.Minute),
	}}
	srv := serveCRL(t, makeCRL(t, root, rootKey, revoked))

	// Re-issue the leaf with the CDP pointing at the server (the CDP must
	// be baked into the cert).
	leaf2, _ := genCert(t, leafTemplate("leaf", 42, []string{srv.URL + "/test.crl"}), root, rootKey)

	c := newChecker(srv.Client())
	_, err := c.Check(context.Background(), [][]*x509.Certificate{{leaf2, root}}, time.Now())
	if err == nil {
		t.Fatal("expected revocation failure")
	}
	if !strings.Contains(err.Error(), "REVOKED") {
		t.Errorf("error should mention REVOKED, got: %v", err)
	}
}
