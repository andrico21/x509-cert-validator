package certinfo

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// makeCert builds a self-contained test certificate signed by itself (or by
// parent when non-nil) so tests exercise real *x509.Certificate values.
func makeCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	signer := parent
	signerKey := parentKey
	if signer == nil {
		signer = tmpl
		signerKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c, key
}

func baseTemplate(cn string, serial int64, notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
}

func TestFromCert_SelfSignedRoot(t *testing.T) {
	now := time.Now()
	tmpl := baseTemplate("Test Root CA", 1, now.Add(-24*time.Hour), now.Add(365*24*time.Hour))
	tmpl.IsCA = true
	tmpl.BasicConstraintsValid = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	cert, _ := makeCert(t, tmpl, nil, nil)

	info := FromCert(cert, 0, now, 30)

	if info.Role != "root" {
		t.Errorf("role = %q, want root", info.Role)
	}
	if !info.IsCA {
		t.Error("IsCA = false, want true")
	}
	if !info.SelfSigned {
		t.Error("SelfSigned = false, want true")
	}
	if info.Expired {
		t.Error("Expired = true, want false")
	}
	if info.PublicKeyAlgorithm != "RSA" {
		t.Errorf("PublicKeyAlgorithm = %q, want RSA", info.PublicKeyAlgorithm)
	}
	if info.PublicKeyBits != 2048 {
		t.Errorf("PublicKeyBits = %d, want 2048", info.PublicKeyBits)
	}
	if len(info.FingerprintSHA256) != 64 {
		t.Errorf("SHA256 fp len = %d, want 64", len(info.FingerprintSHA256))
	}
	if len(info.FingerprintSHA1) != 40 {
		t.Errorf("SHA1 fp len = %d, want 40", len(info.FingerprintSHA1))
	}
	if info.FingerprintSHA256 != upper(info.FingerprintSHA256) {
		t.Error("SHA256 fingerprint is not uppercase")
	}
	wantKU := map[string]bool{"certSign": true, "crlSign": true}
	for _, ku := range info.KeyUsage {
		delete(wantKU, ku)
	}
	if len(wantKU) != 0 {
		t.Errorf("missing key usages: %v (got %v)", wantKU, info.KeyUsage)
	}
}

func TestFromCert_LeafRoleAndExtKeyUsage(t *testing.T) {
	now := time.Now()
	tmpl := baseTemplate("leaf.example.com", 2, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	tmpl.DNSNames = []string{"leaf.example.com", "www.example.com"}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	cert, _ := makeCert(t, tmpl, nil, nil)

	info := FromCert(cert, 0, now, 30)

	if info.Role != "server" {
		t.Errorf("role = %q, want server", info.Role)
	}
	if info.IsCA {
		t.Error("IsCA = true, want false")
	}
	if len(info.DNSNames) != 2 {
		t.Errorf("DNSNames = %v, want 2 entries", info.DNSNames)
	}
	if len(info.ExtKeyUsage) != 1 || info.ExtKeyUsage[0] != "serverAuth" {
		t.Errorf("ExtKeyUsage = %v, want [serverAuth]", info.ExtKeyUsage)
	}
}

func TestFromCert_Expired(t *testing.T) {
	now := time.Now()
	tmpl := baseTemplate("expired.example.com", 3, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	cert, _ := makeCert(t, tmpl, nil, nil)

	info := FromCert(cert, 0, now, 30)

	if !info.Expired {
		t.Error("Expired = false, want true")
	}
	if info.Expiring {
		t.Error("Expiring = true, want false (already expired)")
	}
	if info.DaysRemaining >= 0 {
		t.Errorf("DaysRemaining = %d, want negative", info.DaysRemaining)
	}
}

func TestFromCert_ExpiringWithinThreshold(t *testing.T) {
	now := time.Now()
	// Expires in ~10 days; threshold 30 => expiring.
	tmpl := baseTemplate("soon.example.com", 4, now.Add(-time.Hour), now.Add(10*24*time.Hour))
	cert, _ := makeCert(t, tmpl, nil, nil)

	info := FromCert(cert, 0, now, 30)

	if info.Expired {
		t.Error("Expired = true, want false")
	}
	if !info.Expiring {
		t.Errorf("Expiring = false, want true (DaysRemaining=%d, threshold=30)", info.DaysRemaining)
	}
}

func TestFromCert_NilSafe(t *testing.T) {
	info := FromCert(nil, 5, time.Now(), 30)
	if info.Index != 5 || info.Role != "unknown" {
		t.Errorf("nil cert: got index=%d role=%q, want 5/unknown", info.Index, info.Role)
	}
}

func TestShortFP(t *testing.T) {
	if got := ShortFP("ABCDEF0123456789AABB"); got != "ABCDEF0123456789" {
		t.Errorf("ShortFP = %q, want ABCDEF0123456789", got)
	}
	if got := ShortFP("ABCD"); got != "ABCD" {
		t.Errorf("ShortFP short input = %q, want ABCD", got)
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
