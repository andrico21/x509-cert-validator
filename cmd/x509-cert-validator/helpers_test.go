package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/andrico21/x509-cert-validator/internal/bundle"
	"github.com/andrico21/x509-cert-validator/internal/display"
	"github.com/andrico21/x509-cert-validator/internal/errs"
	"github.com/andrico21/x509-cert-validator/internal/x509util"
)

// ============================================================================
// Helpers for generating in-memory test certificates / CRLs
// ============================================================================

// genTestCert creates a self-signed (or issuer-signed) cert for tests.
// If issuer is nil and issuerKey is nil, the cert is self-signed.
func genTestCert(t *testing.T, tmpl *x509.Certificate, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
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

func selfSignedRoot(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return genTestCert(t, tmpl, nil, nil)
}

func issuedCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	return genTestCert(t, tmpl, parent, parentKey)
}

// ============================================================================
// cnOrDN
// ============================================================================

func TestCnOrDN(t *testing.T) {
	if got := x509util.CnOrDN(nil); got != "UNKNOWN" {
		t.Errorf("nil cert: want UNKNOWN, got %q", got)
	}
	withCN := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com", Organization: []string{"Acme"}}}
	if got := x509util.CnOrDN(withCN); got != "example.com" {
		t.Errorf("with CN: want example.com, got %q", got)
	}
	noCN := &x509.Certificate{Subject: pkix.Name{Organization: []string{"Acme"}, Country: []string{"US"}}}
	got := x509util.CnOrDN(noCN)
	if !strings.Contains(got, "Acme") || !strings.Contains(got, "US") {
		t.Errorf("no CN: expected DN containing Acme & US, got %q", got)
	}
}

// ============================================================================
// serialHex
// ============================================================================

func TestSerialHex(t *testing.T) {
	if got := x509util.SerialHex(nil); got != "?" {
		t.Errorf("nil cert: want ?, got %q", got)
	}
	if got := x509util.SerialHex(&x509.Certificate{}); got != "?" {
		t.Errorf("nil serial: want ?, got %q", got)
	}
	if got := x509util.SerialHex(&x509.Certificate{SerialNumber: big.NewInt(0)}); got != "00" {
		t.Errorf("zero serial: want 00, got %q", got)
	}
	if got := x509util.SerialHex(&x509.Certificate{SerialNumber: big.NewInt(0xdeadbeef)}); got != "deadbeef" {
		t.Errorf("0xdeadbeef serial: want deadbeef, got %q", got)
	}
	big1 := new(big.Int)
	big1.SetString("1234567890abcdef", 16)
	if got := x509util.SerialHex(&x509.Certificate{SerialNumber: big1}); got != "1234567890abcdef" {
		t.Errorf("large serial: want 1234567890abcdef, got %q", got)
	}
}

// ============================================================================
// looksLikeUnsupportedAlgoErr / looksLikeInsecureAlgoErr
// ============================================================================

func TestLooksLikeUnsupportedAlgoErr(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("connection refused"), false},
		{errors.New("x509: algorithm unimplemented"), true},
		{errors.New("unknown public key algorithm"), true},
		{errors.New("unknown signature algorithm"), true},
		{errors.New("unsupported elliptic curve"), true},
		{errors.New("unsupported algorithm GOST"), true},
	}
	for _, c := range cases {
		if got := errs.LooksLikeUnsupportedAlgoErr(c.err); got != c.want {
			t.Errorf("err=%v: want %v, got %v", c.err, c.want, got)
		}
	}
}

func TestLooksLikeInsecureAlgoErr(t *testing.T) {
	if errs.LooksLikeInsecureAlgoErr(nil) {
		t.Error("nil err should be false")
	}
	if errs.LooksLikeInsecureAlgoErr(errors.New("connection refused")) {
		t.Error("non-matching err should be false")
	}
	if !errs.LooksLikeInsecureAlgoErr(errors.New("x509: cannot verify signature: insecure algorithm SHA1-RSA")) {
		t.Error("matching err should be true")
	}
}

// ============================================================================
// humanDuration
// ============================================================================

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{5 * time.Minute, "5m 0s"},
		{2*time.Hour + 30*time.Minute + 15*time.Second, "2h 30m 15s"},
		{3*24*time.Hour + 4*time.Hour, "3d 4h 0m 0s"},
		{0, "0s"},
		{-30 * time.Second, "30s"}, // negative is normalized
	}
	for _, c := range cases {
		if got := display.HumanDuration(c.d); got != c.want {
			t.Errorf("d=%v: want %q, got %q", c.d, c.want, got)
		}
	}
}

// ============================================================================
// truncate
// ============================================================================

func TestTruncate(t *testing.T) {
	if got := display.Truncate("hello", 10); got != "hello" {
		t.Errorf("short: want hello, got %q", got)
	}
	if got := display.Truncate("hello", 5); got != "hello" {
		t.Errorf("exact: want hello, got %q", got)
	}
	if got := display.Truncate("hello world", 8); got != "hello..." {
		t.Errorf("long: want hello..., got %q", got)
	}
}

// ============================================================================
// ipNetListToStrings
// ============================================================================

func TestIPNetListToStrings(t *testing.T) {
	if got := display.IPNetListToStrings(nil); got != nil {
		t.Errorf("nil: want nil, got %v", got)
	}
	if got := display.IPNetListToStrings([]*net.IPNet{}); got != nil {
		t.Errorf("empty: want nil, got %v", got)
	}
	_, n1, _ := net.ParseCIDR("10.0.0.0/8")
	_, n2, _ := net.ParseCIDR("192.168.1.0/24")
	got := display.IPNetListToStrings([]*net.IPNet{n1, nil, n2})
	if len(got) != 2 {
		t.Fatalf("expected 2 (nil filtered), got %d: %v", len(got), got)
	}
	if got[0] != "10.0.0.0/8" || got[1] != "192.168.1.0/24" {
		t.Errorf("unexpected: %v", got)
	}
}

// ============================================================================
// wrapList
// ============================================================================

func TestWrapList(t *testing.T) {
	if got := display.WrapList("DNS", nil, 80); got != nil {
		t.Errorf("nil items: want nil, got %v", got)
	}
	if got := display.WrapList("DNS", []string{}, 80); got != nil {
		t.Errorf("empty items: want nil, got %v", got)
	}
	got := display.WrapList("DNS", []string{"a.example.com", "b.example.com"}, 80)
	if len(got) != 1 {
		t.Fatalf("short list should fit one line, got %d: %v", len(got), got)
	}
	if !strings.HasPrefix(got[0], "DNS: ") {
		t.Errorf("expected prefix 'DNS: ', got %q", got[0])
	}
	// Force wrapping with very small width
	got2 := display.WrapList("DNS", []string{"aaaa", "bbbb", "cccc"}, 12)
	if len(got2) < 2 {
		t.Errorf("expected wrap into >=2 lines, got %d: %v", len(got2), got2)
	}
}

// ============================================================================
// hasAnyNameConstraints
// ============================================================================

func TestHasAnyNameConstraints(t *testing.T) {
	if display.HasAnyNameConstraints(nil) {
		t.Error("nil cert should be false")
	}
	if display.HasAnyNameConstraints(&x509.Certificate{}) {
		t.Error("empty cert should be false")
	}
	cases := []*x509.Certificate{
		{PermittedDNSDomains: []string{"example.com"}},
		{ExcludedDNSDomains: []string{"bad.com"}},
		{PermittedDNSDomainsCritical: true},
		{PermittedIPRanges: []*net.IPNet{{}}},
		{ExcludedIPRanges: []*net.IPNet{{}}},
		{PermittedEmailAddresses: []string{"a@b"}},
		{ExcludedEmailAddresses: []string{"a@b"}},
		{PermittedURIDomains: []string{"x"}},
		{ExcludedURIDomains: []string{"x"}},
	}
	for i, c := range cases {
		if !display.HasAnyNameConstraints(c) {
			t.Errorf("case %d: expected true", i)
		}
	}
}

// ============================================================================
// isSelfSigned
// ============================================================================

func TestIsSelfSigned(t *testing.T) {
	if x509util.IsSelfSigned(nil) {
		t.Error("nil cert: should be false")
	}
	root, key := selfSignedRoot(t, "Root")
	if !x509util.IsSelfSigned(root) {
		t.Error("self-signed root: should be true")
	}
	leaf, _ := issuedCert(t, "leaf", root, key)
	if x509util.IsSelfSigned(leaf) {
		t.Error("issued leaf: should be false")
	}
}

// ============================================================================
// findParentInListCert
// ============================================================================

func TestFindParentInListCert(t *testing.T) {
	root, rootKey := selfSignedRoot(t, "Root")
	leaf, _ := issuedCert(t, "leaf", root, rootKey)
	other, _ := selfSignedRoot(t, "Other")

	if _, ok := x509util.FindParentInListCert(nil, []*x509.Certificate{root}); ok {
		t.Error("nil child: expected not found")
	}
	if _, ok := x509util.FindParentInListCert(leaf, nil); ok {
		t.Error("nil pool: expected not found")
	}
	if _, ok := x509util.FindParentInListCert(leaf, []*x509.Certificate{other}); ok {
		t.Error("wrong parent: expected not found")
	}
	parent, ok := x509util.FindParentInListCert(leaf, []*x509.Certificate{nil, other, root})
	if !ok {
		t.Fatal("expected to find root as parent")
	}
	if parent != root {
		t.Errorf("got wrong parent: %s", x509util.CnOrDN(parent))
	}
}

// ============================================================================
// parseRevocationListFromData
// ============================================================================

func TestParseRevocationListFromData(t *testing.T) {
	root, rootKey := selfSignedRoot(t, "CRL Root")
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, root, rootKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}

	// DER input
	crl, err := x509util.ParseRevocationListFromData(der)
	if err != nil {
		t.Fatalf("DER parse: %v", err)
	}
	if crl.Number.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("DER: wrong number")
	}

	// PEM input
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	crl2, err := x509util.ParseRevocationListFromData(pemBytes)
	if err != nil {
		t.Fatalf("PEM parse: %v", err)
	}
	if crl2.Number.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("PEM: wrong number")
	}

	// Garbage input
	if _, err := x509util.ParseRevocationListFromData([]byte("not a crl")); err == nil {
		t.Error("garbage: expected error")
	}
}

// ============================================================================
// bundle.FromVerifiedChains
// ============================================================================

func TestBuildBundleFromVerifiedChains(t *testing.T) {
	root, rootKey := selfSignedRoot(t, "Root")
	inter, interKey := issuedCert(t, "Inter", root, rootKey)
	leaf, _ := issuedCert(t, "leaf", inter, interKey)

	chain := [][]*x509.Certificate{{leaf, inter, root}}

	// without root
	out := bundle.FromVerifiedChains(chain, false)
	if len(out) != 1 || out[0] != inter {
		t.Errorf("includeRoot=false: expected [inter], got %d certs", len(out))
	}

	// with root
	out2 := bundle.FromVerifiedChains(chain, true)
	if len(out2) != 2 || out2[0] != inter || out2[1] != root {
		t.Errorf("includeRoot=true: expected [inter, root], got %d certs", len(out2))
	}

	// dedup across multiple chains
	chains := [][]*x509.Certificate{{leaf, inter, root}, {leaf, inter, root}}
	out3 := bundle.FromVerifiedChains(chains, true)
	if len(out3) != 2 {
		t.Errorf("dedup: expected 2 unique, got %d", len(out3))
	}
}

// ============================================================================
// bundle.FromDiscovered
// ============================================================================

func TestBuildBundleFromDiscovered(t *testing.T) {
	root, _ := selfSignedRoot(t, "Root")
	inter1, _ := selfSignedRoot(t, "Inter1") // distinct cert (just need .Raw)
	inter2, _ := selfSignedRoot(t, "Inter2")

	out := bundle.FromDiscovered([]*x509.Certificate{inter1, nil, inter2, inter1}, []*x509.Certificate{root}, false)
	if len(out) != 2 {
		t.Errorf("includeRoot=false: expected 2 (deduped), got %d", len(out))
	}

	out2 := bundle.FromDiscovered([]*x509.Certificate{inter1, inter2}, []*x509.Certificate{root, nil}, true)
	if len(out2) != 3 {
		t.Errorf("includeRoot=true: expected 3, got %d", len(out2))
	}
}

// ============================================================================
// aliasFlags / printDefaultsExcludingAliases / isZeroValueFlag
// ============================================================================
// These helpers were moved into the internal/cli package as part of PR5b
// Step I (cli extraction). Their unit tests will be re-introduced in
// internal/cli/cli_test.go during Step K (test split). End-to-end alias
// behavior is covered today by tests.sh which exercises every legacy
// spelling (-includeRoot, -showGraph, -ultrasilent,
// -maxaia, -maxcrl, -maxlocal, -maxcert).

// ============================================================================
// verifyFailureHint (Fix 2: hint ordering / diagnostic mask)
// ============================================================================

func hintText(lines []string) string { return strings.Join(lines, "") }

func TestVerifyFailureHintHostnameBeatsAlgoFlags(t *testing.T) {
	// Regression: an unrelated unsupported-algo cert seen during loading
	// must NOT mask a hostname-mismatch failure.
	err := errors.New("x509: certificate is valid for 137 names, but none matched google.ru")
	got := hintText(verifyFailureHint(err, nil, true /* hasUnsupported */, true /* hasInsecure */, "leaf.pem", "", "any"))
	if !strings.Contains(got, "Hostname mismatch") {
		t.Errorf("want hostname tip, got: %q", got)
	}
	if strings.Contains(got, "CRITICAL HINT") {
		t.Errorf("algo hint must not fire on hostname mismatch, got: %q", got)
	}
}

func TestVerifyFailureHintKeyUsageBeatsAlgoFlags(t *testing.T) {
	err := errors.New("x509: certificate specifies an incompatible key usage")
	got := hintText(verifyFailureHint(err, nil, true, false, "leaf.pem", "", "server"))
	if !strings.Contains(got, "requested type: server") {
		t.Errorf("want key-usage tip, got: %q", got)
	}
	if strings.Contains(got, "CRITICAL HINT") {
		t.Errorf("algo hint must not fire on key-usage error, got: %q", got)
	}
}

func TestVerifyFailureHintUnsupportedAlgoOnGenericError(t *testing.T) {
	// GOST-intermediate case: verify fails generically ("unknown
	// authority") while loading flagged an unsupported algorithm - the
	// algo hint must still fire (before the authority tip).
	err := errors.New("x509: certificate signed by unknown authority")
	got := hintText(verifyFailureHint(err, nil, true, false, "leaf.pem", "root.pem", "any"))
	if !strings.Contains(got, "unsupported algorithm/curve") {
		t.Errorf("want unsupported-algo hint, got: %q", got)
	}
	if !strings.Contains(got, "-CAfile root.pem") {
		t.Errorf("want -CAfile variant when rootPath set, got: %q", got)
	}
}

func TestVerifyFailureHintInsecureAlgo(t *testing.T) {
	root, _ := selfSignedRoot(t, "Leaf For Hint")
	err := errors.New("x509: cannot verify signature: insecure algorithm SHA1-RSA")
	got := hintText(verifyFailureHint(err, root, false, false, "leaf.pem", "", "any"))
	if !strings.Contains(got, "insecure signature algorithm policy") {
		t.Errorf("want insecure-algo hint, got: %q", got)
	}
	if !strings.Contains(got, "Leaf Signature Algorithm:") {
		t.Errorf("want leaf details when leaf provided, got: %q", got)
	}
}

func TestVerifyFailureHintAuthoritySelfSigned(t *testing.T) {
	root, _ := selfSignedRoot(t, "Self Signed")
	err := errors.New("x509: certificate signed by unknown authority")
	got := hintText(verifyFailureHint(err, root, false, false, "leaf.pem", "", "any"))
	if !strings.Contains(got, "self-signed") {
		t.Errorf("want self-signed tip, got: %q", got)
	}
}

func TestVerifyFailureHintAuthorityNotSelfSigned(t *testing.T) {
	err := errors.New("x509: certificate signed by unknown authority")
	got := hintText(verifyFailureHint(err, nil, false, false, "leaf.pem", "", "any"))
	if !strings.Contains(got, "-aia") {
		t.Errorf("want intermediates tip, got: %q", got)
	}
}

// ============================================================================
// Compile-time checks
// ============================================================================

var _ io.Writer = (*strings.Builder)(nil) // ensure strings.Builder is io.Writer
