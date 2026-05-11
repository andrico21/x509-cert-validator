package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
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
	if got := cnOrDN(nil); got != "UNKNOWN" {
		t.Errorf("nil cert: want UNKNOWN, got %q", got)
	}
	withCN := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com", Organization: []string{"Acme"}}}
	if got := cnOrDN(withCN); got != "example.com" {
		t.Errorf("with CN: want example.com, got %q", got)
	}
	noCN := &x509.Certificate{Subject: pkix.Name{Organization: []string{"Acme"}, Country: []string{"US"}}}
	got := cnOrDN(noCN)
	if !strings.Contains(got, "Acme") || !strings.Contains(got, "US") {
		t.Errorf("no CN: expected DN containing Acme & US, got %q", got)
	}
}

// ============================================================================
// serialHex
// ============================================================================

func TestSerialHex(t *testing.T) {
	if got := serialHex(nil); got != "?" {
		t.Errorf("nil cert: want ?, got %q", got)
	}
	if got := serialHex(&x509.Certificate{}); got != "?" {
		t.Errorf("nil serial: want ?, got %q", got)
	}
	if got := serialHex(&x509.Certificate{SerialNumber: big.NewInt(0)}); got != "00" {
		t.Errorf("zero serial: want 00, got %q", got)
	}
	if got := serialHex(&x509.Certificate{SerialNumber: big.NewInt(0xdeadbeef)}); got != "deadbeef" {
		t.Errorf("0xdeadbeef serial: want deadbeef, got %q", got)
	}
	big1 := new(big.Int)
	big1.SetString("1234567890abcdef", 16)
	if got := serialHex(&x509.Certificate{SerialNumber: big1}); got != "1234567890abcdef" {
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
		if got := looksLikeUnsupportedAlgoErr(c.err); got != c.want {
			t.Errorf("err=%v: want %v, got %v", c.err, c.want, got)
		}
	}
}

func TestLooksLikeInsecureAlgoErr(t *testing.T) {
	if looksLikeInsecureAlgoErr(nil) {
		t.Error("nil err should be false")
	}
	if looksLikeInsecureAlgoErr(errors.New("connection refused")) {
		t.Error("non-matching err should be false")
	}
	if !looksLikeInsecureAlgoErr(errors.New("x509: cannot verify signature: insecure algorithm SHA1-RSA")) {
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
		if got := humanDuration(c.d); got != c.want {
			t.Errorf("d=%v: want %q, got %q", c.d, c.want, got)
		}
	}
}

// ============================================================================
// truncate
// ============================================================================

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short: want hello, got %q", got)
	}
	if got := truncate("hello", 5); got != "hello" {
		t.Errorf("exact: want hello, got %q", got)
	}
	if got := truncate("hello world", 8); got != "hello..." {
		t.Errorf("long: want hello..., got %q", got)
	}
}

// ============================================================================
// ipNetListToStrings
// ============================================================================

func TestIPNetListToStrings(t *testing.T) {
	if got := ipNetListToStrings(nil); got != nil {
		t.Errorf("nil: want nil, got %v", got)
	}
	if got := ipNetListToStrings([]*net.IPNet{}); got != nil {
		t.Errorf("empty: want nil, got %v", got)
	}
	_, n1, _ := net.ParseCIDR("10.0.0.0/8")
	_, n2, _ := net.ParseCIDR("192.168.1.0/24")
	got := ipNetListToStrings([]*net.IPNet{n1, nil, n2})
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
	if got := wrapList("DNS", nil, 80); got != nil {
		t.Errorf("nil items: want nil, got %v", got)
	}
	if got := wrapList("DNS", []string{}, 80); got != nil {
		t.Errorf("empty items: want nil, got %v", got)
	}
	got := wrapList("DNS", []string{"a.example.com", "b.example.com"}, 80)
	if len(got) != 1 {
		t.Fatalf("short list should fit one line, got %d: %v", len(got), got)
	}
	if !strings.HasPrefix(got[0], "DNS: ") {
		t.Errorf("expected prefix 'DNS: ', got %q", got[0])
	}
	// Force wrapping with very small width
	got2 := wrapList("DNS", []string{"aaaa", "bbbb", "cccc"}, 12)
	if len(got2) < 2 {
		t.Errorf("expected wrap into >=2 lines, got %d: %v", len(got2), got2)
	}
}

// ============================================================================
// hasAnyNameConstraints
// ============================================================================

func TestHasAnyNameConstraints(t *testing.T) {
	if hasAnyNameConstraints(nil) {
		t.Error("nil cert should be false")
	}
	if hasAnyNameConstraints(&x509.Certificate{}) {
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
		if !hasAnyNameConstraints(c) {
			t.Errorf("case %d: expected true", i)
		}
	}
}

// ============================================================================
// isSelfSigned
// ============================================================================

func TestIsSelfSigned(t *testing.T) {
	if isSelfSigned(nil) {
		t.Error("nil cert: should be false")
	}
	root, key := selfSignedRoot(t, "Root")
	if !isSelfSigned(root) {
		t.Error("self-signed root: should be true")
	}
	leaf, _ := issuedCert(t, "leaf", root, key)
	if isSelfSigned(leaf) {
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

	if _, ok := findParentInListCert(nil, []*x509.Certificate{root}); ok {
		t.Error("nil child: expected not found")
	}
	if _, ok := findParentInListCert(leaf, nil); ok {
		t.Error("nil pool: expected not found")
	}
	if _, ok := findParentInListCert(leaf, []*x509.Certificate{other}); ok {
		t.Error("wrong parent: expected not found")
	}
	parent, ok := findParentInListCert(leaf, []*x509.Certificate{nil, other, root})
	if !ok {
		t.Fatal("expected to find root as parent")
	}
	if parent != root {
		t.Errorf("got wrong parent: %s", cnOrDN(parent))
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
	crl, err := parseRevocationListFromData(der)
	if err != nil {
		t.Fatalf("DER parse: %v", err)
	}
	if crl.Number.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("DER: wrong number")
	}

	// PEM input
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	crl2, err := parseRevocationListFromData(pemBytes)
	if err != nil {
		t.Fatalf("PEM parse: %v", err)
	}
	if crl2.Number.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("PEM: wrong number")
	}

	// Garbage input
	if _, err := parseRevocationListFromData([]byte("not a crl")); err == nil {
		t.Error("garbage: expected error")
	}
}

// ============================================================================
// buildBundleFromVerifiedChains
// ============================================================================

func TestBuildBundleFromVerifiedChains(t *testing.T) {
	root, rootKey := selfSignedRoot(t, "Root")
	inter, interKey := issuedCert(t, "Inter", root, rootKey)
	leaf, _ := issuedCert(t, "leaf", inter, interKey)

	chain := [][]*x509.Certificate{{leaf, inter, root}}

	// without root
	out := buildBundleFromVerifiedChains(chain, false)
	if len(out) != 1 || out[0] != inter {
		t.Errorf("includeRoot=false: expected [inter], got %d certs", len(out))
	}

	// with root
	out2 := buildBundleFromVerifiedChains(chain, true)
	if len(out2) != 2 || out2[0] != inter || out2[1] != root {
		t.Errorf("includeRoot=true: expected [inter, root], got %d certs", len(out2))
	}

	// dedup across multiple chains
	chains := [][]*x509.Certificate{{leaf, inter, root}, {leaf, inter, root}}
	out3 := buildBundleFromVerifiedChains(chains, true)
	if len(out3) != 2 {
		t.Errorf("dedup: expected 2 unique, got %d", len(out3))
	}
}

// ============================================================================
// buildBundleFromDiscovered
// ============================================================================

func TestBuildBundleFromDiscovered(t *testing.T) {
	root, _ := selfSignedRoot(t, "Root")
	inter1, _ := selfSignedRoot(t, "Inter1") // distinct cert (just need .Raw)
	inter2, _ := selfSignedRoot(t, "Inter2")

	out := buildBundleFromDiscovered([]*x509.Certificate{inter1, nil, inter2, inter1}, []*x509.Certificate{root}, false)
	if len(out) != 2 {
		t.Errorf("includeRoot=false: expected 2 (deduped), got %d", len(out))
	}

	out2 := buildBundleFromDiscovered([]*x509.Certificate{inter1, inter2}, []*x509.Certificate{root, nil}, true)
	if len(out2) != 3 {
		t.Errorf("includeRoot=true: expected 3, got %d", len(out2))
	}
}

// ============================================================================
// aliasFlags / hidden alias filtering
// ============================================================================

func TestAliasFlagsBindsSameValue(t *testing.T) {
	// Use a fresh FlagSet to avoid polluting the global flag set
	saved := flag.CommandLine
	savedAliases := hiddenAliasFlags
	t.Cleanup(func() {
		flag.CommandLine = saved
		hiddenAliasFlags = savedAliases
	})
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	hiddenAliasFlags = make(map[string]struct{})

	canonical := flag.Int("max-foo", 100, "max foo")
	aliasFlags(map[string]string{"maxfoo": "max-foo"})

	if _, ok := hiddenAliasFlags["maxfoo"]; !ok {
		t.Error("alias not registered in hiddenAliasFlags")
	}

	// Setting via alias must mutate canonical
	if err := flag.CommandLine.Parse([]string{"-maxfoo", "999"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if *canonical != 999 {
		t.Errorf("alias did not mutate canonical: got %d, want 999", *canonical)
	}
}

func TestAliasFlagsPanicsOnUnknownCanonical(t *testing.T) {
	saved := flag.CommandLine
	savedAliases := hiddenAliasFlags
	t.Cleanup(func() {
		flag.CommandLine = saved
		hiddenAliasFlags = savedAliases
	})
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	hiddenAliasFlags = make(map[string]struct{})

	defer func() {
		if recover() == nil {
			t.Error("expected panic for unknown canonical")
		}
	}()
	aliasFlags(map[string]string{"alias": "nonexistent"})
}

func TestPrintDefaultsExcludingAliases(t *testing.T) {
	saved := flag.CommandLine
	savedAliases := hiddenAliasFlags
	t.Cleanup(func() {
		flag.CommandLine = saved
		hiddenAliasFlags = savedAliases
	})
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	hiddenAliasFlags = make(map[string]struct{})

	flag.Int("max-foo", 100, "max foo")
	flag.String("type", "any", "validation type")
	flag.Bool("crl", false, "enable CRL")
	aliasFlags(map[string]string{"maxfoo": "max-foo"})

	var buf strings.Builder
	printDefaultsExcludingAliases(&buf)
	out := buf.String()

	if !strings.Contains(out, "-max-foo") {
		t.Error("canonical -max-foo should be present")
	}
	if strings.Contains(out, "-maxfoo") {
		t.Errorf("alias -maxfoo should NOT appear in help output, got:\n%s", out)
	}
	// int default bare
	if !strings.Contains(out, "(default 100)") {
		t.Errorf("expected bare int default '(default 100)', got:\n%s", out)
	}
	// string default quoted
	if !strings.Contains(out, `(default "any")`) {
		t.Errorf("expected quoted string default '(default \"any\")', got:\n%s", out)
	}
	// bool default omitted (zero value)
	if strings.Contains(out, "(default false)") {
		t.Errorf("zero-value bool default should be omitted, got:\n%s", out)
	}
}

// ============================================================================
// isZeroValueFlag
// ============================================================================

func TestIsZeroValueFlag(t *testing.T) {
	saved := flag.CommandLine
	t.Cleanup(func() { flag.CommandLine = saved })
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)

	flag.Int("i", 0, "")
	flag.String("s", "", "")
	flag.Bool("b", false, "")

	fi := flag.Lookup("i")
	fs := flag.Lookup("s")
	fb := flag.Lookup("b")

	if !isZeroValueFlag(fi, "0") {
		t.Error("int 0 should be zero")
	}
	if isZeroValueFlag(fi, "5") {
		t.Error("int 5 should NOT be zero")
	}
	if !isZeroValueFlag(fs, "") {
		t.Error("empty string should be zero")
	}
	if isZeroValueFlag(fs, "x") {
		t.Error("non-empty string should NOT be zero")
	}
	if !isZeroValueFlag(fb, "false") {
		t.Error("false bool should be zero")
	}
	if isZeroValueFlag(fb, "true") {
		t.Error("true bool should NOT be zero")
	}
}

// ============================================================================
// Compile-time checks
// ============================================================================

var _ io.Writer = (*strings.Builder)(nil) // ensure strings.Builder is io.Writer
