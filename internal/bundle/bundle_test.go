package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func genSelfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func countPEMCertBlocks(t *testing.T, data []byte) int {
	t.Helper()
	n := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return n
		}
		if block.Type == "CERTIFICATE" {
			n++
		}
	}
}

func TestWritePEMRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.crt")
	a := genSelfSigned(t, "A")
	b := genSelfSigned(t, "B")

	written, rootsWritten, err := WritePEM(path, []*x509.Certificate{a, b, a /* dup */, nil})
	if err != nil {
		t.Fatalf("WritePEM: %v", err)
	}
	if written != 2 {
		t.Errorf("written: want 2, got %d", written)
	}
	if rootsWritten != 2 {
		t.Errorf("rootsWritten: want 2 (both self-signed), got %d", rootsWritten)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := countPEMCertBlocks(t, data); got != 2 {
		t.Errorf("PEM blocks: want 2, got %d", got)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o644 {
			t.Errorf("perm: want 0644, got %o", perm)
		}
	}
}

// Regression for Fix 10: a pre-existing user file named exactly
// "<path>.tmp" must survive a successful bundle write (the old code
// truncated and renamed/deleted it).
func TestWritePEMDoesNotClobberPreexistingTmpFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.crt")
	sentinelPath := path + ".tmp"
	if err := os.WriteFile(sentinelPath, []byte("sentinel"), 0o644); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	if _, _, err := WritePEM(path, []*x509.Certificate{genSelfSigned(t, "A")}); err != nil {
		t.Fatalf("WritePEM: %v", err)
	}

	data, err := os.ReadFile(sentinelPath)
	if err != nil {
		t.Fatalf("sentinel gone: %v", err)
	}
	if string(data) != "sentinel" {
		t.Errorf("sentinel content changed: %q", data)
	}
}

func TestWritePEMFailureLeavesNoStrayTempFiles(t *testing.T) {
	dir := t.TempDir()
	// Force the final rename to fail: the destination is an existing
	// directory.
	path := filepath.Join(dir, "iamadir")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	_, _, err := WritePEM(path, []*x509.Certificate{genSelfSigned(t, "A")})
	if err == nil {
		t.Fatal("expected rename failure")
	}

	entries, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatalf("readdir: %v", rerr)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("stray temp file left behind: %s", e.Name())
		}
	}
}
