package main

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"time"

	"github.com/andrico21/x509-cert-validator/internal/certinfo"
)

// emitJSON writes v as indented JSON to stdout. Shared by the -json output
// of validate, inspect, and split. encoding/json escapes control characters
// (ESC -> \u001b) and HTML-significant runes, so untrusted certificate
// fields cannot inject terminal escape sequences through JSON output.
func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// expiryJSON is the leaf-expiry summary embedded in validate -json output.
type expiryJSON struct {
	DaysRemaining int  `json:"days_remaining"`
	Expired       bool `json:"expired"`
	Expiring      bool `json:"expiring"`
	ThresholdDays int  `json:"threshold_days"`
}

// validateJSON is the -json document emitted by the validate operation.
// Error is populated (and OK is false) on failure; Leaf/Chains/Expiry are
// present on success.
type validateJSON struct {
	OK             bool                  `json:"ok"`
	Error          string                `json:"error,omitempty"`
	ValidationTime time.Time             `json:"validation_time"`
	RootTrust      string                `json:"root_trust,omitempty"`
	Leaf           *certinfo.CertInfo    `json:"leaf,omitempty"`
	Chains         [][]certinfo.CertInfo `json:"chains,omitempty"`
	CRLChecked     bool                  `json:"crl_checked"`
	Expiry         *expiryJSON           `json:"expiry,omitempty"`
}

// chainsToInfos converts verified chains (leaf-first) into CertInfo rows for
// JSON output, deriving each cert's role from its position.
func chainsToInfos(chains [][]*x509.Certificate, now time.Time, days int) [][]certinfo.CertInfo {
	out := make([][]certinfo.CertInfo, 0, len(chains))
	for _, ch := range chains {
		infos := make([]certinfo.CertInfo, 0, len(ch))
		for i, c := range ch {
			infos = append(infos, certinfo.FromCert(c, i, now, days))
		}
		out = append(out, infos)
	}
	return out
}
