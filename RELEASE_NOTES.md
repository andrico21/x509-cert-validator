# 1.6.0 - machine-visible diagnostics, terminal-safe fields, gated releases

This release closes a set of findings from a security audit of the whole repository. The theme is
the one the audit named: in every case the cryptographic verification was already correct, but what
the tool *reported* about it was not. Machine consumers could not see a skipped hostname check, a
trust anchor fetched over an unauthenticated channel, or a CA bundle containing a certificate
outside the verified chain.

**Read the breaking changes before upgrading a script or CI job.** The verdict semantics are
unchanged - every certificate that validated before still validates, and no exit code changes
except the one noted - but the `-json` document gained a field, `-json` stdout became strictly a
document, and one export configuration that used to write a file now writes nothing.

## Breaking changes

- **`-json` validate gains `hostname_checked`, always present.** It records whether a hostname check
  *ran* - not whether it passed. `true` when `-dns` or `-sni` supplied a name to verify against.
  Previously a chain-only success and a hostname-verified success produced byte-identical output, so
  automation could not tell an unverified endpoint from a verified one. A check that ran and failed
  is `"ok": false` with `"hostname_checked": true`; the outcome is in `ok`/`error`. A strict-schema
  consumer that rejects unknown keys will need updating. `dns_name` and `warnings` are also added,
  both omitted when empty.
- **`-json` stdout is now the document and nothing else.** AIA and CRL diagnostics used to print to
  stdout *above* the JSON, so a run against a certificate declaring a non-`http(s)` CRL
  distribution point emitted a stream that did not parse. Since the distribution-point list comes
  from the certificate, an attacker chose when a consumer's parse broke. Security-relevant
  diagnostics now travel in `warnings`; progress narration (`Fetching CRL for...`, `Using cached
  CRL...`) is suppressed under `-json` with no replacement.
- **`-export-scope ca` no longer falls back to unverified certificates.** When the verified chain is
  just `[leaf, anchor]` and `-include-root` is not set, the CA scope is legitimately empty. The
  previous behaviour silently substituted certificates collected during loading - including any
  fetched from a certificate-declared AIA URL, even one the tool had already reported as not
  matching the expected issuer. That configuration now writes nothing and says so. Use
  `-export-scope all` or `-include-root` for a non-empty artifact.
- **`-at 0001-01-01T00:00:00Z` is now rejected (exit 1) instead of silently evaluating at the wall
  clock.** This is the only exit-code change. The instant cannot be honoured: `crypto/x509`
  documents `VerifyOptions.CurrentTime` as "if zero, the current time is used" and implements
  exactly that, so passing it through would report a `validation_time` the verification did not
  use. It is refused at parse time with a message naming the reason. Every other instant is
  unaffected, including `0001-01-02T00:00:00Z`. The input matters because
  `var t time.Time; t.Format(time.RFC3339)` produces precisely that string - it is what a wrapper
  emits when its timestamp variable was never populated.

## Changes

- **Certificate fields can no longer forge or corrupt terminal output.** The sanitizer replaced only
  C0 controls and DEL, so 8-bit C1 controls passed through verbatim - a CN carrying U+009B (CSI)
  could erase part of the diagnostic in a terminal that decodes C1, and a CN carrying LF/CR could
  render as extra physical lines styled like the tool's own output. Untrusted values now pass
  through a strict field sanitizer (C0, DEL, C1, LF, CR, TAB all replaced with U+FFFD) *before*
  they are composed into a message, across the inspect table, `-full` detail, validate chain
  output, `-silent` PASS/FAIL lines, short IDs, name constraints, and `-show-graph`. Graph box
  widths are computed after sanitization, so borders no longer misalign on such input.
- **A trust anchor fetched over the network is announced, with its full SHA-256 fingerprint.**
  `-root` accepts an `http(s)://` source, and `-root https://` is deliberately a live probe (that
  is what makes fetching a private root from the server it anchors possible). The transport is not
  authenticated, and the existing skipped-verification warning was gated on `-cert`, so it could
  never fire for `-root`. It now does.
- **Diagnostic hints are no longer steerable by certificate text.** Algorithm rejections were
  classified by substring, and `crypto/x509` echoes certificate field values into parse errors - so
  a SAN URI of `http://insecure algorithm.example/` in *any* certificate in a bundle could replace
  the correct "provide intermediates" hint on an unrelated leaf with a false SHA1/MD5 claim.
  Classification is now type-first (`errors.As`/`errors.Is`), with exact full-message matching for
  the two parse-stage messages `crypto/x509` returns as untyped errors. The parse-stage insecure
  check is removed entirely: `x509.InsecureAlgorithmError` is returned only from the signature
  check, so a parse error could never legitimately be one.
- **Directory scans skip non-regular entries.** A FIFO in a scanned directory blocked `os.Open`
  indefinitely, before any size cap applied. Entries are filtered with `os.Stat` (which follows
  symlinks, so a directory of symlinked certificates keeps working) and non-regular entries are
  skipped with a warning.
- **Releases are gated.** A tag push selected only the release workflow, so no lint, vet,
  staticcheck, gosec, govulncheck, unit-test or `tests.sh` step ran for the event that authorizes a
  publication - while the release body claimed they had. The three gate jobs now live in a reusable
  workflow that both `go.yml` and `release.yml` call, and the release job runs only after they pass.

## Notes

- The project still has no third-party dependencies: `go.mod` has no `require` block and `go.sum` is
  empty.
- `warnings` carries decisions and inferences about untrusted input - an anchor fetched over the
  network, an input not marked CA, an unsupported CRL/AIA scheme, an AIA issuer mismatch, a skipped
  file, an empty export. It deliberately does **not** duplicate facts already structured elsewhere
  in the document (expiry, key and signature algorithm, SAN presence), and does not carry progress
  narration.
- `-silent` and `-ultra-silent` are unchanged: `-silent` still emits one PASS/FAIL line,
  `-ultra-silent` still emits nothing at all.
- The integration suite grew from 43 to 55 cases, covering each of the above.

## Build

```shell
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.6.0" \
  -o ./x509-cert-validator ./cmd/x509-cert-validator
```

## Verification

Verified locally before tagging: `go test -count=1 ./...`, `go vet ./...`, `gofmt -d` clean,
`staticcheck ./...`, `gosec -quiet ./...`, `govulncheck ./...`, and `./tests.sh` (55/55 against
OpenSSL 3.5.5). The tag push runs the same gate set on the tagged revision and then builds and
publishes the release artifacts; the gates also run on `main` and on pull requests.
