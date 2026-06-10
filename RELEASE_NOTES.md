# 1.3.0 — Bugfix round: diagnostics accuracy, strict-CRL correctness, output hardening

Twelve fixes from a full second-round code review (validated by two independent reviewer passes). Mostly diagnostic-accuracy and robustness fixes; four deliberate behavior changes are called out below.

## Behavior changes

- **`-crl` strict mode**: an issuer whose KeyUsage extension lacks `cRLSign` while the child declares CRLDistributionPoints is now a **hard failure** (previously: warning + `CRL CHECK PASSED`, silently weakening strict mode). Per RFC 5280 §4.2.1.3, an issuer with **no KeyUsage extension at all** (common on legacy roots) is still treated as CRL-sign capable.
- **`-h` / `--help`** now exits **0** (stdlib convention) and no longer prints `flag: help requested` noise. Unknown flags still exit 2.
- **Self-signed detection is topological**: self-signed **non-CA** certificates (e.g. `openssl req -x509` with `CA:FALSE`) and SHA1-self-signed certificates are now correctly labeled `(self-signed)` and receive the "use `-root` to trust it explicitly" tip.
- **`-silent -show-graph`** no longer prints the ASCII graph; `-silent` output is exactly the single PASS/FAIL line, as documented.

## Fixes

- **Verify-failure hints**: hostname-mismatch and key-usage errors are no longer masked by the unsupported/insecure-algorithm CRITICAL HINT when an unrelated loaded certificate carried an unknown algorithm. Algorithm hints still fire for generic failures (e.g. a GOST intermediate behind an "unknown authority" error).
- **`-at` consistency**: heuristic expiry warnings now use the `-at` validation time instead of the wall clock, so Heuristic Analysis and chain verification agree on what "expired" means.
- **Terminal escape hardening**: all output paths sanitize untrusted certificate fields (CNs, DNs, SANs, URLs); C0 control characters (except `\n`, `\r`, `\t`) and DEL are replaced with `U+FFFD`, preventing ANSI escape injection from hostile certificates.
- **Display**: `Truncate` no longer panics on very small widths and never splits multibyte UTF-8 characters in certificate names.
- **Bundle export**: `-create-ca-bundle` writes through a randomly named same-directory temp file; a pre-existing user file named `<bundle>.tmp` is no longer truncated or deleted. Output keeps the documented 0644 mode and the atomic rename.
- **Size limits**: `-max-*` values at the extreme top of the int64 range no longer overflow internally (previously caused an empty read and a misleading "no certificates found" error).
- **`-sni` IPv6**: `-sni "[::1]:443"` now extracts `::1`, and a bare `-sni ::1` is no longer mangled into `":"`. (Note: RFC 6066 forbids IP literals in SNI; Go omits SNI for IPs — these inputs are diagnostic-only.)

## Internals / tests

- New unit tests for `internal/crl` (cRLSign hard-fail, RFC 5280 carve-out, revoked-serial detection via httptest), `internal/bundle` (atomic write, no-clobber), `internal/display`, `internal/x509util`, `internal/certload`, plus CLI help/exit-code and hint-ordering tests. Packages `crl`, `bundle`, `certload`, `display`, `x509util` previously had no package-local tests.
- Dead code removed: `cli.ParseError.PrintUsage` field and its no-op branch in `main`.

## Backward Compatibility

Flag surface unchanged; all legacy camelCase flag spellings (`-createCAbundle`, `-includeRoot`, `-showGraph`, `-ultrasilent`, `-maxaia`, `-maxcrl`, `-maxlocal`, `-maxcert`) continue to work as hidden aliases. Scripts that relied on `-crl` passing despite a cRLSign-less issuer, or on `-h` exiting 2, must adapt (see behavior changes above).

## Build

```shell
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.3.0" \
  -o ./x509-cert-validator ./cmd/x509-cert-validator
```

## Verification

Unit suite extended this release (`go test ./...`). `tests.sh` exercises 30 end-to-end scenarios covering every legacy flag spelling, AIA fetch, CRL check, bundle export, error paths, and live HTTPS probe behavior. All pass against this release.
