# 1.2.0 — Architecture refactor + security & CI hardening

This release rolls up six PRs focused on internal quality. **No user-visible behavior changes**: output format, exit codes, and flag surface remain identical (legacy camelCase flag spellings are retained as hidden aliases).

## Highlights

- **Package layout standardized**: `cmd/x509-cert-validator/` for the entry point + nine focused `internal/` packages (`x509util`, `display`, `bundle`, `errs`, `validator`, `certload`, `aia`, `crl`, `cli`).
- **Architecture**: `Validator` struct owns a single shared `*http.Client` (one connection pool across every AIA + CRL fetch in a run), a `Logger` interface, per-fetch timeout, and download size caps.
- **Network safety**: full `context.Context` plumbing through every HTTP/TLS path, with both a global wall-clock budget and per-fetch timeouts; whichever fires first wins.
- **Security signals**:
  - HTTPS live probe without `-dns`/`-sni` now prints a loud one-line warning so silent hostname-skip can't surprise operators.
  - AIA-fetched certs are name- and signature-bound to the requesting child; mismatches are logged but still added to the diagnostic pool.
  - CRL Issuer DN is bound to the parent CA Subject DN before signature verification; mismatched CRLs are skipped with a clear reason.
  - Empty trust pool fallback is now flagged at verification time (not just load time).
- **Crypto / size hygiene**: full SHA-256 used for CRL pair-deduplication; atomic bundle writer with explicit `0644` mode; non-`http(s)` AIA/CRL URLs surfaced explicitly.
- **CI hardening**: strict `gofmt -d`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, with per-call-site `#nosec` annotations for intentional diagnostic uses of MD5 / SHA-1 / file-path-from-flag.
- **Tests**: 23 Go unit tests (across `cmd/` and `internal/cli`) + 30 integration tests in `tests.sh`.
- **Toolchain**: Go 1.26.3.

## Pull Requests Included

| PR | Title |
|----|-------|
| [#3](https://github.com/andrico21/x509-cert-validator/pull/3) | PR1 — Security & correctness quick wins |
| [#4](https://github.com/andrico21/x509-cert-validator/pull/4) | PR2 — CI hardening + strict linters |
| [#5](https://github.com/andrico21/x509-cert-validator/pull/5) | PR3 — kebab-case flag rename + backward-compat aliases |
| [#6](https://github.com/andrico21/x509-cert-validator/pull/6) | PR4 — 18 unit tests on pure helpers |
| [#7](https://github.com/andrico21/x509-cert-validator/pull/7) | PR5a — Context plumbing through HTTP/TLS fetch helpers |
| [#8](https://github.com/andrico21/x509-cert-validator/pull/8) | PR5b — Package split into `cmd/` + `internal/*` and `Validator` struct |

## Backward Compatibility

All legacy camelCase flag spellings (`-createCAbundle`, `-includeRoot`, `-showGraph`, `-ultrasilent`, `-maxaia`, `-maxcrl`, `-maxlocal`, `-maxcert`) continue to work as hidden aliases. Scripts written against earlier releases require no changes.

## Build

```shell
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.2.0" \
  -o ./x509-cert-validator ./cmd/x509-cert-validator
```

## Verification

`tests.sh` exercises 30 end-to-end scenarios covering every legacy flag spelling, AIA fetch, CRL check, bundle export, error paths, and live HTTPS probe behavior. All 30 pass against this release.
