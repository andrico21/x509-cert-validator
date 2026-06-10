# 1.2.1 — Toolchain patch

A maintenance release. **No user-visible behavior changes**: output format, exit codes, and flag surface remain identical to 1.2.0 (legacy camelCase flag spellings are still retained as hidden aliases).

## Changes

- **Toolchain**: `go.mod` directive bumped Go 1.26.3 → 1.26.4, aligning the module with the current Go patch release.
- **Docs**: README build examples updated to reflect the 1.2.1 version string.

## Backward Compatibility

Fully compatible with 1.2.0. All legacy camelCase flag spellings (`-createCAbundle`, `-includeRoot`, `-showGraph`, `-ultrasilent`, `-maxaia`, `-maxcrl`, `-maxlocal`, `-maxcert`) continue to work as hidden aliases. Scripts written against earlier releases require no changes.

## Build

```shell
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.2.1" \
  -o ./x509-cert-validator ./cmd/x509-cert-validator
```

## Verification

`tests.sh` exercises 30 end-to-end scenarios covering every legacy flag spelling, AIA fetch, CRL check, bundle export, error paths, and live HTTPS probe behavior. All 30 pass against this release.
