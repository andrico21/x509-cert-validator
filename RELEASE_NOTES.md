# 1.5.1 - Help precedence fix

A patch release. The flag surface is unchanged from 1.5.0.

## Fixes

- `-h`, `-?`, `-help`, `--help`, and `--?` now always show help and exit 0, even when the token is positioned where a string flag would otherwise consume it as its value (e.g. `-export -?`, `-cert -h`). Previously such a token was swallowed as the flag's value and the tool ran the full validate/inspect flow instead of showing help. A help pre-scan now runs before flag parsing.

## Changes

- Deprecated flag-name aliases kept for backward compatibility are still silently accepted, but are no longer shown in `-h` output or the documentation.

## Build

```shell
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.5.1" \
  -o ./x509-cert-validator ./cmd/x509-cert-validator
```

## Verification

`go test ./...` plus the `tests.sh` integration suite (help-precedence cases 46-49 added). All CI gates green: gofmt, vet, staticcheck, gosec, govulncheck, unit tests, CodeQL, and the openssl-backed integration suite.
