# 1.5.2 - Go 1.27.0 toolchain

A maintenance patch. No behavior or flag changes.

## Changes

- Built with the Go 1.27.0 toolchain (was 1.26.6). Release binaries now report `go1.27.0` at runtime. The project has no third-party dependencies, so there is nothing else to update.

## Build

```shell
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.5.2" \
  -o ./x509-cert-validator ./cmd/x509-cert-validator
```

## Verification

`go test ./...` plus the `tests.sh` integration suite. All CI gates green: gofmt, vet, staticcheck, gosec, govulncheck, unit tests, CodeQL, and the openssl-backed integration suite, all on Go 1.27.0.
