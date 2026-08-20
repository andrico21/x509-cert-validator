# 1.5.3 - Consistent export scope + help on stdout

A patch release that removes two `-export` surprises and fixes where `-h` writes.

## Fixes

- `-export-scope ca` now behaves the same in both modes: it selects the CA certificates, excludes the leaf, and excludes the self-signed root unless `-include-root` is set. Previously `-inspect` exported every loaded CA (including any root) and silently ignored `-include-root`, while validate excluded the root by default, so the same flags meant different things.
- `-h`, `-?`, `-help`, and `--help` now write the help screen to stdout and exit 0, so `tool -h | grep ...` works without `2>&1`. Usage shown on a bad flag still goes to stderr with a non-zero exit.

## Changes

- `-inspect -export` prints a one-line hint when the result has no trust-anchor root: either add `-include-root` (a root was loaded but excluded by `ca` scope), or validate instead (a TLS server does not send the root, so only validate resolves it from the trust store).
- README documents the per-mode `-export` semantics and the stdout/stderr routing.

## Notes

- No change to what validate mode exports, and `-export-scope all` still emits every certificate the operation has (the full verified chain in validate; the loaded certs in inspect).

## Build

```shell
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.5.3" \
  -o ./x509-cert-validator ./cmd/x509-cert-validator
```

## Verification

`go test ./...` plus the `tests.sh` integration suite. All CI gates green: gofmt, vet, staticcheck, gosec, govulncheck, unit tests, CodeQL, and the openssl-backed integration suite.
