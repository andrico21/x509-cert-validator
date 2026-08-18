# 1.5.0 - Unified `-export` (replaces `-split` and `-create-ca-bundle`)

A breaking release that consolidates the two overlapping "write certificates to disk" features into a single `-export` interface. The default `validate` behavior and every other flag are unchanged.

## Breaking changes

- Removed `-create-ca-bundle`, `-split`, `-outdir`, `-split-name`, and the hidden `-createCAbundle` alias. Use `-export` and its options instead.

## New: unified `-export`

`-export <dest>` writes certificates to disk on top of the current operation: in the default `validate` mode it exports the verified chain; with `-inspect` it exports the loaded certificates.

- `-export <dest>` selects a file (bundle) or a directory (split).
- `-export-format bundle|split` writes one concatenated PEM file (default) or one file per certificate.
- `-export-scope ca|all` selects the CA chain excluding the leaf (default) or every certificate.
- `-export-name index|subject` picks the split filename scheme: `NN_subject.crt` (default) or `subject.crt` (de-duplicated with a `-N` suffix).
- `-include-root` also emits the root/trust-anchor in `ca` scope (still requires an explicit `-root`).

## Migration

| Old | New |
|---|---|
| `-create-ca-bundle out.pem` | `-export out.pem` |
| `-create-ca-bundle out.pem -include-root -root root.pem` | `-export out.pem -include-root -root root.pem` |
| `-split -cert b.pem -outdir out` | `-inspect -cert b.pem -export out -export-format split -export-scope all` |
| `-split ... -split-name subject` | `... -export-format split -export-name subject` |

## Other changes

- Validate output prints a one-line explanation when multiple verified paths are found (a directly trusted anchor inside the chain yields a separate valid path).
- `-json` no longer emits a split manifest. In `-json` mode the export still writes its files while the JSON document stays the validate/inspect payload.

## Exit codes

`0` success, `1` error / invalid, `2` an expiry gate (`-fail-expired` / `-fail-expiring`) tripped.

## Backward compatibility

The remaining legacy camelCase aliases (`-includeRoot`, `-showGraph`, `-ultrasilent`, `-maxaia`, `-maxcrl`, `-maxlocal`, `-maxcert`) still work as hidden aliases.

## Build

```shell
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.5.0" \
  -o ./x509-cert-validator ./cmd/x509-cert-validator
```

## Verification

`go test ./...` plus the `tests.sh` integration suite. All CI gates green: gofmt, vet, staticcheck, gosec, govulncheck, unit tests, and the openssl-backed integration suite.
