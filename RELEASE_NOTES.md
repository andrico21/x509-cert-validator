# 1.4.0 - Inspect, split, JSON output, and an expiry gate

A feature release adding three ergonomic I/O capabilities alongside the chain validator. Everything is a plain flag - no subcommands - and the default `validate` behavior is unchanged, so every existing invocation and script keeps working.

## New: operations

- **`-inspect`** - describe certificate(s) without validating a chain. Colour-coded summary table (role, subject, issuer, expiry status, SHA-256); `-full` adds a per-cert detail block. Accepts a file, a **directory**, a multi-cert bundle, `-` for **stdin**, or an `http(s)://` URL.
- **`-split`** - decompose a bundle (or directory/stdin) into one PEM file per certificate under `-outdir` (default `certs`); `-split-name` picks `index` (default) or `subject` naming.

## New: output & expiry

- **`-json`** - stable machine-readable output for all three operations (validate → verdict + leaf + chains + expiry; inspect → cert array; split → written-files manifest). Mutually exclusive with `-silent`/`-ultra-silent`.
- **`-days N` + `-fail-expired`** - expiry gate; `-days` sets the "expiring" window (default 30), `-fail-expired` makes the process **exit 2** if any cert is expired. Pairs with `-ultra-silent` for a pure exit-code check in cron/CI.
- **`-no-color`** (and `NO_COLOR`) disable ANSI colour in the inspect table.

## New: input sources

`-cert` now also accepts a **directory** and `-` for **stdin**, in addition to file / `http(s)://` download / `https://` live probe. (Validation still needs a single leaf; directory input is for `-inspect`/`-split`.)

## Exit codes

`0` success · `1` error / invalid · `2` `-fail-expired` and a certificate is expired.

## Internals / tests

- New `internal/certinfo` package: the machine-readable `CertInfo` view shared by JSON and table renderers, so human and machine output never drift.
- Parse-time validation rejects conflicting flags (`-inspect`+`-split`, more than one output format, an unknown `-split-name`).
- Unit tests for `internal/certinfo` and the new CLI flags; `tests.sh` extended to 43 scenarios (inspect/split/json/stdin/expiry/error cases 31-43).
- Toolchain/CI: Go directive 1.26.6, gosec 2.28.0, `actions/checkout`/`setup-go` v7.

## Backward compatibility

The default `validate` operation and its full flag surface are unchanged; legacy camelCase aliases (`-createCAbundle`, `-includeRoot`, `-showGraph`, `-ultrasilent`, `-maxaia`, `-maxcrl`, `-maxlocal`, `-maxcert`) still work as hidden aliases. The new flags are purely additive.

## Build

```shell
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.4.0" \
  -o ./x509-cert-validator ./cmd/x509-cert-validator
```

## Verification

`go test ./...` plus the 43-scenario `tests.sh` integration suite. All CI gates green: gofmt, vet, staticcheck, gosec 2.28.0, govulncheck, unit tests, and the openssl-backed integration suite.
