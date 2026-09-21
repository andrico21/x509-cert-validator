# 1.5.4 - Go 1.27.1 and lint tool pins

A maintenance patch. No behavior, flag, or output changes.

## Changes

- Built with the Go 1.27.1 toolchain (was 1.27.0). Release binaries now report `go1.27.1` at runtime. Every workflow reads the Go version from `go-version-file: go.mod`, so this single line is what pins the toolchain used by the lint, build, integration, release, and CodeQL jobs.
- staticcheck: the temporary dev-commit pin (`v0.7.0-0.dev.0.20260630164810-d69e7ee19e2d`) is replaced by the tagged release `2026.2.1` (module tag v0.8.1). That is the release that added Go 1.27 support, which is why the dev-commit workaround existed. It stays pinned to an exact tag rather than `@latest` so CI stays reproducible.
- gosec: `v2.28.0` to `v2.29.0`.

## Notes

- The dev-commit staticcheck pin was the last place a CI gate ran on moving, unreleased tooling; linting now runs entirely on released versions.
- The project still has no third-party dependencies: `go.mod` has no `require` block and `go.sum` is empty, so there is nothing else to update.

## Build

```shell
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.5.4" \
  -o ./x509-cert-validator ./cmd/x509-cert-validator
```

## Verification

Verified locally before tagging: `go test -count=1 ./...`, `go vet ./...`, `gofmt -d` clean, `staticcheck ./...`, `gosec -quiet ./...`, `govulncheck ./...`. The tag push runs the same gate set on the tagged revision and then builds and publishes the release artifacts; the gates also run on `main` and on pull requests.
