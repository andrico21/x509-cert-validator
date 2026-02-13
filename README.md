# x509-cert-validator
Handy tool to debug certificate-related issues

AI-assisted written code, however it's well-tested.

## Build

```shell
$ go build -trimpath -ldflags="-s -w" -buildmode=pie -o ./cert-validate ./go-cert-validation-tool.go
# or FIPS
$ GOEXPERIMENT=boringcrypto go build -trimpath -ldflags="-s -w" -buildmode=pie -o ./cert-validate-fips ./go-cert-validation-tool.go
```
## Goals
Actually the goal of this tool is to confirm if two x509-related Go libraries validate CA certificate name constraints the same way as OpenSSL below

```shell
$ openssl version
OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)

$ openssl verify -verbose -CAfile ./root.crt -untrusted ./some-issuing-ca.crt -untrusted ./some-other-issuing-ca.crt -policy_check -policy_print -x509_strict -show_chain ./cert.crt
```

## Usage
```shell
Usage of .\cert-validate.exe:
  -aia
        Enable automatic AIA fetching
  -at string
        Optional: Validate at RFC3339 time
  -cert string
        Path to Certificate PEM (required)
  -createCAbundle string
        Optional: Path to create/export the discovered CA bundle
  -crl
        Enable CRL revocation checking
  -dns string
        Optional: Verify specific DNS name
  -includeRoot
        Include Root CA in the generated bundle
  -root string
        Path to Root CA PEM (optional; uses System Roots if empty)
  -type string
        Validation type: server, client, or any (default "any")
```

## Automatic retrieval of CA certificates
```shell
cert-validate.exe -root \Temp\root.crt -cert \Temp\some-cert.crt -aia
```

### Automatic generation of CA bundle
```shell
cert-validate.exe -cert \Temp\cert.crt -aia -createCAbundle .\cabundle.crt -includeRoot
```