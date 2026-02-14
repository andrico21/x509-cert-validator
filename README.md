# x509-cert-validator
Handy tool to debug certificate-related issues

AI-assisted written code, however it's well-tested.

## Build

```shell
$  go build -trimpath -ldflags="-s -w" -buildmode=pie -o ./x509-cert-validator ./x509-cert-validator.go
# or FIPS
$ GOEXPERIMENT=boringcrypto  go build -trimpath -ldflags="-s -w" -buildmode=pie -o ./x509-cert-validator ./x509-cert-validator.go
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
Usage of ./x509-cert-validator:
  -aia
        Enable automatic AIA fetching
  -at string
        Optional: Validate at RFC3339 time
  -cert string
        Path to Certificate PEM, HTTP URL (download), or HTTPS URL (live probe)
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
  -showGraph
        Display ASCII graph of the verified chain
  -silent
        Output only pass/fail status and cert ID
  -type string
        Validation type: server, client, or any (default "any")
  -ultrasilent
        No output, exit code only (0=Pass, 1=Fail)

EXAMPLES:
  1. Live HTTPS Probe (Check server's current chain):
     cert-validate -cert https://github.com

  2. Validate a Remote Certificate File (e.g., from an AIA URL):
     cert-validate -cert http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt

  3. Validation with Specific Constraints (-dns, -at, -type, -crl):
     cert-validate -cert leaf.pem -dns example.com -at "2025-12-25T12:00:00Z"
     cert-validate -cert client-cert.pem -type client
     cert-validate -cert leaf.pem -crl

  4. Fix Local Chain & Export Bundle:
     cert-validate -cert leaf.pem -aia -createCAbundle full-chain.crt

  5. Exporting Root CA (-includeRoot):
     cert-validate -cert leaf.pem -aia -createCAbundle bundle.crt -includeRoot
     (⚠️  SECURITY WARNING: This also exports the Root CA certificate.)
     (    Never install an unknown Root CA unless you know what you are doing)
     (    and have verified its fingerprint manually.)
     (    Trusting a malicious Root might lead to interception of your private data.)

  6. Visualization:
     cert-validate -cert leaf.pem -showGraph

  7. Silent Mode (Short status line only):
     cert-validate -cert leaf.pem -silent
     > PASS [github.com] Serial:12345...

  8. Ultra Silent (Exit code only):
     cert-validate -cert leaf.pem -ultrasilent
     (echo $?)
```

## Validating of sample certificate (from Go website)
```shell
./x509-cert-validator -cert test.crt -aia -crl
Runtime: go1.26.0
Validation Time: 2026-02-13T22:56:41+04:00
--- Loading Roots (System) ---
ℹ️  Loaded System Root Store.

=== Target Certificate Certificate Details ===
Subject:     CN=go.dev
Issuer:      CN=WR3,O=Google Trust Services,C=US
Fingerprint: 9a03722804eb0cf1ec2742c68db052b01501e9a47c597d64d41aa6938681a56e
Serial:      286526495291874000263485908549286454672
Validity:    2026-02-10 08:12:27 +0000 UTC to 2026-05-11 09:01:37 +0000 UTC
SAN (DNS):   [go.dev]
AIA (Issuer): [http://i.pki.goog/wr3.crt]
CRL DPs:     [http://c.pki.goog/wr3/PBTgX3IAo5A.crl]

=== Heuristic Analysis ===

=== Automatic AIA Fetching ===
⬇️  Fetching Parent via AIA [1/1]: http://i.pki.goog/wr3.crt
✅ Added fetched certificate: CN=WR3,O=Google Trust Services,C=US
⬇️  Fetching Parent via AIA [1/1]: http://i.pki.goog/r1.crt
ℹ️  Fetched cert is Root CA (GTS Root R1). Stopping fetch.

=== Verifying Chain ===
✅ VALIDATION SUCCEEDED

--- Verified Chain Path 1 ---
[0] Subject: CN=go.dev
    Fingerprint: 9a03722804eb0cf1
  [1] Subject: CN=WR3,O=Google Trust Services,C=US
      Fingerprint: 2fe357db13751ff9
    [2] Subject: CN=GTS Root R1,O=Google Trust Services LLC,C=US
        Fingerprint: d947432abde7b7fa

=== Checking CRLs ===
⬇️  Fetching CRL for 'go.dev' [1/1]: http://c.pki.goog/wr3/PBTgX3IAo5A.crl
   ✅ Valid CRL found via http://c.pki.goog/wr3/PBTgX3IAo5A.crl
⬇️  Fetching CRL for 'WR3' [1/1]: http://c.pki.goog/r/r1.crl
   ✅ Valid CRL found via http://c.pki.goog/r/r1.crl
✅ CRL CHECK PASSED
```

## Automatic retrieval of CA certificates
```shell
cert-validate.exe -root \Temp\root.crt -cert \Temp\some-cert.crt -aia
```

### Automatic generation of CA bundle
```shell
cert-validate.exe -cert \Temp\cert.crt -aia -createCAbundle .\cabundle.crt -includeRoot
```