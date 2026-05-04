# x509-cert-validator
There's no "black magic" here guys: OpenSSL and certutil can do absolutely everything this tool does.

The major difference is convenience. Instead of wrestling with OS-specific flags or deciphering error codes, this is a 1-stop tool designed to give you a clear, human-readable "why" when a certificate fails.

No CLI gymnastics, human-readable results: get a direct explanation instead of "Error 20 at depth 0". The same behavior and output whether you’re on Linux, Windows, or macOS.

It’s just a faster way to validate certificates without the overhead and automatic certificate-bundle creation for lazy-arses.

AI-assisted written code, however it's well-tested.

## Build

```shell
# Development
go build -o ./x509-cert-validator .

# Production (v1.1)
go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.1" \
  -o ./x509-cert-validator .

# Production + FIPS
GOEXPERIMENT=boringcrypto go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.1" \
  -o ./x509-cert-validator .

# Cross-compile (e.g. Linux ARM64)
GOOS=linux GOARCH=arm64 go build -buildmode=pie -trimpath \
  -ldflags="-s -w -X main.version=1.1" \
  -o ./x509-cert-validator-linux-arm64 .
```

Check version:
```shell
./x509-cert-validator -version
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
        Path to Certificate PEM/DER, HTTP URL (download), or HTTPS URL (live probe). Note: file:// is NOT supported.
  -createCAbundle string
        Optional: Path to create/export CA bundle. On success, exports from verified chain(s).
  -crl
        Enable certificate revocation checking (CRL)
  -dns string
        Optional: Verify specific DNS name
  -fp-show-all
        Show alternative fingerprint algo values (+MD5, SHA-384, SHA-512)
  -includeRoot
        Include Root/Trust-Anchor certificate(s) in the generated bundle
  -maxaia int
        Max bytes to download per AIA issuer fetch (default 524288)
  -maxcert int
        Max bytes to download for remote cert file (http/https) (default 524288)
  -maxcrl int
        Max bytes to download per CRL URL (default 20971520)
  -maxlocal int
        Max bytes to read from local cert file (default 1048576)
  -root string
        Path/URL to Root CA PEM/DER (optional; uses System Roots if empty). Supports local path, http(s) download, or https live-probe (same as -cert).
  -showGraph
        Display ASCII graph of the verified chain
  -silent
        Output only pass/fail status and cert ID
  -sni string
        Optional: Override TLS SNI for live HTTPS probes (https://...)
  -type string
        Validation type: server, client, or any (default "any")
  -ultrasilent
        No output, exit code only (0=Pass, 1=Fail)
  -version
        Print version and exit

EXAMPLES:
  1. Live HTTPS Probe (Check server's current chain):
     x509-cert-validator -cert https://github.com

  2. Validate a Remote Certificate File (e.g., from an AIA URL):
     x509-cert-validator -cert http://cacerts.digicert.com/DigiCertGlobalG2TLSRSASHA2562020CA1-1.crt

  3. Validation with Specific Constraints (-dns, -at, -type, -crl):
     x509-cert-validator -cert leaf.pem -dns example.com -at "2025-12-25T12:00:00Z"
     x509-cert-validator -cert client-cert.pem -type client
     x509-cert-validator -cert leaf.pem -crl

  4. Fix Local Chain & Export Bundle:
     x509-cert-validator -cert leaf.pem -aia -createCAbundle full-chain.crt
     Exporting Root CA (-includeRoot) requires explicit specification of root CA's certificate file (-root <filename>).
     x509-cert-validator -cert leaf.pem -aia -createCAbundle bundle.crt -includeRoot -root custom-root-ca.crt
     (⚠️  SECURITY WARNING: This also exports the Root CA certificate.)
     (    Never install an unknown Root CA unless you know what you are doing)
     (    and have verified its fingerprint manually.)
     (    Trusting a malicious Root might lead to interception of your private data.)

  5. Visualization:
     x509-cert-validator -cert leaf.pem -showGraph

  6. Silent Mode (Short status line only):
     x509-cert-validator -cert leaf.pem -silent
     > PASS [github.com] Serial:12345...

  7. Ultra Silent (Exit code only):
     x509-cert-validator -cert leaf.pem -ultrasilent
     (echo $?)
```

## Validating of sample certificate (from Go website) - from file
```shell
./x509-cert-validator -cert test.crt -aia -crl
Runtime: go1.26.0
Validation Time: 2026-02-13T22:56:41+04:00
--- Loading Roots (System) ---
ℹ️  Loaded System Root Store.

=== Target Certificate Certificate Details ===
Subject:     CN=go.dev
Issuer:      CN=WR3,O=Google Trust Services,C=US
FP(sha1):    <sha1 hash>
FP(sha256):  9a03722804eb0cf1ec2742c68db052b01501e9a47c597d64d41aa6938681a56e
Serial:      d7882e5fb8e25988b37a84d4862b36f0
Validity:    2026-02-10 08:12:27 +0000 UTC to 2026-05-11 09:01:37 +0000 UTC
SAN (DNS):   [go.dev]
AIA (Issuer): [http://i.pki.goog/wr3.crt]
CRL DPs:     [http://c.pki.goog/wr3/PBTgX3IAo5A.crl]
Public Key:  ECDSA-P-256(256)
Sig Alg:     SHA256-RSA

=== Heuristic Analysis ===
ℹ️  Leaf Public Key: ECDSA-P-256(256)
ℹ️  Leaf Signature Algorithm: SHA256-RSA

=== Automatic AIA Fetching ===
⬇️  Fetching Parent via AIA [1/1]: http://i.pki.goog/wr3.crt
✅ Added fetched certificate: CN=WR3,O=Google Trust Services,C=US (Key=RSA-2048)
⬇️  Fetching Parent via AIA [1/1]: http://i.pki.goog/r1.crt
ℹ️  Fetched cert is Self-Signed Root (GTS Root R1, Key=RSA-4096). Stopping fetch.

=== Verifying Chain ===
Root Trust: System Trust Store
✅ VALIDATION SUCCEEDED

--- Verified Chain Path 1 ---
[0] Subject: CN=go.dev
    Issuer:  CN=WR3,O=Google Trust Services,C=US
    FP(sha1):   <sha1 hash>
    FP(sha256): 9a03722804eb0cf1ec2742c68db052b01501e9a47c597d64d41aa6938681a56e
    Serial: d7882e5fb8e25988b37a84d4862b36f0
    PubKey: ECDSA-P-256(256)
    SigAlg: SHA256-RSA
    SignedByKey: RSA-2048
  [1] Subject: CN=WR3,O=Google Trust Services,C=US
      Issuer:  CN=GTS Root R1,O=Google Trust Services LLC,C=US
      FP(sha1):   <sha1 hash>
      FP(sha256): 2fe357db13751ff9...
      Serial: <hex serial>
      PubKey: RSA-2048
      SigAlg: SHA256-RSA
      SignedByKey: RSA-4096
    [2] Subject: CN=GTS Root R1,O=Google Trust Services LLC,C=US (self-signed)
        Issuer:  CN=GTS Root R1,O=Google Trust Services LLC,C=US
        FP(sha1):   <sha1 hash>
        FP(sha256): d947432abde7b7fa...
        Serial: <hex serial>
        PubKey: RSA-4096
        SigAlg: SHA384-RSA
        SignedByKey: RSA-4096

=== Checking CRLs ===
⬇️  Fetching CRL for 'go.dev' [1/1]: http://c.pki.goog/wr3/PBTgX3IAo5A.crl
   ℹ️  CRL Signature Verified: SigAlg=SHA256-RSA SignedByKey=RSA-2048 Issuer=WR3
   ✅ Valid CRL checked via http://c.pki.goog/wr3/PBTgX3IAo5A.crl
⬇️  Fetching CRL for 'WR3' [1/1]: http://c.pki.goog/r/r1.crl
   ℹ️  CRL Signature Verified: SigAlg=SHA256-RSA SignedByKey=RSA-4096 Issuer=GTS Root R1
   ✅ Valid CRL checked via http://c.pki.goog/r/r1.crl
✅ CRL CHECK PASSED
```

## Full certificate check - including incorrect DNS name

```shell
./x509-cert-validator -cert https://google.com -dns google.ru -aia -crl -showGraph
Runtime: go1.26.0
Validation Time: 2026-02-15T20:46:39+04:00
--- Loading Roots (System) ---
ℹ️  Loaded System Root Store.
⬇️  Connecting to remote server: google.com:443 ...
✅ Retrieved 3 certificates from server.

ℹ️  Target URL returned 3 certificates. Treating [1..n] as intermediates.
[Server-Sent] e6fe22bf... (CN=WR2, Key=RSA-2048)
[Server-Sent] 3ee0278d... (CN=GTS Root R1, Key=RSA-4096)

=== Target Certificate Certificate Details ===
Subject:     CN=*.google.com
Issuer:      CN=WR2,O=Google Trust Services,C=US
FP(sha1):    <sha1 hash>
FP(sha256):  977eca18f030b2d8f5c6f872e1cf30b5ceea5dcf26ac0bbbcf1723e233e05612
Serial:      2741bdc24e9d339a3340cff0234df4ff
Validity:    2026-01-26 08:39:20 +0000 UTC to 2026-04-20 08:39:19 +0000 UTC
Public Key:  ECDSA-P-256(256)
Sig Alg:     SHA256-RSA
SAN (DNS):   [*.google.com *.appengine.google.com *.bdn.dev *.origin-test.bdn.dev *.cloud.google.com *.crowdsource.google.com *.datacompute.google.com *.google.ca *.google.cl *.google.co.in *.google.co.jp *.google.co.uk *.google.com.ar *.google.com.au *.google.com.br *.google.com.co *.google.com.mx *.google.com.tr *.google.com.vn *.google.de *.google.es *.google.fr *.google.hu *.google.it *.google.nl *.google.pl *.google.pt *.googleapis.cn *.gstatic.cn *.gstatic-cn.com googlecnapps.cn *.googlecnapps.cn googleapps-cn.com *.googleapps-cn.com gkecnapps.cn *.gkecnapps.cn googledownloads.cn *.googledownloads.cn recaptcha.net.cn *.recaptcha.net.cn recaptcha-cn.net *.recaptcha-cn.net widevine.cn *.widevine.cn ampproject.org.cn *.ampproject.org.cn ampproject.net.cn *.ampproject.net.cn google-analytics-cn.com *.google-analytics-cn.com googleadservices-cn.com *.googleadservices-cn.com googlevads-cn.com *.googlevads-cn.com googleapis-cn.com *.googleapis-cn.com googleoptimize-cn.com *.googleoptimize-cn.com doubleclick-cn.net *.doubleclick-cn.net *.fls.doubleclick-cn.net *.g.doubleclick-cn.net doubleclick.cn *.doubleclick.cn *.fls.doubleclick.cn *.g.doubleclick.cn dartsearch-cn.net *.dartsearch-cn.net googletraveladservices-cn.com *.googletraveladservices-cn.com googletagservices-cn.com *.googletagservices-cn.com googletagmanager-cn.com *.googletagmanager-cn.com googlesyndication-cn.com *.googlesyndication-cn.com *.safeframe.googlesyndication-cn.com app-measurement-cn.com *.app-measurement-cn.com gvt1-cn.com *.gvt1-cn.com gvt2-cn.com *.gvt2-cn.com 2mdn-cn.net *.2mdn-cn.net googleflights-cn.net *.googleflights-cn.net admob-cn.com *.admob-cn.com *.gemini.cloud.google.com googlesandbox-cn.com *.googlesandbox-cn.com *.safenup.googlesandbox-cn.com *.gstatic.com *.metric.gstatic.com *.gvt1.com *.gcpcdn.gvt1.com *.gvt2.com *.gcp.gvt2.com *.url.google.com *.youtube-nocookie.com *.ytimg.com ai.android android.com *.android.com *.flash.android.com g.cn *.g.cn g.co *.g.co goo.gl www.goo.gl google-analytics.com *.google-analytics.com google.com googlecommerce.com *.googlecommerce.com ggpht.cn *.ggpht.cn urchin.com *.urchin.com youtu.be youtube.com *.youtube.com music.youtube.com *.music.youtube.com youtubeeducation.com *.youtubeeducation.com youtubekids.com *.youtubekids.com yt.be *.yt.be android.clients.google.com *.android.google.cn *.chrome.google.cn *.developers.google.cn *.aistudio.google.com]
AIA (Issuer): [http://i.pki.goog/wr2.crt]
CRL DPs:     [http://c.pki.goog/wr2/oBFYYahzgVI.crl]

=== Heuristic Analysis ===
ℹ️  Leaf Public Key: ECDSA-P-256(256)
ℹ️  Leaf Signature Algorithm: SHA256-RSA

=== Automatic AIA Fetching ===
ℹ️  Found parent locally: WR2. Continuing walk.
ℹ️  Found parent locally: GTS Root R1. Continuing walk.
ℹ️  Reached Self-Signed Root (GTS Root R1). Stopping fetch.

=== Verifying Chain ===
Root Trust: System Trust Store
  (Tip: Hostname mismatch; use -dns or -sni appropriately)
❌ ERROR: VALIDATION FAILED: x509: certificate is valid for 137 names, but none matched google.ru
```

## Full certificate check - including correct DNS name
```shell
/x509-cert-validator -cert https://google.com -dns google.com -aia -crl -showGraph
Runtime: go1.26.0
Validation Time: 2026-02-15T20:48:04+04:00
--- Loading Roots (System) ---
ℹ️  Loaded System Root Store.
⬇️  Connecting to remote server: google.com:443 ...
✅ Retrieved 3 certificates from server.

ℹ️  Target URL returned 3 certificates. Treating [1..n] as intermediates.
[Server-Sent] e6fe22bf... (CN=WR2, Key=RSA-2048)
[Server-Sent] 3ee0278d... (CN=GTS Root R1, Key=RSA-4096)

=== Target Certificate Certificate Details ===
Subject:     CN=*.google.com
Issuer:      CN=WR2,O=Google Trust Services,C=US
FP(sha1):    <sha1 hash>
FP(sha256):  977eca18f030b2d8f5c6f872e1cf30b5ceea5dcf26ac0bbbcf1723e233e05612
Serial:      2741bdc24e9d339a3340cff0234df4ff
Validity:    2026-01-26 08:39:20 +0000 UTC to 2026-04-20 08:39:19 +0000 UTC
Public Key:  ECDSA-P-256(256)
Sig Alg:     SHA256-RSA
SAN (DNS):   [*.google.com *.appengine.google.com *.bdn.dev *.origin-test.bdn.dev *.cloud.google.com *.crowdsource.google.com *.datacompute.google.com *.google.ca *.google.cl *.google.co.in *.google.co.jp *.google.co.uk *.google.com.ar *.google.com.au *.google.com.br *.google.com.co *.google.com.mx *.google.com.tr *.google.com.vn *.google.de *.google.es *.google.fr *.google.hu *.google.it *.google.nl *.google.pl *.google.pt *.googleapis.cn *.gstatic.cn *.gstatic-cn.com googlecnapps.cn *.googlecnapps.cn googleapps-cn.com *.googleapps-cn.com gkecnapps.cn *.gkecnapps.cn googledownloads.cn *.googledownloads.cn recaptcha.net.cn *.recaptcha.net.cn recaptcha-cn.net *.recaptcha-cn.net widevine.cn *.widevine.cn ampproject.org.cn *.ampproject.org.cn ampproject.net.cn *.ampproject.net.cn google-analytics-cn.com *.google-analytics-cn.com googleadservices-cn.com *.googleadservices-cn.com googlevads-cn.com *.googlevads-cn.com googleapis-cn.com *.googleapis-cn.com googleoptimize-cn.com *.googleoptimize-cn.com doubleclick-cn.net *.doubleclick-cn.net *.fls.doubleclick-cn.net *.g.doubleclick-cn.net doubleclick.cn *.doubleclick.cn *.fls.doubleclick.cn *.g.doubleclick.cn dartsearch-cn.net *.dartsearch-cn.net googletraveladservices-cn.com *.googletraveladservices-cn.com googletagservices-cn.com *.googletagservices-cn.com googletagmanager-cn.com *.googletagmanager-cn.com googlesyndication-cn.com *.googlesyndication-cn.com *.safeframe.googlesyndication-cn.com app-measurement-cn.com *.app-measurement-cn.com gvt1-cn.com *.gvt1-cn.com gvt2-cn.com *.gvt2-cn.com 2mdn-cn.net *.2mdn-cn.net googleflights-cn.net *.googleflights-cn.net admob-cn.com *.admob-cn.com *.gemini.cloud.google.com googlesandbox-cn.com *.googlesandbox-cn.com *.safenup.googlesandbox-cn.com *.gstatic.com *.metric.gstatic.com *.gvt1.com *.gcpcdn.gvt1.com *.gvt2.com *.gcp.gvt2.com *.url.google.com *.youtube-nocookie.com *.ytimg.com ai.android android.com *.android.com *.flash.android.com g.cn *.g.cn g.co *.g.co goo.gl www.goo.gl google-analytics.com *.google-analytics.com google.com googlecommerce.com *.googlecommerce.com ggpht.cn *.ggpht.cn urchin.com *.urchin.com youtu.be youtube.com *.youtube.com music.youtube.com *.music.youtube.com youtubeeducation.com *.youtubeeducation.com youtubekids.com *.youtubekids.com yt.be *.yt.be android.clients.google.com *.android.google.cn *.chrome.google.cn *.developers.google.cn *.aistudio.google.com]
AIA (Issuer): [http://i.pki.goog/wr2.crt]
CRL DPs:     [http://c.pki.goog/wr2/oBFYYahzgVI.crl]

=== Heuristic Analysis ===
ℹ️  Leaf Public Key: ECDSA-P-256(256)
ℹ️  Leaf Signature Algorithm: SHA256-RSA

=== Automatic AIA Fetching ===
ℹ️  Found parent locally: WR2. Continuing walk.
ℹ️  Found parent locally: GTS Root R1. Continuing walk.
ℹ️  Reached Self-Signed Root (GTS Root R1). Stopping fetch.

=== Verifying Chain ===
Root Trust: System Trust Store
✅ VALIDATION SUCCEEDED

--- Verified Chain Path 1 ---

+--------------------------------------------------+
| ROOT ANCHOR                                      |
| CN: GTS Root R1                                  |
| Issuer: GTS Root R1                              |
| Key: RSA-4096                                    |
| Sig: SHA384-RSA                                  |
| SN: 77d8d39a786fa7e8ba11ceab96e2                 |
+--------------------------------------------------+
      |
      V
+--------------------------------------------------+
| INTERMEDIATE                                     |
| CN: WR2                                          |
| Issuer: GTS Root R1                              |
| Key: RSA-2048                                    |
| Sig: SHA256-RSA                                  |
| SN: 8011a64a4817633ced5e79a598c98b08             |
+--------------------------------------------------+
      |
      V
+--------------------------------------------------+
| TARGET LEAF                                      |
| CN: *.google.com                                 |
| Issuer: WR2                                      |
| Key: ECDSA-P-256(256)                            |
| Sig: SHA256-RSA                                  |
| SN: 2741bdc24e9d339a3340cff0234df4ff             |
+--------------------------------------------------+


--- Verified Chain Path 2 ---

+--------------------------------------------------+
| ROOT ANCHOR                                      |
| CN: GlobalSign Root CA                           |
| Issuer: GlobalSign Root CA                       |
| Key: RSA-2048                                    |
| Sig: SHA1-RSA                                    |
| SN: 040000000001154b5ac394                       |
+--------------------------------------------------+
      |
      V
+--------------------------------------------------+
| INTERMEDIATE                                     |
| CN: GTS Root R1                                  |
| Issuer: GlobalSign Root CA                       |
| Key: RSA-4096                                    |
| Sig: SHA256-RSA                                  |
| SN: 77bd0d6cdb36f91aea210fc4f058d30d             |
+--------------------------------------------------+
      |
      V
+--------------------------------------------------+
| INTERMEDIATE                                     |
| CN: WR2                                          |
| Issuer: GTS Root R1                              |
| Key: RSA-2048                                    |
| Sig: SHA256-RSA                                  |
| SN: 8011a64a4817633ced5e79a598c98b08             |
+--------------------------------------------------+
      |
      V
+--------------------------------------------------+
| TARGET LEAF                                      |
| CN: *.google.com                                 |
| Issuer: WR2                                      |
| Key: ECDSA-P-256(256)                            |
| Sig: SHA256-RSA                                  |
| SN: 2741bdc24e9d339a3340cff0234df4ff             |
+--------------------------------------------------+


=== Checking CRLs ===
⬇️  Fetching CRL for '*.google.com' [1/1]: http://c.pki.goog/wr2/oBFYYahzgVI.crl
   ℹ️  CRL Signature Verified: SigAlg=SHA256-RSA SignedByKey=RSA-2048 Issuer=WR2
   ✅ Valid CRL checked via http://c.pki.goog/wr2/oBFYYahzgVI.crl
⬇️  Fetching CRL for 'WR2' [1/1]: http://c.pki.goog/r/r1.crl
   ℹ️  CRL Signature Verified: SigAlg=SHA256-RSA SignedByKey=RSA-4096 Issuer=GTS Root R1
   ✅ Valid CRL checked via http://c.pki.goog/r/r1.crl
ℹ️  Skipping CRL re-check (already checked) for '*.google.com' issued by 'WR2'
ℹ️  Using cached CRL for 'WR2' [1/1]: http://c.pki.goog/r/r1.crl
   ℹ️  CRL Signature Verified: SigAlg=SHA256-RSA SignedByKey=RSA-4096 Issuer=GTS Root R1
   ✅ Valid CRL checked via http://c.pki.goog/r/r1.crl
⬇️  Fetching CRL for 'GTS Root R1' [1/1]: http://crl.pki.goog/gsr1/gsr1.crl
   ℹ️  CRL Signature Verified: SigAlg=SHA256-RSA SignedByKey=RSA-2048 Issuer=GlobalSign Root CA
   ✅ Valid CRL checked via http://crl.pki.goog/gsr1/gsr1.crl
✅ CRL CHECK PASSED
```

## Automatic retrieval of CA certificates
```shell
x509-cert-validator.exe -root C:\Temp\root.crt -cert C:\Temp\some-cert.crt -aia
```

### Automatic generation of CA bundle

If root is reachable via AIA - it will be added to bundle with the following command:
```shell
x509-cert-validator.exe -cert C:\Temp\cert.crt -aia -createCAbundle .\cabundle.crt -includeRoot
```
