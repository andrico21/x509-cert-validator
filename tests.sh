#!/usr/bin/env bash
# x509-cert-validator test suite runner
#
# Usage:
#   ./tests.sh -validator /path/to/x509-cert-validator
#
# Env:
#   DEBUG=1                     # bash -x
#   KEEP_TMP=1                  # keep temp dir
#   TIMEOUT_SECS=15             # per-test timeout
#   OPENSSL_KEYGEN_QUIET=1      # suppress RSA/EC keygen progress (default: 1)
#   OPENSSL_QUIET=1             # if 1, suppress most openssl stdout/stderr (default: 1)
#   CRL_DAYS=30                 # CRL validity for openssl ca -gencrl (default: 30)
#   EXTRA_CRYPTO=0              # if 1, also generate/run extra RSA/EC tests not in canonical list

set -euo pipefail

DEBUG="${DEBUG:-0}"
KEEP_TMP="${KEEP_TMP:-0}"
TIMEOUT_SECS="${TIMEOUT_SECS:-15}"
OPENSSL_KEYGEN_QUIET="${OPENSSL_KEYGEN_QUIET:-1}"
OPENSSL_QUIET="${OPENSSL_QUIET:-1}"
CRL_DAYS="${CRL_DAYS:-30}"
EXTRA_CRYPTO="${EXTRA_CRYPTO:-0}"

if [[ "${DEBUG}" == "1" ]]; then
  set -x
fi

die() { echo "ERROR: $*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

need_cmd() {
  command -v "${1}" >/dev/null 2>&1 || die "missing required command: ${1}"
}

write_file() {
  local path="${1}"; shift
  mkdir -p "$(dirname "${path}")"
  cat >"${path}" <<EOF
$*
EOF
}

pick_free_port() {
  python3 - <<'PY'
import socket
s=socket.socket()
s.bind(("127.0.0.1",0))
print(s.getsockname()[1])
s.close()
PY
}

wait_for_tcp_listen() {
  # returns:
  #   0 => ready
  #   1 => timed out (not ready)
  #   2 => process died
  local host="${1}" port="${2}" pid="${3}" tries="${4:-80}" sleep_s="${5:-0.05}"
  python3 - <<PY
import socket, time, os, sys
host="${host}"; port=int("${port}")
pid=int("${pid}")
tries=int("${tries}")
sleep_s=float("${sleep_s}")
for _ in range(tries):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        sys.exit(2)
    s=socket.socket()
    s.settimeout(0.2)
    try:
        s.connect((host, port))
        s.close()
        sys.exit(0)
    except Exception:
        s.close()
        time.sleep(sleep_s)
sys.exit(1)
PY
}

openssl_run() {
  if [[ "${OPENSSL_QUIET}" == "1" ]]; then
    openssl "$@" >/dev/null 2>&1
  else
    openssl "$@"
  fi
}

gen_rsa_key() {
  local bits="${1}" out="${2}"
  mkdir -p "$(dirname "${out}")"
  if [[ "${OPENSSL_KEYGEN_QUIET}" == "1" ]]; then
    openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${bits}" -out "${out}" 2>/dev/null
  else
    openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${bits}" -out "${out}"
  fi
}

gen_ec_key() {
  local curve="${1}" out="${2}"
  mkdir -p "$(dirname "${out}")"
  if [[ "${OPENSSL_KEYGEN_QUIET}" == "1" ]]; then
    openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${curve}" -out "${out}" 2>/dev/null
  else
    openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${curve}" -out "${out}"
  fi
}

csr() {
  local key="${1}" out="${2}" cn="${3}"
  if [[ "${OPENSSL_QUIET}" == "1" ]]; then
    openssl req -new -key "${key}" -subj "/CN=${cn}" -out "${out}" >/dev/null 2>&1
  else
    openssl req -new -key "${key}" -subj "/CN=${cn}" -out "${out}"
  fi
}

# CSR -> self-signed cert with extensions from extfile (stable across key types)
selfsign_root_ca() {
  local key="${1}" crt="${2}" cn="${3}" extfile="${4}"
  local tmpcsr
  tmpcsr="$(mktemp "${TMP:-/tmp}/rootcsr.XXXXXX")"
  csr "${key}" "${tmpcsr}" "${cn}"
  if [[ "${OPENSSL_QUIET}" == "1" ]]; then
    openssl x509 -req -in "${tmpcsr}" -signkey "${key}" -sha256 -days 3650 -out "${crt}" \
      -extfile "${extfile}" -extensions v3_ca >/dev/null 2>&1
  else
    openssl x509 -req -in "${tmpcsr}" -signkey "${key}" -sha256 -days 3650 -out "${crt}" \
      -extfile "${extfile}" -extensions v3_ca
  fi
  rm -f "${tmpcsr}"
}

openssl_supports_curve() {
  local curve="${1}"
  local tmpk
  tmpk="$(mktemp)"
  rm -f "${tmpk}"
  if openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${curve}" -out "${tmpk}" >/dev/null 2>&1; then
    rm -f "${tmpk}"
    return 0
  fi
  rm -f "${tmpk}"
  return 1
}

make_sparse_or_real_file() {
  local path="${1}" size_mb="${2}"
  mkdir -p "$(dirname "${path}")"
  if command -v truncate >/dev/null 2>&1; then
    truncate -s "${size_mb}M" "${path}"
  else
    dd if=/dev/zero of="${path}" bs=1M count="${size_mb}" status=none
  fi
}

# -----------------------------------------------------------------------------
# OpenSSL CA directory/config (CRL + revocation)
# -----------------------------------------------------------------------------
init_ca_dir() {
  local dir="${1}"
  mkdir -p "${dir}"/{certs,crl,newcerts,private}
  : >"${dir}/index.txt"
  echo 1000 >"${dir}/serial"
  echo 1000 >"${dir}/crlnumber"
}

make_root_ca_openssl_cnf() {
  local dir="${1}" key="${2}" crt="${3}" out="${4}"
  write_file "${out}" "
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${dir}
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
RANDFILE          = \$dir/private/.rand

private_key       = ${key}
certificate       = ${crt}

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 3650
default_crl_days  = ${CRL_DAYS}
unique_subject    = no
policy            = policy_loose
copy_extensions   = copy
crl_extensions    = crl_ext

[ policy_loose ]
commonName = supplied

[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always

[ v3_intermediate_ca ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always

[ crl_ext ]
authorityKeyIdentifier = keyid:always
"
}

make_inter_ca_openssl_cnf() {
  local dir="${1}" key="${2}" crt="${3}" out="${4}"
  write_file "${out}" "
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${dir}
certs             = \$dir/certs
crl_dir           = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
RANDFILE          = \$dir/private/.rand

private_key       = ${key}
certificate       = ${crt}

default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 365
default_crl_days  = ${CRL_DAYS}
unique_subject    = no
policy            = policy_loose
copy_extensions   = copy
crl_extensions    = crl_ext

[ policy_loose ]
commonName = supplied

[ crl_ext ]
authorityKeyIdentifier = keyid:always
"
}

issue_with_ca() {
  local ca_cnf="${1}" csr_in="${2}" crt_out="${3}" extfile="${4}" extsec="${5}" md="${6}"
  if [[ "${OPENSSL_QUIET}" == "1" ]]; then
    openssl ca -batch -notext -config "${ca_cnf}" -in "${csr_in}" -out "${crt_out}" \
      -extfile "${extfile}" -extensions "${extsec}" -md "${md}" >/dev/null 2>&1
  else
    openssl ca -batch -notext -config "${ca_cnf}" -in "${csr_in}" -out "${crt_out}" \
      -extfile "${extfile}" -extensions "${extsec}" -md "${md}"
  fi
}

gen_crl() {
  local ca_cnf="${1}" out="${2}"
  if [[ "${OPENSSL_QUIET}" == "1" ]]; then
    openssl ca -gencrl -config "${ca_cnf}" -crldays "${CRL_DAYS}" -out "${out}" >/dev/null 2>&1
  else
    openssl ca -gencrl -config "${ca_cnf}" -crldays "${CRL_DAYS}" -out "${out}"
  fi
}

revoke_cert() {
  local ca_cnf="${1}" crt="${2}"
  if [[ "${OPENSSL_QUIET}" == "1" ]]; then
    openssl ca -batch -config "${ca_cnf}" -revoke "${crt}" >/dev/null 2>&1
  else
    openssl ca -batch -config "${ca_cnf}" -revoke "${crt}"
  fi
}

# -----------------------------------------------------------------------------
# Simple chain generation (no CA db) for fixtures
# -----------------------------------------------------------------------------
sign_leaf_simple() {
  local ca_key="${1}" ca_crt="${2}" csr_in="${3}" crt_out="${4}" extfile="${5}" extsec="${6}" md="${7}"
  if [[ "${OPENSSL_QUIET}" == "1" ]]; then
    openssl x509 -req -in "${csr_in}" -CA "${ca_crt}" -CAkey "${ca_key}" -CAcreateserial \
      -out "${crt_out}" -days 365 -"${md}" -extfile "${extfile}" -extensions "${extsec}" >/dev/null 2>&1
  else
    openssl x509 -req -in "${csr_in}" -CA "${ca_crt}" -CAkey "${ca_key}" -CAcreateserial \
      -out "${crt_out}" -days 365 -"${md}" -extfile "${extfile}" -extensions "${extsec}"
  fi
}

# Issue via openssl ca with explicit -startdate / -enddate (portable across OpenSSL versions)
issue_with_ca_dates() {
  local ca_cnf="${1}" csr_in="${2}" crt_out="${3}" extfile="${4}" extsec="${5}" md="${6}"
  local startdate="${7}" enddate="${8}"
  if [[ "${OPENSSL_QUIET}" == "1" ]]; then
    openssl ca -batch -notext -config "${ca_cnf}" -in "${csr_in}" -out "${crt_out}" \
      -extfile "${extfile}" -extensions "${extsec}" -md "${md}" \
      -startdate "${startdate}" -enddate "${enddate}" >/dev/null 2>&1
  else
    openssl ca -batch -notext -config "${ca_cnf}" -in "${csr_in}" -out "${crt_out}" \
      -extfile "${extfile}" -extensions "${extsec}" -md "${md}" \
      -startdate "${startdate}" -enddate "${enddate}"
  fi
}

# -----------------------------------------------------------------------------
# Test runner
# -----------------------------------------------------------------------------
declare -a TESTS=()

add_test() {
  local name="${1}" expect="${2}" regex="${3}"
  shift 3
  local cmd=("$@")
  TESTS+=("${name}||${expect}||${regex}||${cmd[*]}")
}

run_one_test() {
  local entry="${1}"
  local name expect regex cmdline
  name="${entry%%||*}"
  entry="${entry#*||}"
  expect="${entry%%||*}"
  entry="${entry#*||}"
  regex="${entry%%||*}"
  entry="${entry#*||}"
  cmdline="${entry}"

  say ""
  say "------------------------------------------------------------"
  say "TEST: ${name}"
  say "CMD: ${cmdline}"
  say "OUTPUT:"

  local out rc ok=1

  set +e
  out="$(timeout "${TIMEOUT_SECS}s" bash -c "${cmdline}" 2>&1)"
  rc=$?
  set -e

  printf '%s\n' "${out}"

  if [[ ${rc} -eq 124 ]]; then
    say "❌ RESULT: FAIL (timeout after ${TIMEOUT_SECS}s)"
    return 1
  fi

  if [[ "${expect}" == "PASS" ]]; then
    if [[ ${rc} -ne 0 ]]; then
      ok=0
      say "❌ RESULT: FAIL (expected exit 0, got ${rc})"
    fi
  else
    if [[ ${rc} -eq 0 ]]; then
      ok=0
      say "❌ RESULT: FAIL (expected non-zero exit, got 0)"
    fi
  fi

  if [[ -n "${regex}" ]]; then
    if ! printf '%s\n' "${out}" | grep -Eq "${regex}"; then
      ok=0
      say "❌ RESULT: FAIL (regex not matched: /${regex}/)"
    else
      say "✅ CONTENT: matched /${regex}/"
    fi
  fi

  if [[ ${ok} -eq 1 ]]; then
    say "✅ RESULT: PASS"
    return 0
  fi

  return 1
}

run_all_tests() {
  local fails=0 total=0
  say "=== Running ${#TESTS[@]} tests ==="
  for t in "${TESTS[@]}"; do
    total=$((total+1))
    if ! run_one_test "${t}"; then
      fails=$((fails+1))
    fi
  done

  say ""
  if [[ ${fails} -eq 0 ]]; then
    say "=== ALL ${total} TESTS PASSED ==="
    return 0
  fi
  say "=== FAILURES: ${fails}/${total} ==="
  return 1
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
need_cmd openssl
need_cmd python3
need_cmd timeout

TOOL_BIN=""
while [[ $# -gt 0 ]]; do
  case "${1}" in
    -validator) TOOL_BIN="${2:-}"; shift 2;;
    -keep) KEEP_TMP=1; shift;;
    *) die "unknown argument: ${1}";;
  esac
done

[[ -n "${TOOL_BIN}" ]] || die "missing -validator /path/to/validator"
[[ -x "${TOOL_BIN}" ]] || die "validator is not executable: ${TOOL_BIN}"

TMP="$(mktemp -d /tmp/x509-validator-testsuite.XXXXXX)"
PKI="${TMP}/pki"
mkdir -p "${PKI}"

HTTP_PID=""
HTTP_PORT=""
HTTP_URL=""

cleanup() {
  set +e
  if [[ -n "${HTTP_PID}" ]]; then
    kill "${HTTP_PID}" >/dev/null 2>&1 || true
    wait "${HTTP_PID}" >/dev/null 2>&1 || true
  fi
  if [[ "${KEEP_TMP}" != "1" ]]; then
    rm -rf "${TMP}"
  else
    say "NOTE: keeping tmp dir: ${TMP}"
  fi
}
trap cleanup EXIT

say "=== Using validator: ${TOOL_BIN} ==="
say "=== Generating test PKI in ${PKI} ==="

# Start HTTP server FIRST and wait until it's reachable
HTTP_PORT="$(pick_free_port)"
HTTP_URL="http://127.0.0.1:${HTTP_PORT}"
say "=== Starting HTTP server on ${HTTP_URL} serving ${PKI} ==="
python3 -m http.server "${HTTP_PORT}" --bind 127.0.0.1 --directory "${PKI}" >/dev/null 2>&1 &
HTTP_PID=$!

set +e
wait_for_tcp_listen 127.0.0.1 "${HTTP_PORT}" "${HTTP_PID}"
rc=$?
set -e
case "${rc}" in
  0) : ;;
  1) die "HTTP server did not become ready on ${HTTP_URL}" ;;
  2) die "HTTP server process died immediately (bind failure?)" ;;
  *) die "unexpected readiness check rc=${rc}" ;;
esac

# -----------------------------------------------------------------------------
# Base PKI with root -> intermediate -> leaf (AIA + CRL)
# -----------------------------------------------------------------------------
ROOT_KEY="${PKI}/root.key"
ROOT_CRT="${PKI}/root.crt"
ROOT_EXT="${PKI}/root_ext.cnf"

gen_rsa_key 2048 "${ROOT_KEY}"
write_file "${ROOT_EXT}" "
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"
selfsign_root_ca "${ROOT_KEY}" "${ROOT_CRT}" "Test Root CA" "${ROOT_EXT}"

ROOT_CA_DIR="${PKI}/root_ca"
init_ca_dir "${ROOT_CA_DIR}"
cp -f "${ROOT_KEY}" "${ROOT_CA_DIR}/private/ca.key"
cp -f "${ROOT_CRT}" "${ROOT_CA_DIR}/ca.crt"
ROOT_CA_CNF="${PKI}/root_ca.cnf"
make_root_ca_openssl_cnf "${ROOT_CA_DIR}" "${ROOT_CA_DIR}/private/ca.key" "${ROOT_CA_DIR}/ca.crt" "${ROOT_CA_CNF}"

INTER_KEY="${PKI}/inter.key"
INTER_CSR="${PKI}/inter.csr"
INTER_CRT="${PKI}/inter.crt"
INTER_PEM="${PKI}/inter.pem"

gen_rsa_key 2048 "${INTER_KEY}"
csr "${INTER_KEY}" "${INTER_CSR}" "Test Intermediate CA"

INTER_EXT="${PKI}/inter_ext.cnf"
write_file "${INTER_EXT}" "
[v3_intermediate_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"
issue_with_ca "${ROOT_CA_CNF}" "${INTER_CSR}" "${INTER_CRT}" "${INTER_EXT}" "v3_intermediate_ca" "sha256"
cp -f "${INTER_CRT}" "${INTER_PEM}"

INTER_CA_DIR="${PKI}/inter_ca"
init_ca_dir "${INTER_CA_DIR}"
cp -f "${INTER_KEY}" "${INTER_CA_DIR}/private/inter.key"
cp -f "${INTER_CRT}" "${INTER_CA_DIR}/inter.crt"
INTER_CA_CNF="${PKI}/inter_ca.cnf"
make_inter_ca_openssl_cnf "${INTER_CA_DIR}" "${INTER_CA_DIR}/private/inter.key" "${INTER_CA_DIR}/inter.crt" "${INTER_CA_CNF}"

write_leaf_ext() {
  local path="${1}" dns="${2}" eku="${3}" ku="${4}"
  write_file "${path}" "
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,${ku}
extendedKeyUsage = ${eku}
subjectAltName = DNS:${dns}
authorityInfoAccess = caIssuers;URI:${HTTP_URL}/inter.pem
crlDistributionPoints = URI:${HTTP_URL}/inter.crl
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"
}

issue_leaf_inter() {
  local name="${1}" dns="${2}" eku="${3}" keyusage="${4}" md="${5}"
  local key="${PKI}/leaf_${name}.key"
  local csrfile="${PKI}/leaf_${name}.csr"
  local crtfile="${PKI}/leaf_${name}.crt"
  local extfile="${PKI}/leaf_${name}_ext.cnf"

  gen_rsa_key 2048 "${key}"
  csr "${key}" "${csrfile}" "${dns}"
  write_leaf_ext "${extfile}" "${dns}" "${eku}" "${keyusage}"
  issue_with_ca "${INTER_CA_CNF}" "${csrfile}" "${crtfile}" "${extfile}" "v3_leaf" "${md}"
}

issue_leaf_inter "valid"   "valid.local"   "serverAuth" "digitalSignature,keyEncipherment" "sha256"
issue_leaf_inter "revoked" "revoked.local" "serverAuth" "digitalSignature,keyEncipherment" "sha256"
issue_leaf_inter "client"  "client.local"  "clientAuth" "digitalSignature,keyEncipherment" "sha256"

# CRL and revocation
INTER_CRL="${PKI}/inter.crl"
gen_crl "${INTER_CA_CNF}" "${INTER_CRL}"
revoke_cert "${INTER_CA_CNF}" "${PKI}/leaf_revoked.crt"
gen_crl "${INTER_CA_CNF}" "${INTER_CRL}"

# Oversized file for size-limit test (2MB is enough; test uses explicit -maxcert 1024)
make_sparse_or_real_file "${PKI}/large_file.crt" 2

# DER format fixture (convert PEM leaf to DER)
openssl x509 -in "${PKI}/leaf_valid.crt" -outform DER -out "${PKI}/leaf_valid.der" 2>/dev/null

# -----------------------------------------------------------------------------
# 10. Security: Weak Cipher (implemented as SHA1-signed cert policy rejection)
# -----------------------------------------------------------------------------
ROOT_STRONG_KEY="${PKI}/root_strong.key"
ROOT_STRONG_CRT="${PKI}/root_strong.crt"
ROOT_STRONG_EXT="${PKI}/root_strong_ext.cnf"
gen_rsa_key 2048 "${ROOT_STRONG_KEY}"
write_file "${ROOT_STRONG_EXT}" "
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"
selfsign_root_ca "${ROOT_STRONG_KEY}" "${ROOT_STRONG_CRT}" "Strong Root" "${ROOT_STRONG_EXT}"

WEAK_KEY="${PKI}/weak_sha1.key"
WEAK_CSR="${PKI}/weak_sha1.csr"
WEAK_CRT="${PKI}/weak_sha1.crt"
WEAK_EXT="${PKI}/weak_sha1_ext.cnf"
gen_rsa_key 2048 "${WEAK_KEY}"
csr "${WEAK_KEY}" "${WEAK_CSR}" "weaksha1.local"
write_file "${WEAK_EXT}" "
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:weaksha1.local
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"
sign_leaf_simple "${ROOT_STRONG_KEY}" "${ROOT_STRONG_CRT}" "${WEAK_CSR}" "${WEAK_CRT}" "${WEAK_EXT}" "v3_leaf" "sha1"

# -----------------------------------------------------------------------------
# Crypto suite fixtures: RSA4096 + P-256/P-384/P-521 only (canonical list)
# -----------------------------------------------------------------------------
make_rsa_fixture() {
  local bits="${1}"
  local rkey="${PKI}/root_rsa${bits}.key"
  local rcrt="${PKI}/root_rsa${bits}.crt"
  local rext="${PKI}/root_rsa${bits}_ext.cnf"
  local lkey="${PKI}/leaf_rsa${bits}.key"
  local lcsr="${PKI}/leaf_rsa${bits}.csr"
  local lcrt="${PKI}/leaf_rsa${bits}.crt"
  local lext="${PKI}/leaf_rsa${bits}_ext.cnf"

  gen_rsa_key "${bits}" "${rkey}"
  write_file "${rext}" "
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"
  selfsign_root_ca "${rkey}" "${rcrt}" "RSA${bits} Root" "${rext}"

  gen_rsa_key "${bits}" "${lkey}"
  csr "${lkey}" "${lcsr}" "rsa${bits}.local"
  write_file "${lext}" "
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:rsa${bits}.local
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"
  sign_leaf_simple "${rkey}" "${rcrt}" "${lcsr}" "${lcrt}" "${lext}" "v3_leaf" "sha256"
}

make_ec_fixture() {
  local label="${1}" curve="${2}"
  local rkey="${PKI}/root_ec${label}.key"
  local rcrt="${PKI}/root_ec${label}.crt"
  local rext="${PKI}/root_ec${label}_ext.cnf"
  local lkey="${PKI}/leaf_ec${label}.key"
  local lcsr="${PKI}/leaf_ec${label}.csr"
  local lcrt="${PKI}/leaf_ec${label}.crt"
  local lext="${PKI}/leaf_ec${label}_ext.cnf"

  if ! openssl_supports_curve "${curve}"; then
    die "OpenSSL does not support required curve '${curve}' for EC${label} fixture"
  fi

  gen_ec_key "${curve}" "${rkey}"
  write_file "${rext}" "
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"
  selfsign_root_ca "${rkey}" "${rcrt}" "EC${label} Root" "${rext}"

  gen_ec_key "${curve}" "${lkey}"
  csr "${lkey}" "${lcsr}" "ec${label}.local"
  write_file "${lext}" "
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:ec${label}.local
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"
  sign_leaf_simple "${rkey}" "${rcrt}" "${lcsr}" "${lcrt}" "${lext}" "v3_leaf" "sha256"
}

make_rsa_fixture 4096

# P-256
if openssl_supports_curve prime256v1; then
  make_ec_fixture 256 prime256v1
elif openssl_supports_curve secp256r1; then
  make_ec_fixture 256 secp256r1
else
  die "OpenSSL EC P-256 curve not supported (prime256v1/secp256r1)"
fi
# P-384, P-521
make_ec_fixture 384 secp384r1
make_ec_fixture 521 secp521r1

# -----------------------------------------------------------------------------
# Advanced scenarios
# -----------------------------------------------------------------------------
# Mixed: RSA chain signs EC leaf (via intermediate CA)
MIXED_EC_KEY="${PKI}/leaf_mixed.key"
MIXED_EC_CSR="${PKI}/leaf_mixed.csr"
MIXED_EC_CRT="${PKI}/leaf_mixed.crt"
MIXED_EC_EXT="${PKI}/leaf_mixed_ext.cnf"

# Use P-256 for mixed leaf
if openssl_supports_curve prime256v1; then
  gen_ec_key prime256v1 "${MIXED_EC_KEY}"
else
  gen_ec_key secp256r1 "${MIXED_EC_KEY}"
fi
csr "${MIXED_EC_KEY}" "${MIXED_EC_CSR}" "Mixed EC Leaf"
write_leaf_ext "${MIXED_EC_EXT}" "mixed.local" "serverAuth" "digitalSignature"
issue_with_ca "${INTER_CA_CNF}" "${MIXED_EC_CSR}" "${MIXED_EC_CRT}" "${MIXED_EC_EXT}" "v3_leaf" "sha256"

# Mixed: EC root signs RSA leaf (distinct filenames)
ROOT_EC256_MIX_KEY="${PKI}/root_ec256_mixed.key"
ROOT_EC256_MIX_CRT="${PKI}/root_ec256_mixed.crt"
ROOT_EC256_MIX_EXT="${PKI}/root_ec256_mixed_ext.cnf"

if openssl_supports_curve prime256v1; then
  gen_ec_key prime256v1 "${ROOT_EC256_MIX_KEY}"
elif openssl_supports_curve secp256r1; then
  gen_ec_key secp256r1 "${ROOT_EC256_MIX_KEY}"
else
  die "OpenSSL EC P-256 curve not supported (prime256v1/secp256r1)"
fi
write_file "${ROOT_EC256_MIX_EXT}" "
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
"
selfsign_root_ca "${ROOT_EC256_MIX_KEY}" "${ROOT_EC256_MIX_CRT}" "EC256 Mixed Root" "${ROOT_EC256_MIX_EXT}"

RSA_FROM_EC_KEY="${PKI}/leaf_rsa_from_ec.key"
RSA_FROM_EC_CSR="${PKI}/leaf_rsa_from_ec.csr"
RSA_FROM_EC_CRT="${PKI}/leaf_rsa_from_ec.crt"
RSA_FROM_EC_EXT="${PKI}/leaf_rsa_from_ec_ext.cnf"
gen_rsa_key 2048 "${RSA_FROM_EC_KEY}"
csr "${RSA_FROM_EC_KEY}" "${RSA_FROM_EC_CSR}" "EC Root -> RSA Leaf"
write_file "${RSA_FROM_EC_EXT}" "
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:ecroot-rsaleaf.local
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"
sign_leaf_simple "${ROOT_EC256_MIX_KEY}" "${ROOT_EC256_MIX_CRT}" "${RSA_FROM_EC_CSR}" "${RSA_FROM_EC_CRT}" "${RSA_FROM_EC_EXT}" "v3_leaf" "sha256"

# NameConstraints root and leaves
ROOT_CONS_KEY="${PKI}/root_constrained.key"
ROOT_CONS_CRT="${PKI}/root_constrained.crt"
ROOT_CONS_EXT="${PKI}/root_constrained_ext.cnf"
gen_rsa_key 2048 "${ROOT_CONS_KEY}"
write_file "${ROOT_CONS_EXT}" "
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
nameConstraints = critical,@nc

[nc]
permitted;DNS.0 = .allowed.local
excluded;DNS.0 = .forbidden.local
"
selfsign_root_ca "${ROOT_CONS_KEY}" "${ROOT_CONS_CRT}" "Constrained Root" "${ROOT_CONS_EXT}"

LEAF_PERM_KEY="${PKI}/leaf_permitted.key"
LEAF_PERM_CSR="${PKI}/leaf_permitted.csr"
LEAF_PERM_CRT="${PKI}/leaf_permitted.crt"
LEAF_PERM_EXT="${PKI}/leaf_permitted_ext.cnf"
gen_rsa_key 2048 "${LEAF_PERM_KEY}"
csr "${LEAF_PERM_KEY}" "${LEAF_PERM_CSR}" "test.allowed.local"
write_file "${LEAF_PERM_EXT}" "
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:test.allowed.local
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"
sign_leaf_simple "${ROOT_CONS_KEY}" "${ROOT_CONS_CRT}" "${LEAF_PERM_CSR}" "${LEAF_PERM_CRT}" "${LEAF_PERM_EXT}" "v3_leaf" "sha256"

LEAF_EXCL_KEY="${PKI}/leaf_excluded.key"
LEAF_EXCL_CSR="${PKI}/leaf_excluded.csr"
LEAF_EXCL_CRT="${PKI}/leaf_excluded.crt"
LEAF_EXCL_EXT="${PKI}/leaf_excluded_ext.cnf"
gen_rsa_key 2048 "${LEAF_EXCL_KEY}"
csr "${LEAF_EXCL_KEY}" "${LEAF_EXCL_CSR}" "test.forbidden.local"
write_file "${LEAF_EXCL_EXT}" "
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:test.forbidden.local
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"
sign_leaf_simple "${ROOT_CONS_KEY}" "${ROOT_CONS_CRT}" "${LEAF_EXCL_CSR}" "${LEAF_EXCL_CRT}" "${LEAF_EXCL_EXT}" "v3_leaf" "sha256"

# -----------------------------------------------------------------------------
# Short-lived cert for proportional expiry NOTICE test
# Cert lifetime: 3 days (NotBefore: 2 days ago, NotAfter: 1 day from now)
# threshold = max(3d/10=7.2h, min(7d, 1.5d)=1.5d) = 1.5d
# remaining ~1d < 1.5d => NOTICE fires
# -----------------------------------------------------------------------------
EXPIRY_SOON_KEY="${PKI}/leaf_expiry_soon.key"
EXPIRY_SOON_CSR="${PKI}/leaf_expiry_soon.csr"
EXPIRY_SOON_CRT="${PKI}/leaf_expiry_soon.crt"
EXPIRY_SOON_EXT="${PKI}/leaf_expiry_soon_ext.cnf"

gen_rsa_key 2048 "${EXPIRY_SOON_KEY}"
csr "${EXPIRY_SOON_KEY}" "${EXPIRY_SOON_CSR}" "expiry-soon.local"
write_file "${EXPIRY_SOON_EXT}" "
[v3_leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:expiry-soon.local
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"
# OpenSSL ca date format: YYYYMMDDHHMMSSZ
# Compute start=2 days ago, end=1 day from now => 3-day lifetime, ~1 day remaining.
# Threshold = max(3d/10=7.2h, min(7d, 1.5d)=1.5d) = 1.5d; remaining ~1d < 1.5d => NOTICE fires.
EXPIRY_START="$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.UTC)-datetime.timedelta(days=2)).strftime("%Y%m%d%H%M%SZ"))')"
EXPIRY_END="$(python3 -c 'import datetime; print((datetime.datetime.now(datetime.UTC)+datetime.timedelta(days=1)).strftime("%Y%m%d%H%M%SZ"))')"
issue_with_ca_dates "${ROOT_CA_CNF}" "${EXPIRY_SOON_CSR}" "${EXPIRY_SOON_CRT}" \
  "${EXPIRY_SOON_EXT}" "v3_leaf" "sha256" "${EXPIRY_START}" "${EXPIRY_END}"

# Bundle output path (inside TMP so cleanup handles it)
BUNDLE_OUT="${TMP}/bundle_out.pem"
BUNDLE_ROOT_OUT="${TMP}/bundle_root_out.pem"

# -----------------------------------------------------------------------------
# Optional extra crypto fixtures/tests (not in your canonical 1–21 list)
# -----------------------------------------------------------------------------
if [[ "${EXTRA_CRYPTO}" == "1" ]]; then
  make_rsa_fixture 1024
  make_rsa_fixture 2048
  make_rsa_fixture 3072

  # Optional unsupported-by-Go curves as negative fixtures (best-effort, not required)
  if openssl_supports_curve secp128r1; then make_ec_fixture 128 secp128r1 || true; fi
  if openssl_supports_curve secp160r1; then make_ec_fixture 160 secp160r1 || true; fi
  if openssl_supports_curve prime192v1; then make_ec_fixture 192 prime192v1 || true; fi
fi

say "=== PKI generation complete ==="

# -----------------------------------------------------------------------------
# Define tests (CANONICAL LIST 1..21 + NEW 22..30)
# -----------------------------------------------------------------------------
add_test "1. AIA Auto-Fetch" "PASS" "VALIDATION SUCCEEDED" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia"

add_test "2. Missing Inter" "FAIL" "unknown authority|VALIDATION FAILED" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt"

add_test "3. CRL Check (Valid)" "PASS" "CRL CHECK PASSED" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia -crl"

add_test "4. Revocation" "FAIL" "REVOKED|revoked" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_revoked.crt -aia -crl"

add_test "5. Visualization" "PASS" "ROOT ANCHOR" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia -showGraph"

add_test "6. Silent Mode" "PASS" "PASS \\[" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia -silent"

add_test "7. Untrusted Root" "FAIL" "unknown authority" \
  "${TOOL_BIN} -cert ${PKI}/leaf_valid.crt -aia"

add_test "8. Security: Protocol" "FAIL" "unsupported.*scheme|file://.*not accepted" \
  "${TOOL_BIN} -cert file://${PKI}/leaf_valid.crt"

add_test "9. Security: DoS" "FAIL" "exceeded size limit" \
  "${TOOL_BIN} -cert ${HTTP_URL}/large_file.crt -maxcert 1024"

add_test "10. Security: Weak Cipher" "FAIL" "Weak signature algorithm|insecure algorithm|SHA1-RSA|weak signature" \
  "${TOOL_BIN} -root ${ROOT_STRONG_CRT} -cert ${WEAK_CRT}"

# CRYPTO SUITE
add_test "11. Crypto: RSA 4096" "PASS" "VALIDATION SUCCEEDED" \
  "${TOOL_BIN} -root ${PKI}/root_rsa4096.crt -cert ${PKI}/leaf_rsa4096.crt"

add_test "12. Crypto: P-256" "PASS" "VALIDATION SUCCEEDED" \
  "${TOOL_BIN} -root ${PKI}/root_ec256.crt -cert ${PKI}/leaf_ec256.crt"

add_test "13. Crypto: P-384" "PASS" "VALIDATION SUCCEEDED" \
  "${TOOL_BIN} -root ${PKI}/root_ec384.crt -cert ${PKI}/leaf_ec384.crt"

add_test "14. Crypto: P-521" "PASS" "VALIDATION SUCCEEDED" \
  "${TOOL_BIN} -root ${PKI}/root_ec521.crt -cert ${PKI}/leaf_ec521.crt"

# ADVANCED SCENARIOS
add_test "15. Mixed: RSA Root -> EC Leaf" "PASS" "VALIDATION SUCCEEDED" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${MIXED_EC_CRT} -aia"

add_test "16. Mixed: EC Root -> RSA Leaf" "PASS" "VALIDATION SUCCEEDED" \
  "${TOOL_BIN} -root ${ROOT_EC256_MIX_CRT} -cert ${RSA_FROM_EC_CRT}"

add_test "17. Constraints: Permitted" "PASS" "VALIDATION SUCCEEDED" \
  "${TOOL_BIN} -root ${ROOT_CONS_CRT} -cert ${LEAF_PERM_CRT}"

add_test "18. Constraints: Excluded" "FAIL" "excluded|not permitted|CANotAuthorizedForThisName" \
  "${TOOL_BIN} -root ${ROOT_CONS_CRT} -cert ${LEAF_EXCL_CRT}"

add_test "19. Key Usage: Client as Server" "FAIL" "incompatible key usage|key usage" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_client.crt -aia -type server"

add_test "20. Key Usage: Client as Client" "PASS" "VALIDATION SUCCEEDED" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_client.crt -aia -type client"

add_test "21. Cross: RSA vs EC (Fail)" "FAIL" "unknown authority" \
  "${TOOL_BIN} -root ${PKI}/root_ec256.crt -cert ${PKI}/leaf_valid.crt -aia"

# ---- NEW TESTS (22..30) ----

add_test "22. Ultra Silent Mode" "PASS" "" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia -ultrasilent"

add_test "23. DER Format Input" "PASS" "VALIDATION SUCCEEDED" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.der -aia"

add_test "24. Bundle: Create" "PASS" "Successfully bundled" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia -createCAbundle ${BUNDLE_OUT}"

add_test "25. Bundle: IncludeRoot" "PASS" "Included.*Root.*certificate" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia -createCAbundle ${BUNDLE_ROOT_OUT} -includeRoot"

add_test "26. Negative Size Limit" "FAIL" "size limits must be" \
  "${TOOL_BIN} -cert ${PKI}/leaf_valid.crt -maxaia=-1"

add_test "27. Time Travel: Future" "FAIL" "expired|has expired|VALIDATION FAILED" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia -at 2040-01-01T00:00:00Z"

add_test "28. DNS Name Mismatch" "FAIL" "valid for|VALIDATION FAILED" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia -dns wrong.example.com"

add_test "29. Expiry NOTICE (short-lived)" "PASS" "NOTICE.*expires soon" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${EXPIRY_SOON_CRT}"

add_test "30. Root Trust Label" "PASS" "Root Trust: Explicit User Root" \
  "${TOOL_BIN} -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia"

# ---- NEW TESTS (31..43): inspect / split / json / stdin / expiry gate ----

add_test "31. Inspect: table" "PASS" "Role" \
  "${TOOL_BIN} -inspect -cert ${PKI}/leaf_valid.crt"

add_test "32. Inspect: json" "PASS" "\"fingerprint_sha256\"" \
  "${TOOL_BIN} -inspect -json -cert ${PKI}/leaf_valid.crt"

add_test "33. Inspect: full detail" "PASS" "Public key" \
  "${TOOL_BIN} -inspect -full -cert ${PKI}/leaf_valid.crt"

add_test "34. Inspect: directory" "PASS" "Role" \
  "${TOOL_BIN} -inspect -cert ${PKI}"

add_test "35. Validate: json success" "PASS" "\"ok\": true" \
  "${TOOL_BIN} -json -root ${ROOT_CRT} -cert ${PKI}/leaf_valid.crt -aia"

add_test "36. Validate: json failure" "FAIL" "\"ok\": false" \
  "${TOOL_BIN} -json -cert ${PKI}/leaf_valid.crt"

add_test "37. Inspect: stdin" "PASS" "Role" \
  "cat ${PKI}/leaf_valid.crt | ${TOOL_BIN} -inspect -cert -"

add_test "38. Split: files" "PASS" "saved" \
  "${TOOL_BIN} -split -cert ${INTER_PEM} -outdir ${TMP}/split_out"

add_test "39. Split: json" "PASS" "\"count\"" \
  "${TOOL_BIN} -split -json -cert ${INTER_PEM} -outdir ${TMP}/split_out_json"

add_test "40. Expiry gate: -fail-expired exit 2 (at future)" "FAIL" "" \
  "${TOOL_BIN} -inspect -cert ${PKI}/leaf_valid.crt -at 2040-01-01T00:00:00Z -fail-expired -ultra-silent"

add_test "41. Error: -inspect + -split" "FAIL" "one operation" \
  "${TOOL_BIN} -inspect -split -cert ${PKI}/leaf_valid.crt"

add_test "42. Error: -json + -silent" "FAIL" "one output format" \
  "${TOOL_BIN} -json -silent -cert ${PKI}/leaf_valid.crt"

add_test "43. Validate: directory input rejected" "FAIL" "directory input requires" \
  "${TOOL_BIN} -cert ${PKI}"

add_test "44. Expiry gate: -fail-expiring within window (exit 2)" "FAIL" "" \
  "${TOOL_BIN} -inspect -cert ${PKI}/leaf_valid.crt -days 5000 -fail-expiring -ultra-silent"

add_test "45. Expiry gate: -fail-expiring outside window (exit 0)" "PASS" "" \
  "${TOOL_BIN} -inspect -cert ${PKI}/leaf_valid.crt -days 1 -fail-expiring -ultra-silent"

# ---- End of test definitions ----

run_all_tests
