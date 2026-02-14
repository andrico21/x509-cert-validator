#!/bin/bash
set -e

# --- Configuration ---
TOOL_BIN="./x509-cert-validator"
PKI_DIR="test_pki_verbose"
SERVER_PORT=9091
SERVER_URL="http://localhost:${SERVER_PORT}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Helper functions
run_test() {
  TEST_NAME="$1"
  EXPECTED_EXIT="$2"
  SEARCH_TERM="$3" # New: Optional text to search for in output
  shift 3
  CMD="$@"

  echo -e "\n${BLUE}------------------------------------------------------------${NC}"
  echo -e "${YELLOW}TEST: ${TEST_NAME}${NC}"
  echo -e "${BLUE}Command:${NC} ${CMD}"

  # --- CRITICAL: Disable 'set -e' for the command execution ---
  set +e
  ${CMD} > test_output.tmp 2>&1
  EXIT_CODE=$?
  set -e
  # ------------------------------------------------------------

  echo -e "${BLUE}Output:${NC}"
  cat test_output.tmp

  # 1. Content Verification (If search term provided)
  CONTENT_CHECK=0
  if [ -n "${SEARCH_TERM}" ]; then
    # FIX: Use -F to treat search term as a fixed string, preventing regex errors with brackets []
    if grep -Fq "${SEARCH_TERM}" test_output.tmp; then
      echo -e "${GREEN}✅ CONTENT: Found expected text: '${SEARCH_TERM}'${NC}"
    else
      echo -e "${RED}❌ CONTENT: Expected text '${SEARCH_TERM}' NOT found!${NC}"
      CONTENT_CHECK=1
    fi
  fi

  rm test_output.tmp

  echo -e "${BLUE}Exit Code:${NC} ${EXIT_CODE}"

  # 2. Server Liveness Check
  if ! kill -0 ${SERVER_PID} 2>/dev/null; then
    echo -e "${RED}⚠️  CRITICAL: Background Webserver died unexpectedly!${NC}"
    echo -e "${RED}--- Server Logs ---${NC}"
    cat server.log
    echo -e "${RED}-------------------${NC}"
    exit 1
  fi

  # 3. Final Verdict Logic
  VERDICT="FAIL"
  if [ "${EXPECTED_EXIT}" == "PASS" ]; then
    if [ ${EXIT_CODE} -eq 0 ] && [ ${CONTENT_CHECK} -eq 0 ]; then
      VERDICT="PASS"
    fi
  else # EXPECTED_EXIT == FAIL
    if [ ${EXIT_CODE} -ne 0 ] && [ ${CONTENT_CHECK} -eq 0 ]; then
      VERDICT="PASS"
    fi
  fi

  if [ "${VERDICT}" == "PASS" ]; then
    echo -e "${GREEN}✅ RESULT: PASS${NC}"
  else
    echo -e "${RED}❌ RESULT: FAIL${NC}"
    kill ${SERVER_PID} 2>/dev/null || true
    exit 1
  fi
}

# Ensure binary exists
if [ ! -f "${TOOL_BIN}" ]; then
  echo "❌ Binary '${TOOL_BIN}' not found. Build it first."
  exit 1
fi

echo -e "${YELLOW}=== 1. Cleaning Port ${SERVER_PORT} ===${NC}"
if command -v fuser &> /dev/null; then
    fuser -k ${SERVER_PORT}/tcp > /dev/null 2>&1 || true
elif command -v lsof &> /dev/null; then
    PID=$(lsof -ti tcp:${SERVER_PORT})
    if [ ! -z "$PID" ]; then kill -9 $PID; fi
fi
sleep 1

echo -e "${YELLOW}=== 2. Setting up Test Environment ===${NC}"
rm -rf ${PKI_DIR}
mkdir -p ${PKI_DIR}
cd ${PKI_DIR}

# --- Standard PKI (Root -> Inter -> Leaf) ---
echo "Generating Standard Root CA..."
openssl req -x509 -new -nodes -newkey rsa:2048 -keyout root.key -out root.crt -days 365 -subj "/CN=Test Root CA" 2>/dev/null

echo "Generating Intermediate CA..."
openssl genrsa -out inter.key 2048 2>/dev/null
openssl req -new -key inter.key -out inter.csr -subj "/CN=Test Intermediate CA" 2>/dev/null
cat > inter.ext <<EOF
basicConstraints=CA:TRUE
keyUsage=keyCertSign,cRLSign
EOF
openssl x509 -req -in inter.csr -CA root.crt -CAkey root.key -CAcreateserial -out inter.crt -days 365 -extfile inter.ext 2>/dev/null

cat > leaf.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=DNS:valid.local
authorityInfoAccess=caIssuers;URI:${SERVER_URL}/inter.crt
crlDistributionPoints=URI:${SERVER_URL}/inter.crl
EOF

echo "Generating Valid Leaf..."
openssl genrsa -out valid.key 2048 2>/dev/null
openssl req -new -key valid.key -out valid.csr -subj "/CN=valid.local" 2>/dev/null
openssl x509 -req -in valid.csr -CA inter.crt -CAkey inter.key -CAcreateserial -out valid.crt -days 365 -extfile leaf.ext 2>/dev/null

echo "Generating Revoked Leaf..."
openssl genrsa -out revoked.key 2048 2>/dev/null
openssl req -new -key revoked.key -out revoked.csr -subj "/CN=revoked.local" 2>/dev/null
openssl x509 -req -in revoked.csr -CA inter.crt -CAkey inter.key -CAcreateserial -out revoked.crt -days 365 -extfile leaf.ext 2>/dev/null

echo "Generating CRL..."
mkdir -p demoCA
touch demoCA/index.txt
echo "1000" > demoCA/crlnumber
cat > crl.conf <<EOF
[ ca ]
default_ca = my_ca
[ my_ca ]
dir = ./demoCA
database = ./demoCA/index.txt
crlnumber = ./demoCA/crlnumber
default_md = sha256
default_crl_days = 30
private_key = inter.key
certificate = inter.crt
default_days = 365
EOF
openssl ca -config crl.conf -revoke revoked.crt -batch 2>/dev/null || true
openssl ca -gencrl -config crl.conf -out inter.crl 2>/dev/null

# --- Weak PKI (Strong Root -> SHA1 Leaf) ---
echo "Generating Weak Crypto Chain..."
# 1. Strong Root for Weak Chain
openssl req -x509 -new -nodes -newkey rsa:2048 -keyout root_strong.key -out root_strong.crt -days 365 -subj "/CN=Strong Root CA" -sha256 2>/dev/null
# 2. Weak Leaf (SHA-1 Signed)
openssl genrsa -out weak.key 2048 2>/dev/null
openssl req -new -key weak.key -out weak.csr -subj "/CN=weak-algo.local" 2>/dev/null
openssl x509 -req -in weak.csr -CA root_strong.crt -CAkey root_strong.key -CAcreateserial -out weak_sha1.crt -days 365 -sha1 2>/dev/null

# --- DoS Files ---
echo "Generating Large File..."
dd if=/dev/zero of=large_file.crt bs=1M count=10 2>/dev/null

# --- Start Server ---
echo -e "${YELLOW}=== 3. Starting AIA/CRL Server ===${NC}"
python3 -m http.server ${SERVER_PORT} > server.log 2>&1 &
SERVER_PID=$!
echo "Server process ID: ${SERVER_PID}"
sleep 2

if ! kill -0 ${SERVER_PID} 2>/dev/null; then
  echo -e "${RED}❌ Server failed to start!${NC}"
  cat server.log
  exit 1
fi

# --- Run Tests ---
echo -e "${YELLOW}=== 4. Execution Tests (Verbose) ===${NC}"

# Test 1
run_test "AIA Auto-Fetch (Valid Chain)" "PASS" "" \
  ../${TOOL_BIN} -root root.crt -cert valid.crt -aia

# Test 2
run_test "Missing Intermediate (No AIA)" "FAIL" "" \
  ../${TOOL_BIN} -root root.crt -cert valid.crt

# Test 3
run_test "CRL Check (Valid Cert)" "PASS" "CRL CHECK PASSED" \
  ../${TOOL_BIN} -root root.crt -cert valid.crt -aia -crl

# Test 4
run_test "CRL Check (Revoked Cert)" "FAIL" "certificate CN=revoked.local is REVOKED" \
  ../${TOOL_BIN} -root root.crt -cert revoked.crt -aia -crl

# Test 5
run_test "Graph Visualization" "PASS" "ROOT ANCHOR" \
  ../${TOOL_BIN} -root root.crt -cert valid.crt -aia -showGraph

# Test 6
run_test "Silent Mode" "PASS" "PASS [valid.local]" \
  ../${TOOL_BIN} -root root.crt -cert valid.crt -aia -silent

# Test 7
run_test "Untrusted Root (System Default)" "FAIL" "unknown authority" \
  ../${TOOL_BIN} -cert valid.crt -aia

# Test 8: Security - Protocol Smuggling
run_test "Security: Block file:// Protocol" "FAIL" "read error" \
  ../${TOOL_BIN} -cert file://$(pwd)/valid.crt

# Test 9: Security - Large File DoS
run_test "Security: Large File DoS Protection" "FAIL" "File reached size limit" \
  ../${TOOL_BIN} -cert ${SERVER_URL}/large_file.crt

# Test 10: Weak Ciphers (SHA-1)
# We expect FAIL (Exit 1) AND specific warning text
run_test "Security: Weak Cipher (SHA-1)" "FAIL" "Weak signature algorithm" \
  ../${TOOL_BIN} -root root_strong.crt -cert weak_sha1.crt

# Cleanup
echo -e "\n${BLUE}Stopping background server...${NC}"
kill ${SERVER_PID} 2>/dev/null || true

cd ..
echo -e "\n${GREEN}🎉 ALL 10 TESTS PASSED! 🎉${NC}"