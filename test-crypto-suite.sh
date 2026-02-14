#!/bin/bash
set -e

# --- Configuration ---
TOOL_BIN="./x509-cert-validator"
PKI_DIR="test_pki_crypto"
SERVER_PORT=9092
SERVER_URL="http://localhost:${SERVER_PORT}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 1. Helper Functions ---

# Function to run the Go tool and assert results
run_test() {
  TEST_NAME="$1"
  EXPECTED_EXIT="$2"
  SEARCH_TERM="$3"
  shift 3
  CMD="$@"

  echo -e "\n${BLUE}------------------------------------------------------------${NC}"
  echo -e "${YELLOW}TEST: ${TEST_NAME}${NC}"
  echo -e "${BLUE}Command:${NC} ${CMD}"
  
  set +e
  ${CMD} > test_output.tmp 2>&1
  EXIT_CODE=$?
  set -e

  echo -e "${BLUE}Output:${NC}"
  cat test_output.tmp
  
  CONTENT_CHECK=0
  if [ -n "${SEARCH_TERM}" ]; then
    if grep -Fq "${SEARCH_TERM}" test_output.tmp; then
      echo -e "${GREEN}✅ CONTENT: Found '${SEARCH_TERM}'${NC}"
    else
      echo -e "${RED}❌ CONTENT: Expected '${SEARCH_TERM}' NOT found!${NC}"
      CONTENT_CHECK=1
    fi
  fi
  rm test_output.tmp

  # Verdict
  VERDICT="FAIL"
  if [ "${EXPECTED_EXIT}" == "PASS" ] && [ ${EXIT_CODE} -eq 0 ] && [ ${CONTENT_CHECK} -eq 0 ]; then
      VERDICT="PASS"
  elif [ "${EXPECTED_EXIT}" == "FAIL" ] && [ ${EXIT_CODE} -ne 0 ] && [ ${CONTENT_CHECK} -eq 0 ]; then
      VERDICT="PASS"
  fi

  if [ "${VERDICT}" == "PASS" ]; then
    echo -e "${GREEN}✅ RESULT: PASS${NC}"
  else
    echo -e "${RED}❌ RESULT: FAIL (Exit: ${EXIT_CODE})${NC}"
    kill ${SERVER_PID} 2>/dev/null || true
    exit 1
  fi
}

# Function to generate a full PKI chain (Root -> Inter -> Leaf) with specific crypto
generate_chain() {
    SUFFIX=$1    # e.g., rsa4096
    TYPE=$2      # rsa or ec
    PARAM=$3     # 4096 or prime256v1

    echo -e "${CYAN}>> Generating Chain: ${SUFFIX} (${TYPE} ${PARAM})...${NC}"

    # 1. Generate Keys
    if [ "$TYPE" == "rsa" ]; then
        openssl genrsa -out root_${SUFFIX}.key ${PARAM} 2>/dev/null
        openssl genrsa -out inter_${SUFFIX}.key ${PARAM} 2>/dev/null
        openssl genrsa -out leaf_${SUFFIX}.key ${PARAM} 2>/dev/null
    else
        openssl ecparam -name ${PARAM} -genkey -out root_${SUFFIX}.key 2>/dev/null
        openssl ecparam -name ${PARAM} -genkey -out inter_${SUFFIX}.key 2>/dev/null
        openssl ecparam -name ${PARAM} -genkey -out leaf_${SUFFIX}.key 2>/dev/null
    fi

    # 2. Root CA (Self-Signed)
    openssl req -x509 -new -nodes -key root_${SUFFIX}.key -out root_${SUFFIX}.crt -days 365 -subj "/CN=${SUFFIX} Root CA" -sha256 2>/dev/null

    # 3. Intermediate CA
    # We must embed the correct AIA/CRL URLs for this specific chain
    openssl req -new -key inter_${SUFFIX}.key -out inter_${SUFFIX}.csr -subj "/CN=${SUFFIX} Inter CA" 2>/dev/null
    
    cat > inter_${SUFFIX}.ext <<EOF
basicConstraints=CA:TRUE
keyUsage=keyCertSign,cRLSign
EOF
    openssl x509 -req -in inter_${SUFFIX}.csr -CA root_${SUFFIX}.crt -CAkey root_${SUFFIX}.key -CAcreateserial \
        -out inter_${SUFFIX}.crt -days 365 -extfile inter_${SUFFIX}.ext -sha256 2>/dev/null

    # 4. Leaf Certificate
    # Points to the Intermediate we just created
    openssl req -new -key leaf_${SUFFIX}.key -out leaf_${SUFFIX}.csr -subj "/CN=${SUFFIX}.local" 2>/dev/null
    
    cat > leaf_${SUFFIX}.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
subjectAltName=DNS:${SUFFIX}.local
authorityInfoAccess=caIssuers;URI:${SERVER_URL}/inter_${SUFFIX}.crt
crlDistributionPoints=URI:${SERVER_URL}/inter_${SUFFIX}.crl
EOF
    openssl x509 -req -in leaf_${SUFFIX}.csr -CA inter_${SUFFIX}.crt -CAkey inter_${SUFFIX}.key -CAcreateserial \
        -out leaf_${SUFFIX}.crt -days 365 -extfile leaf_${SUFFIX}.ext -sha256 2>/dev/null

    # 5. Generate CRL for this chain
    mkdir -p db_${SUFFIX}
    touch db_${SUFFIX}/index.txt
    echo "1000" > db_${SUFFIX}/crlnumber
    
    cat > crl_${SUFFIX}.conf <<EOF
[ ca ]
default_ca = my_ca
[ my_ca ]
dir = ./db_${SUFFIX}
database = ./db_${SUFFIX}/index.txt
crlnumber = ./db_${SUFFIX}/crlnumber
default_md = sha256
default_crl_days = 30
private_key = inter_${SUFFIX}.key
certificate = inter_${SUFFIX}.crt
default_days = 365
EOF
    # Initialize CRL
    openssl ca -gencrl -config crl_${SUFFIX}.conf -out inter_${SUFFIX}.crl 2>/dev/null
}

# --- 2. Setup ---

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

echo -e "${YELLOW}=== 2. Generating Crypto Suite ===${NC}"
rm -rf ${PKI_DIR}
mkdir -p ${PKI_DIR}
cd ${PKI_DIR}

# --- Generate 5 Chains ---
generate_chain "rsa2048" "rsa" "2048"
generate_chain "rsa4096" "rsa" "4096"
generate_chain "ec256"   "ec"  "prime256v1" # P-256
generate_chain "ec384"   "ec"  "secp384r1"  # P-384
generate_chain "ec521"   "ec"  "secp521r1"  # P-521

# --- Start Server ---
echo -e "${YELLOW}=== 3. Starting Artifact Server ===${NC}"
python3 -m http.server ${SERVER_PORT} > server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: ${SERVER_PID}"
sleep 2

if ! kill -0 ${SERVER_PID} 2>/dev/null; then
  echo -e "${RED}❌ Server failed to start!${NC}"
  cat server.log
  exit 1
fi

# --- 3. Run Tests ---
echo -e "${YELLOW}=== 4. Executing Validation Tests ===${NC}"

# 1. RSA 2048 (Baseline)
run_test "RSA 2048 (Baseline)" "PASS" "VALIDATION SUCCEEDED" \
  ../${TOOL_BIN} -root root_rsa2048.crt -cert leaf_rsa2048.crt -aia -crl

# 2. RSA 4096 (Large Key)
run_test "RSA 4096 (Large Key)" "PASS" "VALIDATION SUCCEEDED" \
  ../${TOOL_BIN} -root root_rsa4096.crt -cert leaf_rsa4096.crt -aia -crl

# 3. EC P-256 (Standard)
run_test "ECDSA P-256" "PASS" "VALIDATION SUCCEEDED" \
  ../${TOOL_BIN} -root root_ec256.crt -cert leaf_ec256.crt -aia -crl

# 4. EC P-384 (High Security)
run_test "ECDSA P-384" "PASS" "VALIDATION SUCCEEDED" \
  ../${TOOL_BIN} -root root_ec384.crt -cert leaf_ec384.crt -aia -crl

# 5. EC P-521 (Maximum Security)
run_test "ECDSA P-521" "PASS" "VALIDATION SUCCEEDED" \
  ../${TOOL_BIN} -root root_ec521.crt -cert leaf_ec521.crt -aia -crl

# 6. Cross-Protocol Test (Sanity Check)
# Trying to validate an EC leaf against an RSA Root (where chain is broken/mismatched) should fail
run_test "Mismatched Root (EC Leaf vs RSA Root)" "FAIL" "certificate signed by unknown authority" \
  ../${TOOL_BIN} -root root_rsa2048.crt -cert leaf_ec256.crt -aia

# Cleanup
echo -e "\n${BLUE}Stopping background server...${NC}"
kill ${SERVER_PID} 2>/dev/null || true

cd ..
echo -e "\n${GREEN}🎉 CRYPTO SUITE TESTS PASSED! 🎉${NC}"