#!/usr/bin/env bash
# run_all_dynamic_tests.sh
# Runs dynamic_analysis_cli against every supported test binary.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BIN_DIR="$ROOT_DIR/build/bin"
CLI="$BIN_DIR/dynamic_analysis_cli"

if [[ ! -x "$CLI" ]]; then
  echo "dynamic_analysis_cli not found at $CLI" >&2
  echo "Please build the project first: cmake -S . -B build && cmake --build build -j" >&2
  exit 1
fi

TESTS=(
  openssl_aes_lib_test
  openssl_symm_aes_gcm_test
  openssl_ecc_sign_test
  openssl_ecc_ecies_test
  openssl_provider_ex2_test
  openssl_provider_ex2_params_test
)

# Include Java detector only if it was built (requires JNI).
OPTIONAL_TESTS=(java_process_detector)

# libsodium demo is optional: build depends on having libsodium headers.
OPTIONAL_TESTS+=(
  libsodium_chacha20_poly1305_demo
  libsodium_xchacha20_poly1305_demo
  libsodium_secretbox_demo
  libsodium_box_demo
  libsodium_sign_demo
  gnutls_aes_gcm_demo
  gnutls_aes_gcm_roundtrip_demo
  gnutls_aes_cbc_demo
  nss_aes_gcm_demo
  nss_aes_gcm_roundtrip_demo
  nss_aes_cbc_demo
  mbedtls_aes_gcm_demo
  mbedtls_hmac_sha256_demo
  mbedtls_ecdsa_demo
  mbedtls_rsa_demo
  boringssl_aes_gcm_demo
  af_alg_skcipher_aes_cbc_demo
  af_alg_aes_gcm_demo
  af_alg_hmac_sha256_demo
  wolfssl_aes_gcm_demo
  wolfssl_aes_cbc_demo
  wolfssl_hmac_sha256_demo
  cryptodev_aes_cbc_demo
  cryptodev_hmac_sha256_demo
  cryptodev_rsa_demo
)

STATUS=0

run_test() {
  local target=$1
  local path="$BIN_DIR/$target"
  if [[ ! -x "$path" ]]; then
    echo "[skip] $target (binary not found)" >&2
    return
  fi

  echo
  echo "=== $target ==="
  "$CLI" "$path" || STATUS=$?
}

for t in "${TESTS[@]}"; do
  run_test "$t"
  if [[ $STATUS -ne 0 ]]; then
    echo "[warn] $t exited with status $STATUS" >&2
    STATUS=0
  fi
done

for t in "${OPTIONAL_TESTS[@]}"; do
  run_test "$t"
  if [[ $STATUS -ne 0 ]]; then
    echo "[warn] $t exited with status $STATUS" >&2
    STATUS=0
  fi
done

echo
echo "All requested dynamic analysis runs completed."
