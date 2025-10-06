#!/usr/bin/env bash
# run_all_dynamic_tests.sh
# Runs dynamic_analysis_cli against every supported test binary.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

CLI=
if [[ -x "$ROOT_DIR/build-linux/bin/dynamic_analysis_cli" ]]; then
  CLI="$ROOT_DIR/build-linux/bin/dynamic_analysis_cli"
  BIN_DIR="$ROOT_DIR/build-linux/bin"
elif [[ -x "$ROOT_DIR/build-windows/bin/Release/dynamic_analysis_cli.exe" ]]; then
  CLI="$ROOT_DIR/build-windows/bin/Release/dynamic_analysis_cli.exe"
  BIN_DIR="$ROOT_DIR/build-windows/bin/Release"
elif [[ -x "$ROOT_DIR/build/bin/dynamic_analysis_cli" ]]; then
  CLI="$ROOT_DIR/build/bin/dynamic_analysis_cli"
  BIN_DIR="$ROOT_DIR/build/bin"
else
  echo "dynamic_analysis_cli not found." >&2
  echo "Please build the project first, e.g.:" >&2
  echo "  cmake -S . -B build-linux && cmake --build build-linux -j" >&2
  echo "or" >&2
  echo "  cmake -S . -B build-windows -G \"Visual Studio 17 2022\" -A x64" >&2
  echo "    cmake --build build-windows --config Release" >&2
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
  boringssl_aes_gcm_roundtrip_demo
  boringssl_chacha20_poly1305_demo
  boringssl_xchacha20_poly1305_demo
  tests/PyCryptodome/symmetric/run_pycryptodome_aes_gcm_demo.sh
  tests/PyCryptodome/symmetric/run_pycryptodome_aes_gcm_aad_demo.sh
  tests/PyCryptodome/symmetric/run_pycryptodome_aes_gcm_stream_demo.sh
  af_alg_skcipher_aes_cbc_demo
  af_alg_aes_gcm_demo
  af_alg_hmac_sha256_demo
  af_alg_akcipher_demo
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
  local path
  if [[ "$target" == */* ]]; then
    path="$ROOT_DIR/$target"
  else
    path="$BIN_DIR/$target"
  fi
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
