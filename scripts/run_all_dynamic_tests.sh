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
  aes_lib_test
  symm_aes_gcm_test
  ecc_sign_test
  ecc_ECIES_test
  openssl3_ex2_test
  openssl3_ex2_params_test
  demo_target
)

# Include Java detector only if it was built (requires JNI).
OPTIONAL_TESTS=(java_process_detector)

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
