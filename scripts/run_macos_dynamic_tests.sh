#!/usr/bin/env bash
# macOS test runner that mirrors the Linux/Windows workflows and
# captures quantum-vulnerable algorithms across the whole dataset.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/build-macos"
BIN_DIR="$BUILD_DIR/bin"
LIB_DIR="$BUILD_DIR/lib"
LOGS_DIR="$PROJECT_ROOT/logs"
TESTS_DIR="$PROJECT_ROOT/tests"
CLI="$BIN_DIR/dynamic_analysis_cli"
HOOK_LIB="$LIB_DIR/libhook.dylib"
ENTITLEMENTS="$SCRIPT_DIR/macos_hook_entitlements.plist"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$LOGS_DIR/backup_$TIMESTAMP"
MERGED_LOG="$LOGS_DIR/all_tests_${TIMESTAMP}.ndjson"
SUMMARY_FILE="$LOGS_DIR/summary_${TIMESTAMP}.txt"

QUANTUM_PATTERNS=(
  "RSA"
  "ECDSA"
  "ECDH"
  "DH"
  "DSA"
  "secp256k1"
  "secp256r1"
  "secp384r1"
  "secp521r1"
  "prime256v1"
)

TOTAL=0
PASSED=0
FAILED=0
DETECTED=0
VULN_SUMMARY=()

printf "%b========================================%b\n" "$BLUE" "$NC"
printf "%bmacOS Dynamic Test Sweep%b\n" "$BLUE" "$NC"
printf "%b========================================%b\n\n" "$BLUE" "$NC"

if [[ "$(uname -s)" != "Darwin" ]]; then
  printf "%bThis runner requires macOS (Darwin host).%b\n" "$RED" "$NC"
  exit 1
fi

if [[ ! -x "$CLI" ]]; then
  printf "%bdynamic_analysis_cli not found at %s%b\n" "$RED" "$CLI" "$NC"
  printf "%bBuild the macOS target first:\n  cmake -S . -B build-macos\n  cmake --build build-macos -j%b\n" "$YELLOW" "$NC"
  exit 1
fi

if [[ ! -f "$HOOK_LIB" ]]; then
  printf "%bHook library missing: %s%b\n" "$RED" "$HOOK_LIB" "$NC"
  printf "%bPlease rebuild the macOS target to regenerate libhook.dylib%b\n" "$YELLOW" "$NC"
  exit 1
fi

mkdir -p "$LOGS_DIR"

if compgen -G "$LOGS_DIR"/*.ndjson > /dev/null 2>&1; then
  printf "%bBack up previous NDJSON logs → %s%b\n" "$YELLOW" "$BACKUP_DIR" "$NC"
  mkdir -p "$BACKUP_DIR"
  mv "$LOGS_DIR"/*.ndjson "$BACKUP_DIR"/
fi

if command -v codesign >/dev/null 2>&1; then
  if [[ ! -f "$ENTITLEMENTS" ]]; then
    printf "%bEntitlements file missing: %s%b\n" "$RED" "$ENTITLEMENTS" "$NC"
    exit 1
  fi
  printf "%bPreparing binaries for DYLD insertion…%b\n" "$YELLOW" "$NC"
  for candidate in "$BIN_DIR"/*; do
    if [[ -f "$candidate" && -x "$candidate" ]]; then
      base="$(basename "$candidate")"
      [[ "$base" == "dynamic_analysis_cli" ]] && continue
      codesign --remove-signature "$candidate" >/dev/null 2>&1 || true
      codesign --force --sign - --entitlements "$ENTITLEMENTS" --timestamp=none "$candidate" >/dev/null 2>&1 || true
    fi
  done
  codesign --remove-signature "$CLI" >/dev/null 2>&1 || true
  codesign --force --sign - --entitlements "$ENTITLEMENTS" --timestamp=none "$CLI" >/dev/null 2>&1 || true
  codesign --remove-signature "$HOOK_LIB" >/dev/null 2>&1 || true
  codesign --force --sign - --entitlements "$ENTITLEMENTS" --timestamp=none "$HOOK_LIB" >/dev/null 2>&1 || true
else
  printf "%bcodesign not found; skipping automatic entitlement setup.%b\n" "$YELLOW" "$NC"
fi

TARGETS=()
for candidate in "$BIN_DIR"/*; do
  if [[ -f "$candidate" && -x "$candidate" ]]; then
    base="$(basename "$candidate")"
    [[ "$base" == "dynamic_analysis_cli" ]] && continue
    TARGETS+=("$candidate")
  fi
done

# PyCryptodome scripts run through dynamic_analysis_cli (if available)
PY_SCRIPTS=(
  "$PROJECT_ROOT/tests/PyCryptodome/symmetric/run_pycryptodome_aes_gcm_demo.sh"
  "$PROJECT_ROOT/tests/PyCryptodome/symmetric/run_pycryptodome_aes_gcm_aad_demo.sh"
  "$PROJECT_ROOT/tests/PyCryptodome/symmetric/run_pycryptodome_aes_gcm_stream_demo.sh"
)
for script in "${PY_SCRIPTS[@]}"; do
  if [[ -f "$script" && -x "$script" ]]; then
    TARGETS+=("$script")
  elif [[ -f "$script" ]]; then
    chmod +x "$script" 2>/dev/null || true
    TARGETS+=("$script")
  fi
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  printf "%bNo test binaries found under %s%b\n" "$YELLOW" "$BIN_DIR" "$NC"
  printf "%bBuild at least one target from the dataset in %s%b\n" "$YELLOW" "$TESTS_DIR" "$NC"
  exit 0
fi

IFS=$'\n' TARGETS=($(printf "%s\n" "${TARGETS[@]}" | LC_ALL=C sort))
unset IFS

run_target() {
  local target_path="$1"
  local base_name
  base_name="$(basename "$target_path")"
  local rel_path="${target_path#$PROJECT_ROOT/}"
  local log_file="$LOGS_DIR/${base_name}_${TIMESTAMP}.ndjson"
  local cli_output
  cli_output="$(mktemp)"

  printf "%b▶ %s%b\n" "$BLUE" "$rel_path" "$NC"
  TOTAL=$((TOTAL + 1))

  export HOOK_NDJSON="$log_file"

  if "$CLI" "$target_path" >"$cli_output" 2>&1; then
    PASSED=$((PASSED + 1))
    if [[ -s "$log_file" ]]; then
      local events
      events="$(wc -l <"$log_file" | tr -d '[:space:]')"
      printf "%b    captured events: %s%b\n" "$GREEN" "$events" "$NC"

      local vulnerabilities=()
      local pattern count
      for pattern in "${QUANTUM_PATTERNS[@]}"; do
        count="$( (LC_ALL=C grep -F -o "\"$pattern\"" "$log_file" || true) | wc -l | tr -d '[:space:]' )"
        if (( count > 0 )); then
          vulnerabilities+=("$pattern x$count")
        fi
      done
      if (( ${#vulnerabilities[@]} > 0 )); then
        DETECTED=$((DETECTED + 1))
        VULN_SUMMARY+=("$base_name: ${vulnerabilities[*]}")
        printf "%b    quantum-vulnerable hits: %s%b\n" "$RED" "${vulnerabilities[*]}" "$NC"
      fi

      local ciphers=()
      while IFS= read -r cipher; do
        [[ -n "$cipher" ]] && ciphers+=("$cipher")
      done < <( (grep -o '"cipher":"[^"]*"' "$log_file" || true) | cut -d'"' -f4 | LC_ALL=C sort -u )
      if (( ${#ciphers[@]} > 0 )); then
        printf "%b    ciphers: %s%b\n" "$BLUE" "${ciphers[*]}" "$NC"
      fi
    else
      printf "%b    warning: hook produced no events%b\n" "$YELLOW" "$NC"
    fi
  else
    local status=$?
    FAILED=$((FAILED + 1))
    printf "%b    dynamic_analysis_cli failed (exit %d)%b\n" "$RED" "$status" "$NC"
    if [[ -s "$cli_output" ]]; then
      sed 's/^/      /' "$cli_output"
    fi
  fi

  unset HOOK_NDJSON
  rm -f "$cli_output"
  printf "\n"
}

for target in "${TARGETS[@]}"; do
  run_target "$target"
done

cat "$LOGS_DIR"/*_"$TIMESTAMP".ndjson >"$MERGED_LOG" 2>/dev/null || true
if [[ -s "$MERGED_LOG" ]]; then
  total_events="$(wc -l <"$MERGED_LOG" | tr -d '[:space:]')"
  printf "%bMerged log: %s (%s events)%b\n" "$GREEN" "$MERGED_LOG" "$total_events" "$NC"
fi

{
  echo "macOS dynamic analysis summary ($TIMESTAMP)"
  echo "tests: $TOTAL"
  echo "passed: $PASSED"
  echo "failed: $FAILED"
  echo "quantum_vulnerable_hits: $DETECTED"
  if (( ${#VULN_SUMMARY[@]} > 0 )); then
    echo ""
    echo "vulnerable targets:"
    for entry in "${VULN_SUMMARY[@]}"; do
      echo "  - $entry"
    done
  fi
} >"$SUMMARY_FILE"

printf "%b========================================%b\n" "$BLUE" "$NC"
printf "%bCompleted %d tests · %d passed · %d failed%b\n" "$BLUE" "$TOTAL" "$PASSED" "$FAILED" "$NC"
printf "%bQuantum-vulnerable detections: %d%b\n" "$RED" "$DETECTED" "$NC"
printf "%bLogs: %s%b\n" "$BLUE" "$LOGS_DIR" "$NC"
printf "%bSummary: %s%b\n" "$BLUE" "$SUMMARY_FILE" "$NC"
