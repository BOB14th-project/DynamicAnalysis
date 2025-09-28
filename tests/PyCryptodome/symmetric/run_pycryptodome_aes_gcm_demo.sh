#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
TARGET_SCRIPT="$ROOT_DIR/tests/PyCryptodome/symmetric/aes_gcm_demo.py"

PY_BIN="${PY_BIN:-$ROOT_DIR/.venv/bin/python}"
if [[ ! -x "$PY_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PY_BIN=$(command -v python3)
  else
    echo "python3 interpreter not found" >&2
    exit 1
  fi
fi

if ! "$PY_BIN" -c "import Crypto.Cipher.AES" >/dev/null 2>&1; then
  echo "[pycryptodome] module not found - skipping" >&2
  exit 0
fi

export PYCRYPTODOME_DISABLE_DEEPBIND=1
exec "$PY_BIN" "$TARGET_SCRIPT"
