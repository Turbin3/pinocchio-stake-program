#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/export_rust.sh [OUTPUT_FILE]
# Default output file: repo_rust_code.txt at repo root

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_FILE="${1:-${ROOT_DIR}/repo_rust_code.txt}"

rm -f "$OUT_FILE"
touch "$OUT_FILE"

# Collect and append all Rust source files under program/
files_count=0
while IFS= read -r -d '' f; do
  rel="${f#$ROOT_DIR/}"
  {
    echo "===== FILE: ${rel} ====="
    cat "$f"
    echo
  } >> "$OUT_FILE"
  files_count=$((files_count+1))
done < <(cd "$ROOT_DIR" && find program -type f -name '*.rs' -print0 | sort -z)

echo "Wrote ${files_count} files to $OUT_FILE"
