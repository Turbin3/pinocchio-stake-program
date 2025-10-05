#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"   # program/
REPO_DIR="$(cd "$ROOT_DIR/.." && pwd)"                         # repo root
OUT="$REPO_DIR/instructions_dump.txt"
SRC_DIR="$ROOT_DIR/src/instruction"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "instruction directory not found: $SRC_DIR" >&2
  exit 1
fi

echo "Writing $OUT" >&2
{
  echo "# Pinocchio Stake – instruction sources"
  echo
  for f in $(ls -1 "$SRC_DIR"/*.rs | sort); do
    echo "===== ${f#$ROOT_DIR/} ====="
    cat "$f"
    echo
  done
} > "$OUT"

echo "Done: $OUT" >&2
