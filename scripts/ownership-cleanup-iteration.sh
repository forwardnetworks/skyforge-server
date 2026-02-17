#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATUS_SCRIPT="$ROOT/scripts/ownership-cleanup-status.sh"
ITERATION="${1:-1}"

if ! [[ "$ITERATION" =~ ^[0-9]+$ ]]; then
  ITERATION=1
fi

if [[ ! -x "$STATUS_SCRIPT" ]]; then
  echo "missing status script: $STATUS_SCRIPT" >&2
  exit 1
fi

status_output=$(OWNERSHIP_CLEANUP_ITERATION="$ITERATION" "$STATUS_SCRIPT")
echo "$status_output"

total=$(echo "$status_output" | awk -F': ' '/^  total_active_refs:/ { print $2 }')

if [[ -z "$total" ]]; then
  echo "[ownership-cleanup] unable to parse total_active_refs" >&2
  exit 3
fi

if [[ "$total" -gt 0 ]]; then
  echo
  echo "[ownership-cleanup] not complete: $total active references remain" >&2
  exit 2
fi

echo
echo "[ownership-cleanup] complete: no active legacy references"
