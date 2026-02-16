#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SEARCH_PATHS=(
  "skyforge"
  "internal"
  "cmd"
  "worker"
)

echo "[owner-contract] verifying owner-first API/runtime markers..."

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

rg -n -g '*.go' \
  'json:"scopeId"|json:"workspaceId"|/api/scopes|/api/workspaces|\["scopeId"\]|\["workspaceId"\]' \
  "${SEARCH_PATHS[@]}" >"$tmp" || true

# Legacy-removal comments are allowed as historical notes.
if [[ -s "$tmp" ]]; then
  grep -v 'Deprecated public route removed' "$tmp" >"$tmp.filtered" || true
  mv "$tmp.filtered" "$tmp"
fi

if [[ -s "$tmp" ]]; then
  echo "[owner-contract] found legacy workspace/scope API markers:"
  cat "$tmp"
  exit 1
fi

echo "[owner-contract] OK"
