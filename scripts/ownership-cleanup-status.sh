#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ITERATION="${1:-${OWNERSHIP_CLEANUP_ITERATION:-1}}"
if ! [[ "$ITERATION" =~ ^[0-9]+$ ]]; then
  ITERATION=1
fi

legacy_token="$(printf '\167\157\162\153\163\160\141\143\145')"
workspace_pattern="\\b${legacy_token}s?\\b|${legacy_token}[A-Z][[:alnum:]_]*|${legacy_token}_[[:alnum:]_]+|${legacy_token}Id|${legacy_token}Key"
scan_scope="${OWNERSHIP_SCOPE_SCAN:-0}"
scope_pattern="\\bscope\\b|scopeId|scopeKey"
schema_match_filter='(^|[^[:alnum:]_])(sf_workspace|workspace_)[[:alnum:]_]+($|[^[:alnum:]_])'

count_matches() {
  local matches=$1
  if [[ -z "$matches" ]]; then
    echo 0
  else
    printf '%s\n' "$matches" | wc -l | tr -d ' '
  fi
}

filter_schema() {
  awk -F: -v pat="$schema_match_filter" '
  {
    text=$0
    sub(/^[^:]+:[0-9]+:/, "", text)
    if (text !~ pat) print $0
  }'
}

server_matches=$(rg -n -S -i "$workspace_pattern" "$ROOT/skyforge" "$ROOT/internal" \
  --glob '!**/frontend_dist/**' \
  --glob '!**/openapi.json' \
  --glob '!**/docs/**' \
  --glob '!**/*_test.go' \
  --glob '!**/migrations/**' 2>/dev/null | filter_schema || true)

portal_matches=$(rg -n -S -i "$workspace_pattern" "$ROOT/../skyforge-portal/src" \
  --glob '!**/openapi.gen.ts' \
  --glob '!**/routeTree.gen.ts' 2>/dev/null | filter_schema || true)

server_count=$(count_matches "$server_matches")
portal_count=$(count_matches "$portal_matches")
scope_count=0
if [[ "$scan_scope" == "1" ]]; then
  scope_matches=$(rg -n -S "$scope_pattern" "$ROOT/skyforge" "$ROOT/internal" "$ROOT/../skyforge-portal/src" \
    --glob '!**/frontend_dist/**' \
    --glob '!**/openapi.gen.ts' \
    --glob '!**/routeTree.gen.ts' \
    --glob '!**/docs/**' \
    --glob '!**/*_test.go' \
    --glob '!**/migrations/**' 2>/dev/null || true)
  scope_count=$(count_matches "$scope_matches")
fi

echo "[ownership-cleanup] status"
echo "[ownership-cleanup] iteration: $ITERATION"

echo "  server_active_refs: $server_count"
echo "  portal_active_refs: $portal_count"
echo "  total_active_refs: $((server_count + portal_count))"
echo "  scope_active_refs: $scope_count"

echo
echo "[ownership-cleanup] top server files"
if [[ -n "$server_matches" ]]; then
  printf '%s\n' "$server_matches" | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 20
else
  echo "  (no active server references found)"
fi

echo
echo "[ownership-cleanup] top portal files"
if [[ -n "$portal_matches" ]]; then
  printf '%s\n' "$portal_matches" | cut -d: -f1 | sort | uniq -c | sort -nr | head -n 20
else
  echo "  (no active portal references found)"
fi
