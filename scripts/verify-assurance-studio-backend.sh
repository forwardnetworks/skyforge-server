#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"

server_dir="$repo_root/skyforge-server"
portal_dir="$repo_root/skyforge-portal"

echo "[1/4] Backend: encore check"
cd "$server_dir"
encore check ./...

echo "[2/4] Backend: go test (compile + unit tests) (ENCORERUNTIME_NOPANIC=1)"
ENCORERUNTIME_NOPANIC=1 go test ./...

echo "[3/4] Frontend: ensure Assurance Studio uses unified evaluate endpoint"
cd "$portal_dir"
route_file="src/routes/dashboard/fwd/\$networkRef.assurance-studio.tsx"

if rg -n "postAssuranceStudioEvaluate" "$route_file" >/dev/null; then
  : # ok
else
  echo "ERROR: expected $route_file to call postAssuranceStudioEvaluate"
  exit 1
fi

# Guard against accidentally reintroducing separate backend calls for the Assurance Studio page.
if rg -n "postAssuranceTrafficEvaluate|postForwardNetworkCapacityPathBottlenecks|runWorkspacePolicyReportPathsEnforcementBypass" "$route_file" >/dev/null; then
  echo "ERROR: found legacy Assurance Studio calls in $route_file"
  exit 1
fi

echo "[4/4] Frontend: type-check"
if command -v pnpm >/dev/null 2>&1; then
  pnpm -s run type-check || pnpm -s run typecheck
elif command -v npm >/dev/null 2>&1; then
  npm -s run type-check || npm -s run typecheck
else
  echo "WARN: pnpm/npm not found; skipped portal type-check"
fi

echo "OK"
