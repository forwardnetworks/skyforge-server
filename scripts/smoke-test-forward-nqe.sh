#!/usr/bin/env bash
set -euo pipefail

# Smoke-test running Skyforge Policy Report .nqe checks directly against Forward's /api/nqe.
#
# This does NOT persist credentials anywhere. Provide them via environment variables.
#
# Required:
#   FWD_USERNAME
#   FWD_PASSWORD
#   FWD_NETWORK_ID
#
# Optional:
#   FWD_BASE_URL       (default: https://fwd.app)
#   FWD_SNAPSHOT_ID    (default: empty -> latest processed on Forward side)
#   FWD_MAX_NUM_ITEMS  (default: 50)
#   FWD_MAX_SECONDS    (default: 30)
#   FWD_SKIP_TLS_VERIFY (default: false)
#
# Notes:
# - This is a "does it execute" harness, not a correctness oracle.
# - For checks that require parameters, we pass reasonable placeholders that should
#   still run even if they yield no matches.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKS_DIR="$ROOT_DIR/skyforge/policy_reports_assets/checks"

: "${FWD_USERNAME:?FWD_USERNAME is required}"
: "${FWD_PASSWORD:?FWD_PASSWORD is required}"
: "${FWD_NETWORK_ID:?FWD_NETWORK_ID is required}"

FWD_BASE_URL="${FWD_BASE_URL:-https://fwd.app}"
FWD_SNAPSHOT_ID="${FWD_SNAPSHOT_ID:-}"
FWD_MAX_NUM_ITEMS="${FWD_MAX_NUM_ITEMS:-50}"
FWD_MAX_SECONDS="${FWD_MAX_SECONDS:-30}"
FWD_SKIP_TLS_VERIFY="${FWD_SKIP_TLS_VERIFY:-false}"

auth_b64="$(printf '%s:%s' "$FWD_USERNAME" "$FWD_PASSWORD" | base64)"

curl_tls_args=()
if [[ "${FWD_SKIP_TLS_VERIFY}" == "true" ]]; then
  curl_tls_args+=(-k)
fi

have_jq=false
if command -v jq >/dev/null 2>&1; then
  have_jq=true
fi

run_check() {
  local check_id="$1"
  local query_path="$CHECKS_DIR/$check_id"
  if [[ ! -f "$query_path" ]]; then
    echo "ERROR: missing check file: $query_path" >&2
    return 1
  fi

  local query_text
  query_text="$(cat "$query_path")"

  # Parameters for parameterized checks.
  # Use placeholders that should parse and run in most environments.
  local params_json="null"
  case "$check_id" in
    acl-flow-decision.nqe|acl-flow-to-rules.nqe)
      params_json='{"srcIp":"10.0.0.1","dstIp":"10.0.0.2","ipProto":6,"dstPort":443,"firewallsOnly":true,"includeImplicitDefault":false}'
      ;;
    nat-flow-matches.nqe)
      params_json='{"srcIp":"10.0.0.1","dstIp":"10.0.0.2","ipProto":6,"dstPort":443}'
      ;;
    acl-any-to-zone-any-service.nqe)
      params_json='{"dstSubnets":["10.1.0.0/16"],"firewallsOnly":true,"includeImplicitDefault":false}'
      ;;
    acl-any-to-zone-sensitive-ports.nqe)
      params_json='{"dstSubnets":["10.1.0.0/16"],"sensitivePorts":[22,23,3389,445],"firewallsOnly":true,"includeImplicitDefault":false}'
      ;;
    acl-zone-to-zone-any-service.nqe)
      params_json='{"srcSubnets":["10.0.0.0/8"],"dstSubnets":["10.1.0.0/16"],"firewallsOnly":true,"includeImplicitDefault":false}'
      ;;
    acl-zone-to-zone-sensitive-ports.nqe)
      params_json='{"srcSubnets":["10.0.0.0/8"],"dstSubnets":["10.1.0.0/16"],"sensitivePorts":[22,23,3389,445],"firewallsOnly":true,"includeImplicitDefault":false}'
      ;;
  esac

  local query_opts_json
  query_opts_json="$(printf '{"maxNumItems":%s,"maxSeconds":%s}' "$FWD_MAX_NUM_ITEMS" "$FWD_MAX_SECONDS")"

  # Build payload without needing jq (use python3 to render JSON safely).
  local payload
  payload="$(python3 - <<PY
import json,sys
query_text = open(${query_path!r}, "r", encoding="utf-8").read()
payload = {"query": query_text, "queryOptions": json.loads(${query_opts_json!r})}
params_raw = ${params_json!r}
if params_raw != "null":
  payload["parameters"] = json.loads(params_raw)
print(json.dumps(payload))
PY
)"

  local url="${FWD_BASE_URL%/}/api/nqe?networkId=${FWD_NETWORK_ID}"
  if [[ -n "$FWD_SNAPSHOT_ID" ]]; then
    url="${url}&snapshotId=${FWD_SNAPSHOT_ID}"
  fi

  echo "-> $check_id"
  local body_file
  body_file="$(mktemp)"
  local status
  status="$(curl -sS "${curl_tls_args[@]}" -o "$body_file" -w '%{http_code}' \
    -X POST "$url" \
    -H 'accept: application/json' \
    -H "Authorization: Basic ${auth_b64}" \
    -H 'Content-Type: application/json' \
    -d "$payload")"

  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    echo "ERROR: Forward /api/nqe returned HTTP $status for $check_id" >&2
    # Print a small snippet for debugging (avoid huge output).
    head -c 2000 "$body_file" >&2 || true
    echo >&2
    rm -f "$body_file"
    return 1
  fi

  if $have_jq; then
    # Ensure we got an object with array results (Forward may use "results" or "items").
    if ! jq -e 'type=="object" and ((.results|type=="array") or (.items|type=="array"))' "$body_file" >/dev/null; then
      echo "ERROR: response JSON shape unexpected for $check_id" >&2
      head -c 2000 "$body_file" >&2 || true
      echo >&2
      rm -f "$body_file"
      return 1
    fi
    total="$(jq -r '.total // .totalNumItems // 0' "$body_file" 2>/dev/null || echo 0)"
    snap="$(jq -r '.snapshotId // ""' "$body_file" 2>/dev/null || echo "")"
    echo "   ok: total=${total} snapshotId=${snap}"
  else
    echo "   ok"
  fi

  rm -f "$body_file"
}

echo "Forward NQE smoke test"
echo "  baseUrl=${FWD_BASE_URL}"
echo "  networkId=${FWD_NETWORK_ID}"
echo "  snapshotId=${FWD_SNAPSHOT_ID:-<default>}"

checks=(
  aws-sg-ingress-sensitive-ports.nqe
  aws-sg-ingress-any-service.nqe
  aws-sg-egress-any-service.nqe
  acl-any-any-permit.nqe
  acl-any-to-rfc1918-sensitive-ports.nqe
  acl-any-to-zone-any-service.nqe
  acl-any-to-zone-sensitive-ports.nqe
  acl-zone-to-zone-any-service.nqe
  acl-zone-to-zone-sensitive-ports.nqe
  acl-flow-decision.nqe
  acl-flow-to-rules.nqe
  nat-flow-matches.nqe
  acl-shadowed-rules.nqe
  acl-partial-shadowed-rules.nqe
  acl-unreachable-rules.nqe
  acl-redundant-rules.nqe
  acl-overlap-conflicts.nqe
  acl-unused-permits-days.nqe
  acl-never-hit-permits.nqe
  acl-new-permits-30d.nqe
  acl-modified-permits-30d.nqe
  acl-stale-permits-30d.nqe
  default-route-urpf-heuristic.nqe
  ospf-passive-default.nqe
)

for c in "${checks[@]}"; do
  run_check "$c"
done

echo "OK: all checks executed successfully"

