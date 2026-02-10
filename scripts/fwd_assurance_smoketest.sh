#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CREDS_FILE="${FWD_CREDS_FILE:-"$ROOT_DIR/../fwdcreds.env"}"

if [[ -f "$CREDS_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CREDS_FILE"
fi

if [[ -z "${FWD_HOST:-}" || -z "${FWD_USER:-}" || -z "${FWD_PASS:-}" || -z "${FWD_NETWORK_ID:-}" ]]; then
  echo "Missing Forward env. Expected FWD_HOST, FWD_USER, FWD_PASS, FWD_NETWORK_ID."
  echo "Set them in env or in $CREDS_FILE."
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required"
  exit 1
fi

base_url="$FWD_HOST"
if [[ "$base_url" != http*://* ]]; then
  base_url="https://$base_url"
fi
base_url="${base_url%/}"

curl_flags=(-sS --fail -u "$FWD_USER:$FWD_PASS" -H 'content-type: application/json')
if [[ "${FWD_INSECURE:-}" == "1" ]]; then
  curl_flags+=(-k)
fi

api_get() {
  local path="$1"
  curl "${curl_flags[@]}" "$base_url$path"
}

api_post() {
  local path="$1"
  local body="$2"
  curl "${curl_flags[@]}" -X POST --data-binary "$body" "$base_url$path"
}

read_file_json_string() {
  local p="$1"
  jq -Rs . <"$p"
}

echo "[1/7] Fetch latest processed snapshot..."
snap_json="$(api_get "/api/networks/${FWD_NETWORK_ID}/snapshots/latestProcessed")"
snapshot_id="$(jq -r '.id // .snapshotId // empty' <<<"$snap_json")"
if [[ -z "$snapshot_id" || "$snapshot_id" == "null" ]]; then
  echo "Failed to parse snapshot id from latestProcessed:"
  echo "$snap_json"
  exit 1
fi
echo "snapshotId=$snapshot_id"

echo "[2/7] Run NQE: traffic seed endpoints..."
seed_q="$ROOT_DIR/internal/trafficassets/traffic_assets/queries/traffic-seed-endpoints.nqe"
seed_query="$(read_file_json_string "$seed_q")"
seed_body="$(jq -n \
  --argjson query "$seed_query" \
  '{query:$query, parameters:{tagParts:[], nameParts:[], deviceTypes:[], includeGroups:true}}')"
seed_out="$(api_post "/api/nqe?networkId=${FWD_NETWORK_ID}&snapshotId=${snapshot_id}" "$seed_body")"
seed_n="$(jq -r '.totalNumItems // (.items|length) // 0' <<<"$seed_out")"
echo "seed items=$seed_n"

src_dev="$(jq -r '.items[0].deviceName // empty' <<<"$seed_out")"
src_ip="$(jq -r '.items[0].mgmtIp // empty' <<<"$seed_out")"
dst_ip="$(jq -r --arg src "$src_ip" '.items[]? | select((.mgmtIp // "") != $src) | .mgmtIp' <<<"$seed_out" | head -n 1)"
if [[ -z "$src_dev" || -z "$src_ip" || -z "$dst_ip" ]]; then
  echo "Need at least 2 seed endpoints with mgmtIp to continue."
  exit 1
fi

echo "[3/7] Run NQE: assurance enforcement points helper..."
enf_q="$ROOT_DIR/skyforge/policy_reports_assets/checks/assurance-enforcement-points.nqe"
enf_query="$(read_file_json_string "$enf_q")"
enf_body="$(jq -n \
  --argjson query "$enf_query" \
  '{query:$query, parameters:{enforcementDeviceTypes:[], enforcementDeviceNameParts:[], enforcementTagParts:[], includeGroups:true}}')"
enf_out="$(api_post "/api/nqe?networkId=${FWD_NETWORK_ID}&snapshotId=${snapshot_id}" "$enf_body")"
enf_n="$(jq -r '.totalNumItems // (.items|length) // 0' <<<"$enf_out")"
echo "enforcement points=$enf_n"

echo "[4/7] Run NQE: assurance posture summary..."
post_q="$ROOT_DIR/skyforge/policy_reports_assets/checks/assurance-posture-summary.nqe"
post_query="$(read_file_json_string "$post_q")"
post_body="$(jq -n \
  --argjson query "$post_query" \
  '{query:$query, parameters:{sensitivePorts:[22,23,445,3389,1433,1521,3306,5432,6379,9200,27017]}}')"
post_out="$(api_post "/api/nqe?networkId=${FWD_NETWORK_ID}&snapshotId=${snapshot_id}" "$post_body")"
post_n="$(jq -r '.totalNumItems // (.items|length) // 0' <<<"$post_out")"
echo "posture findings rows=$post_n"

echo "[5/7] Run NQE: RFC1918 to internet any-service..."
eg_q="$ROOT_DIR/skyforge/policy_reports_assets/checks/acl-rfc1918-to-internet-any-service.nqe"
eg_query="$(read_file_json_string "$eg_q")"
eg_body="$(jq -n --argjson query "$eg_query" '{query:$query}')"
eg_out="$(api_post "/api/nqe?networkId=${FWD_NETWORK_ID}&snapshotId=${snapshot_id}" "$eg_body")"
eg_n="$(jq -r '.totalNumItems // (.items|length) // 0' <<<"$eg_out")"
echo "egress findings rows=$eg_n"

echo "[6/7] Run NQE: RFC1918 to internet sensitive ports..."
eg2_q="$ROOT_DIR/skyforge/policy_reports_assets/checks/acl-rfc1918-to-internet-sensitive-ports.nqe"
eg2_query="$(read_file_json_string "$eg2_q")"
eg2_body="$(jq -n \
  --argjson query "$eg2_query" \
  '{query:$query, parameters:{sensitivePorts:[22,23,445,3389,1433,1521,3306,5432,6379,9200,27017]}}')"
eg2_out="$(api_post "/api/nqe?networkId=${FWD_NETWORK_ID}&snapshotId=${snapshot_id}" "$eg2_body")"
eg2_n="$(jq -r '.totalNumItems // (.items|length) // 0' <<<"$eg2_out")"
echo "egress sensitive rows=$eg2_n"

echo "[7/7] Run paths-bulk + interface-metrics-history (UTILIZATION)..."
paths_body="$(jq -n --arg srcIp "$src_ip" --arg dstIp "$dst_ip" \
  '{queries:[{srcIp:$srcIp, dstIp:$dstIp}], intent:"PREFER_DELIVERED", maxCandidates:1000, maxResults:1, maxReturnPathResults:0, maxSeconds:30, maxOverallSeconds:60, includeTags:true, includeNetworkFunctions:false}')"
paths_out="$(api_post "/api/networks/${FWD_NETWORK_ID}/paths-bulk?snapshotId=${snapshot_id}" "$paths_body")"
hop_obj="$(jq -c '.[0].info.paths[0].hops[]? | select(((.ingressInterface // "")|tostring|length)>0 or ((.egressInterface // "")|tostring|length)>0) | {deviceName, ingressInterface, egressInterface}' <<<"$paths_out" | head -n 1)"
hop_dev="$(jq -r '.deviceName // empty' <<<"$hop_obj")"
hop_in="$(jq -r '.ingressInterface // empty' <<<"$hop_obj")"
hop_eg="$(jq -r '.egressInterface // empty' <<<"$hop_obj")"
hop_if="$hop_in"
hop_dir="INGRESS"
if [[ -z "$hop_if" ]]; then
  hop_if="$hop_eg"
  hop_dir="EGRESS"
fi
if [[ -z "$hop_dev" || -z "$hop_if" ]]; then
  echo "Could not extract a hop interface (ingress or egress) from paths-bulk output."
  exit 1
fi
echo "sample hop iface: device=$hop_dev iface=$hop_if dir=$hop_dir"

perf_body="$(jq -n --arg dev "$hop_dev" --arg ifn "$hop_if" --arg dir "$hop_dir" \
  '{interfaces:[{deviceName:$dev, interfaceName:$ifn, direction:$dir}]}')"
perf_out="$(api_post "/api/networks/${FWD_NETWORK_ID}/interface-metrics-history?type=UTILIZATION&days=7&maxSamples=200&snapshotId=${snapshot_id}" "$perf_body")"
series_n="$(jq -r '.metrics|length' <<<"$perf_out")"
points_n="$(jq -r '.metrics[0].data|length' <<<"$perf_out" 2>/dev/null || echo 0)"
echo "perf series=$series_n points(first)=$points_n"
if [[ "$series_n" -le 0 || "$points_n" -le 0 ]]; then
  echo "Perf history missing/empty."
  exit 1
fi

echo "PASS"
