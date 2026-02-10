# Forward-Backed Capacity Management Showcase (Skyforge)

This document describes a capacity-management integration that uses:

- Forward as the data source (SNMP/perf endpoints + Paths API)
- NQE for normalized inventory/routing metadata (devices, interfaces, VRFs, BGP, route scale, optional custom command outputs like TCAM)
- Skyforge for capacity rollups, forecasting, deltas, and a lightweight UI

Non-goals:

- Replacing an NPM end-to-end
- Alerting/on-call workflows, ticketing, or event correlation
- Duplicating Forward's path analysis UI/workflows

## Why This Is Compelling Versus Traditional NPMs

What we can do as well as typical “capacity modules”:

- Interface utilization rollups across multiple windows (24h/7d/30d)
- Saturation forecasting (threshold crossing projections)
- Top talkers style "what is hot" views (by max/p95, and grouped summaries)
- Upgrade candidate heuristics (what to upgrade next; includes LAG context)

What we can do better (given Forward + NQE dataset):

- Capacity + intent joins: use Forward Paths (computed topology + policy outcomes) to map candidate flows to the actual interfaces most likely to constrain delivery
- Rich inventory normalization: vendor/model/OS, interface speeds, VRFs, tags/groups/locations, aggregate membership (LAGs)
- “Change awareness” with snapshot deltas: highlight inventory/routing scale changes between snapshots, which is often missing or weak in NPM capacity views

## Current Implementation (What Exists In Skyforge Today)

Server APIs (Encore):

- Forward network capacity rollup summary + refresh queueing
- NQE-backed inventory (devices/interfaces/VRFs/BGP/routes; optional TCAM via custom commands)
- Coverage scoring (how complete is inventory + rollup coverage)
- Growth (delta between latest rollup bucket and prior bucket)
- Upgrade candidates (interfaces + LAGs; direction-aware; speed recommendation)
- Portfolio (workspace-level list of Forward networks with key rollup signals)
- Capacity-only paths: `POST /api/workspaces/:id/forward-networks/:networkRef/capacity/path-bottlenecks`
  - Calls Forward `POST /networks/{networkId}/paths-bulk`
  - Joins hop ingress/egress interfaces to utilization rollups
  - Returns the worst headroom interface per flow (plus outcomes and optional minimal hops)
  - Best-effort LAG attribution: if hop interfaces are LAG members, can match rollups on the aggregate (port-channel) interface
  - Bounded on-demand perf fallback: if rollups are missing for hop interfaces, pulls Forward utilization history (window-bounded) to compute p95/max locally
  - Passes through Forward `queryUrl` per flow, for interactive “open in Forward” follow-up (keeps Skyforge capacity-only)
  - Guardrails: fixed to `maxResults=1`, no tags/network-functions, no return path computation; this is not a Forward paths replacement

Portal UI:

- Capacity dashboard for Forward networks (interfaces/devices/growth/plan/routing/changes/health/raw)
- “Paths” tab: batch paste flows and get bottleneck interface + headroom + outcomes, with click-through to interface trend dialog
  - Optional saved batches stored locally in the browser (workspace+network scoped)
  - Coverage diagnostics + sample unmatched interfaces (helps explain missing stats)
  - Optional payload preview/copy: shows the Forward `/paths-bulk` request shape used (guardrails applied)
  - Per-flow “open in Forward” link via Forward `queryUrl`

## Data Model / Join Strategy

- Paths:
  - Forward computes `PathSearchResponse` containing `paths[].hops[]` with `deviceName`, `ingressInterface`, `egressInterface`
- Capacity rollups:
  - Skyforge stores utilization rollups keyed by `(deviceName, interfaceName, direction)` for window labels (24h/7d/30d)
- Join:
  - For each hop:
    - Map `ingressInterface` -> `INGRESS` utilization
    - Map `egressInterface` -> `EGRESS` utilization
  - Select bottleneck as the interface with the smallest headroom at the rollup threshold (default 0.85 if absent)

## Milestones (From Here)

M0 (done): Capacity-only path bottlenecks

- Batch flow paste (5–50 typical)
- Uses Forward `/paths-bulk`
- Returns bottleneck interface + headroom + forecast (when available)
- Click-through to utilization time-series (Forward perf proxy) for that interface

M1 (done): Better normalization + UX polish

- Input helpers:
  - Parse common “flow” formats more robustly (CSV, `src:port -> dst:port`, proto shorthands)
  - Optional “paste Forward bulk JSON” mode (already supported; improve discoverability)
- Results UX:
  - Add an “Export CSV” button for path bottlenecks
  - Add small inline chips for outcomes (DELIVERED, DENIED, BLACKHOLE, etc)
- Matching improvements:
  - Interface name normalization (e.g., vendor abbreviations) to improve hop->rollup matches when naming differs
  - LAG member -> aggregate matching for hop->rollup joins
  - Bounded Forward perf fallback when rollups are missing

M2: Capacity lens enhancements (still non-NPM)

- “Flow portfolio” (not saved in Forward, saved only in Skyforge if desired):
  - Let users save a named batch and re-run against latest rollups (optional; keep simple)
- “Critical segments”:
  - Aggregate bottleneck counts by `(device, interface, direction)` to show which links constrain the most candidate flows
- Planned work overlay:
  - Combine upgrade-candidate list with path bottlenecks (what upgrades unblock which flows)

M3: Internal product pitch (what to upstream into native product)

- Native “capacity-only path bottleneck” concept:
  - A simplified output of paths focused on utilization headroom, not full workflow
- Unified capacity rollup store keyed by Forward Network ID:
  - Standard windows + thresholds
  - Direction-aware interface rollups
- First-class LAG awareness in capacity:
  - Imbalance detection and member-to-aggregate attribution
- Change deltas:
  - Snapshot deltas for inventory + routing scale as part of capacity context

## Acceptance Criteria

- Server build/tests pass: `encore test ./...`
- Portal type-check passes: `pnpm type-check`
- Paths-bulk integration:
  - For at least one query, returns a bottleneck interface when rollups exist
  - For missing rollups, returns a clear “run Refresh” note without failing the request
