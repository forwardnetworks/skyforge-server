# Assurance Studio: Demo Parity and Ownership Map

This document is the source of truth for what Assurance Studio should (and should not) implement.

Goal: for demos, show that Forward Networks (NQE + SNMP + paths analysis) can replace key workflows from:
- Routing assurance: BluePlanet ROA-like
- Capacity management: SolarWinds-like
- Security policy assurance: Tufin/RedSeal-like

Non-goal: alerting / continuous monitoring / ticket automation (demo can be manual runs + exports).

## Ownership Rules

- If a workflow already exists as a canonical view in Forward or Skyforge (Policy Reports / Capacity), Assurance Studio should:
  - Show a thin summary (1 screen) and
  - Deep-link to the canonical view for details.
- Studio-owned code should focus on:
  - Scenario orchestration (demands + knobs)
  - Shared backend evaluation (one `paths-bulk` call per run; baseline compare can be a second call)
  - Concise, demo-friendly summaries and exports

## Shared Backend Contract

Canonical endpoint for Studio runs:
- `POST /api/fwd/:networkRef/assurance/studio/evaluate`

Behavior:
- Always uses a single Forward `paths-bulk` run per evaluation request.
- Optional routing baseline compare:
  - If `baselineSnapshotId` is set (and routing enabled), Studio performs a second `paths-bulk` call to compute regression diffs.

## Routing (BluePlanet ROA-like)

Studio-owned:
- Candidate ranking + recommendation per demand (Forward `paths-bulk` projected into a table)
- Evidence links: per-demand “open in Forward”
- Regression vs baseline snapshot (compare two snapshots and summarize changed flows)

Deep-link only:
- Any Forward-native “blast radius / impact analysis” views (Studio should link, not rebuild)

Acceptance for demo:
- Show: delivered/not delivered counts, missing enforcement count, bottleneck overlay, and a “Regression vs baseline” table.
- Every changed flow has an “open in Forward” evidence link for baseline + compare.

## Capacity (SolarWinds-like)

Studio-owned (thin summary):
- Scenario lens: bottleneck per flow, headroom, forecast crossing timestamp, rollup coverage

Deep-link only:
- Full Capacity UI (inventory, trends, upgrade candidates, etc.)

Acceptance for demo:
- Show “Top bottleneck interfaces for this scenario” plus coverage and headroom.
- Provide “Open full Capacity” CTA.

## Security (Tufin/RedSeal-like)

Studio-owned (thin summary):
- “Paths Assurance” for the scenario demand set:
  - enforcement traversal required/optional
  - return path + symmetry (optional)
  - ACL/NF evidence (optional)

Deep-link only:
- Policy Reports packs/views that resemble posture matrices / segmentation matrices.

Acceptance for demo:
- Show violations list with a short reason.
- Provide “Open full Policy Reports” CTA for deeper posture/segmentation review.
