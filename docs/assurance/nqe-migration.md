# Assurance: NQE-First Migration Notes

## Goal

Keep assurance analytics as close to Forward NQE as possible to showcase the model-driven query engine, with Go acting primarily as:

- request orchestration
- joining Forward REST outputs (notably `paths-bulk`)
- shaping responses for the portal
- limited aggregation / sorting

## What Can Move Into NQE

Snapshot-model-only analysis can be implemented in NQE and executed via Forward `/api/nqe`, for example:

- device/interface discovery and filtering (traffic seed endpoints)
- enforcement-point classification helpers
- modeled ACL/NAT posture checks
- light config heuristics (e.g., OSPF/uRPF patterns)

## What Stays REST/Go (for now)

Some computations require outputs that Forward currently provides via REST endpoints rather than NQE:

- path computation and candidate enumeration: `POST /api/networks/:id/paths-bulk`
- perf time-series: `POST /api/networks/:id/interface-metrics-history`

Skyforge also has local signals/storage that remain Go/DB-scoped:

- capacity rollups and joins (Skyforge tables)
- SNMP trap ingestion/counting (Skyforge live signals)

## Current Implemented Pattern

- NQE is used for discovery and “policy posture” style findings.
- Go calls `paths-bulk` for routing/candidate analysis, then optionally joins:
  - cached utilization rollups (Skyforge)
  - perf fallback (Forward `interface-metrics-history`)

For an end-to-end validation of the NQE + REST flows, see:

- `scripts/fwd_assurance_smoketest.sh`

