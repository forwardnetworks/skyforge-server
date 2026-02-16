# Assurance Studio: Shared Backend Contract

Assurance Studio contains multiple integrations (Routing, Capacity Management, Security) that are all backed by the same Forward Networks primitives:

- One Forward `paths-bulk` run per evaluation.
- Shared use of SNMP-derived capacity rollups + interface inventory (to compute utilization/bottlenecks overlays).
- Shared projection of the same Forward output into the three views (to avoid duplicate queries and drift).

## Backend Endpoint

Assurance Studio uses:

- `POST /api/fwd/:networkRef/assurance/studio/evaluate`

Implementation: `skyforge/assurance_studio_evaluate_api.go`.

This endpoint performs exactly one Forward `paths-bulk` request and then computes:

- Routing: `assuranceTrafficEvaluateFromFwdOut(...)`
- Capacity: `capacityPathBottlenecksFromFwdOut(...)`
- Security: `policyReportsPathsEnforcementBypassEvalFromFwdOut(...)`

Legacy, standalone endpoints still exist for other pages; the Assurance Studio UI should prefer the shared endpoint.

## Verification Before Feature Work

Run the verification script:

```bash
skyforge-server/scripts/verify-assurance-studio-backend.sh
```

It checks:

- Backend compiles and the unit test asserts a single Forward `paths-bulk` call when all phases are enabled.
- The Assurance Studio route does not call the legacy per-integration endpoints.
- Portal TypeScript type-check passes.
