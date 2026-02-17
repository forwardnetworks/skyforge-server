# Owner Schema Cutover Runbook

This release rewrites migration history and removes legacy multi-tenant schema naming.
It is a breaking cutover and requires a fresh database initialization.

## Preconditions

- Maintenance window approved.
- Full backup of the current Skyforge database taken and verified.
- New image tags prepared for server/worker/portal.
- Helm values updated for target image tags.

## Cutover Steps

1. Scale down Skyforge API and workers.
2. Backup current DB and store snapshot metadata.
3. Provision a fresh target DB (empty schema).
4. Deploy updated chart/images.
5. Run migrate job against the fresh DB.
6. Validate app readiness and login flow.
7. Run smoke checks:
   - deployment create/start/delete
   - `/fwd` access
   - collector and policy report CRUD
8. Re-enable normal traffic.

## Validation Commands

- `./scripts/verify-owner-contract.sh`
- `atlas migrate validate --dir file://components/server/internal/skyforgedb/migrations`
- `go test -c ./skyforge`
- `pnpm -s type-check` (portal)
- `helm lint components/charts/skyforge`

## Rollback

1. Scale down new release.
2. Restore previous DB backup.
3. Redeploy previous chart/image set.
4. Run post-restore smoke checks.

## Notes

- In-place upgrade is intentionally unsupported for this cutover.
- Keep this runbook attached to the release artifact for operator review.
