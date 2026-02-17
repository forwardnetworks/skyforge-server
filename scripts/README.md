# Scripts

Operational helpers for Skyforge server development and release.

## ownership-cleanup-status.sh

Reports active legacy ownership-model references in runtime source trees:
- server: `skyforge/`, `internal/` (excludes generated/docs/migrations/dist)
- portal: `../skyforge-portal/src` (excludes generated route/openapi files)

Filtering behavior:
- ignores legacy DB schema identifiers like `sf_workspace*` and `workspace_*` to focus on operational references
- accepts an optional iteration marker as arg 1 or `OWNERSHIP_CLEANUP_ITERATION`

Outputs:
- per-surface counts
- total count
- top files by match volume
- iteration line in status output

## ownership-cleanup-iteration.sh

Iteration gate for ownership-model removal:
- runs `ownership-cleanup-status.sh`
- exits non-zero while active references remain
- exits zero only when active reference count reaches zero
- accepts optional iteration argument (`ownership-cleanup-iteration.sh 7`) that is passed into status output

## validate-policy-reports.sh

Validates Policy Reports embedded checks:
- each `*.nqe` contains an `@query`
- `catalog.yaml` parameter names match the `@query` signature (best-effort, YAML-light)
- optionally runs `nqe-lsp-validate` if available

Optional environment variables (for semantic validation):
- `NQE_LSP_SCHEMA_PATH`: path to generated `nqe-schema.json`
- `NQE_LSP_EXPORT_ZIP`: path to exported `queries.zip`
