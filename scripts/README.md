# Scripts

Operational helpers for Skyforge server development and release.

## validate-policy-reports.sh

Validates Policy Reports embedded checks:
- each `*.nqe` contains an `@query`
- `catalog.yaml` parameter names match the `@query` signature (best-effort, YAML-light)
- optionally runs `nqe-lsp-validate` if available

Optional environment variables (for semantic validation):
- `NQE_LSP_SCHEMA_PATH`: path to generated `nqe-schema.json`
- `NQE_LSP_EXPORT_ZIP`: path to exported `queries.zip`
