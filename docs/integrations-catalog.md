# Integrations & Providers Catalog (Skyforge)

This is a “current state” index of Skyforge’s integration and provider boundaries, using a clear separation between domain logic and external adapters.

## Integrations (`encore.app/integrations/*`)

These are vendor/protocol adapters (HTTP/SSH/SDK). Domain orchestration should call these, not embed low-level client logic.

- `encore.app/integrations/gitea`
  - Purpose: repo provisioning, blueprint migration, directory listing, file create/update, collaborator management.
  - Used by: `encore.app/skyforge` user scope sync logic.
- `encore.app/integrations/sshutil`
  - Purpose: shared SSH dial + command execution (used by Netlab and other SSH-backed features).
  - Used by: `encore.app/skyforge` Netlab provider.
- `encore.app/integrations/objectstore`
  - Purpose: S3-compatible object store operations using MinIO SDK (currently Terraform-state housekeeping such as prefix deletion).
  - Used by: `encore.app/skyforge` user scope delete/cleanup logic.

Planned candidates (not fully extracted yet):
- `integrations/eve` (EVE-NG API/SSH)
- `integrations/netlab` (Netlab SSH + metadata parsing)
- `integrations/aws` (AWS SSO/OIDC + credentials minting for runs)
- `providers/auth/ldap` (LDAP auth/identity; provider layer, not `integrations/*`)
- `integrations/dns` (only if Skyforge starts programmatically managing lab DNS)

## Providers (Skyforge domain adapters)

Providers are domain-level implementations (e.g., “labs”) that may use one or more integrations.

- Labs providers (current dispatch lives in `encore.app/skyforge`):
  - `eve-ng` (public + authenticated listing)
  - `netlab` (SSH-backed state directory listing)
  - (native task engine; no external runner dependency)

Target end state: `encore.app/providers/labs/*` packages that depend on `encore.app/integrations/*`, with the `skyforge` service orchestrating and exposing API endpoints.

## Notes on Skyforge-specific systems

These fit the same layering model:

- **Netlab**: labs provider implemented over SSH metadata; should move parsing/commands into `integrations/netlab` (provider stays small).
- **EVE-NG**: labs provider implemented over API/SSH; should move API calls into `integrations/eve`.
