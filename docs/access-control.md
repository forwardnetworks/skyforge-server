# Access Control Patterns (Skyforge Server)

This document captures the Skyforge access-control conventions for Skyforge’s Encore services.

## Auth sources

- Browser clients authenticate via cookie sessions (`credentials: include`).
- The portal may send `X-Current-Role` for UI role switching; it must not use Bearer tokens for Skyforge.
- Server code should use `requireAuthUser()` and derive `SessionClaims` from the authenticated user.

## User-scope Endpoints

Skyforge uses a single user scope identity:

1) **Skyforge user scope key** (string): slug/ID used in routes like `/api/users/:id/...`

### A) Skyforge user scope key endpoints (preferred)

If an endpoint is routed by Skyforge user scope key (slug/ID), use:
- `s.userContextForUser(user, workspaceKey)`

This enforces:
- authentication required
- user scope exists
- membership/role access is not `"none"`

## Impersonation

Impersonation affects the authenticated actor identity; handlers must always make authorization decisions using:
- the effective `AuthUser` returned by `requireAuthUser()`
- `SessionClaims` derived from that user

Do not trust portal-provided identity headers for authorization.
