# Access Control Patterns (Skyforge Server)

This document captures Skyforge access-control conventions for Encore services.

## Auth sources

- Browser clients authenticate via cookie sessions (`credentials: include`).
- The portal may send `X-Current-Role` for UI role switching; it must not use Bearer tokens for Skyforge.
- Server code should use `requireAuthUser()` and derive `SessionClaims` from the authenticated user.

## User-context endpoints

Skyforge uses a per-user owner context identity:

1) **Owner key** (string): user slug/ID used in routes.

### Owner key endpoints (preferred)

If an endpoint is routed by owner key (slug/ID), use:

- `s.ownerContextForUser(user, ownerKey)`

This enforces:

- authentication required
- owner context exists
- effective role access is not `"none"`

## Impersonation

Impersonation affects the authenticated actor identity; handlers must always make authorization decisions using:

- the effective `AuthUser` returned by `requireAuthUser()`
- `SessionClaims` derived from that user

Do not trust portal-provided identity headers for authorization.
