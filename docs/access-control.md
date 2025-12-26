# Access Control Patterns (Skyforge Server)

This document captures the Skyforge access-control conventions for Skyforge’s Encore services.

## Auth sources

- Browser clients authenticate via cookie sessions (`credentials: include`).
- The portal may send `X-Current-Role` for UI role switching; it must not use Bearer tokens for Skyforge.
- Server code should use `requireAuthUser()` and derive `SessionClaims` from the authenticated user.

## Project-scoped endpoints

Skyforge has two “project identity” shapes:

1) **Skyforge project key** (string): slug/ID used in routes like `/api/projects/:id/...`  
2) **Semaphore project id** (int): `project_id` used in query params for Semaphore-backed endpoints like `/api/runs?project_id=...`

Use the correct guard for each.

### A) Skyforge project key endpoints (preferred)

If an endpoint is routed by Skyforge project key (slug/ID), use:
- `s.projectContextForUser(user, projectKey)`

This enforces:
- authentication required
- project exists
- membership/role access is not `"none"`

### B) Semaphore project id endpoints

If an endpoint is scoped by `project_id` (Semaphore project id), call:
- `s.authorizeSemaphoreProjectID(claims, projectID)`

This enforces:
- authentication required
- the project exists in Skyforge project state and the user has access, or the user is admin/default-project access applies

## Impersonation

Impersonation affects the authenticated actor identity; handlers must always make authorization decisions using:
- the effective `AuthUser` returned by `requireAuthUser()`
- `SessionClaims` derived from that user

Do not trust portal-provided identity headers for authorization.
