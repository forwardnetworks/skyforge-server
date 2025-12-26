# Integrations Architecture (Skyforge domain)

This is a target architecture for Skyforge’s external integrations (Semaphore, Gitea, EVE-NG, Netlab) using Encore-native patterns while keeping Skyforge’s domain focused on labs and automation.

Goal: make integrations **easy to swap**, **easy to test**, and **hard to leak** into UI/domain code.

## Principles

- **Integrations are adapters**: hide vendor APIs behind typed interfaces and small clients.
- **Encore endpoints are the public contract**: integration details stay internal.
- **Async by default for long-running operations**: background jobs/cron/pubsub for sync/provision/run orchestration.
- **One authorization path**: authorize at the domain boundary, not inside adapters.

## Target package layout (incremental refactor-friendly)

Keep Encore services small and domain-oriented, and move vendor glue into non-service packages.

### Services (Encore)

Recommended future split (can be gradual; no need to do all at once):

- `encore.app/skyforge` (core domain orchestration; auth/session, project membership)
- `encore.app/runs` (Semaphore-backed runs orchestration: list/start/output)
- `encore.app/labs` (provider-backed labs queries/actions: EVE/Netlab)
- `encore.app/artifacts` (artifact upload/download/transfer, backed by `storage`)
- `encore.app/storage` (object storage primitive, already present)

You can keep the current single `skyforge` service short-term, but the code should be organized *as if* it were split.

### Integration clients (non-service packages)

Create a stable “adapter layer” under `encore.app/integrations/*`:

- `encore.app/integrations/semaphore`
  - Typed client for Semaphore HTTP API (list tasks, create task, templates, repos, keys, envs).
  - No auth decisions; takes already-authorized identifiers (Semaphore project id, template id, etc).
- `encore.app/integrations/gitea`
  - Typed client for Gitea (ensure repo/file, list directory, collaborators, etc).
- `encore.app/integrations/eve`
  - Typed client for EVE-NG API (labs list/health/launch URLs, etc).
- `encore.app/integrations/netlab`
  - Typed client for Netlab runner access (SSH commands, metadata read).

### Provider abstraction (domain-facing)

Expose a small provider interface used by the `labs` service (or the `skyforge` service initially):

- `encore.app/providers/labs`
  - `Provider` interface:
    - `ListRunning(ctx, query) ([]LabSummary, []LabSource, error)`
    - `ListForUser(ctx, query) ([]LabSummary, []LabSource, error)`
    - `ListMetadata(ctx, query) ([]JSONMap, error)` (Netlab)
    - `GetMetadata(ctx, id, query) (JSONMap, error)` (Netlab)
  - Implementations:
    - `providers/labs/eve` uses `integrations/eve`
    - `providers/labs/netlab` uses `integrations/netlab`

This keeps `labs_api.go` thin and makes adding a new provider (or swapping Netlab→something else) straightforward.

### Jobs/workflows (async orchestration)

Move “do a bunch of integration calls and update state” work behind a job boundary:

- `encore.app/jobs/projectsync`
  - `RunOnce(ctx)` and `RunForProject(ctx, projectKey)` style entrypoints.
  - Called by:
    - admin/manual endpoints
    - an Encore cron job (preferred over ad-hoc goroutines) once schedule policy is stable

For now you can keep the existing goroutine-based sync, but new workflows should prefer Encore-native scheduling.

## Mapping from current Skyforge code

These are the main clusters that should move into adapters/providers over time:

- Semaphore:
  - `semaphoreDo`, `fetchSemaphoreTasks`, `cachedSemaphoreTaskOutput`, `ensureSemaphore*`, `startSemaphoreRun`
  - Currently spread across `skyforge/service.go`, `skyforge/runs_helpers.go`, `skyforge/projects_api.go`
- Netlab SSH helpers:
  - `dialSSH`, `runSSHCommand` (currently in `skyforge/service.go`)
- Labs provider selection:
  - `listLabProviders` (currently in `skyforge/service.go`)

## Recommended next refactor steps (low risk)

1) **Create adapter packages and move pure clients first** (no endpoint changes).
2) Update endpoints to call adapters (thin handlers).
3) Introduce provider interfaces for labs and runs orchestration.
4) Move background sync from goroutine → Encore cron (once scheduling policy is decided).
5) Optionally split the Encore service(s) once internal boundaries are clean.

## What this buys you (direction)

- Semaphore/EVE/Netlab become “plug-ins” behind stable interfaces.
- You can swap implementations (or add new providers) without touching UI-facing endpoints.
- You can test orchestration logic with fake adapters.
- You reduce the “giant service.go integration blob” risk as Skyforge grows.
