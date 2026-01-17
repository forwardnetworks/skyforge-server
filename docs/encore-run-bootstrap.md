# Local bootstrap: `encore run` (Skyforge server)

Skyforge uses Encore for the backend service, but most infrastructure in this environment lives in k3s (Postgres, Redis, MinIO).

This guide standardizes how to run the Skyforge server locally with Encore while still pointing at your k8s services when desired.

## Prereqs

- Encore CLI available (`encore version` works).
- Docker running (Encore local runtime requires Docker even if you point DB/Redis elsewhere).
- A populated local env file:
  - Copy `skyforge/server/.env.local.example` → `skyforge/server/.env.local`
  - Fill in required values (LDAP/session secret).

## Option A (default): run with Encore local infra

Use this when you don’t care which Postgres/Redis/object storage is backing the dev run.

```bash
cd skyforge/server
set -a
source .env.local
set +a
encore run --watch=false --browser=never --port=4000
```

## Option B: use k8s Postgres/Redis while running via `encore run`

Port-forward the services and point Skyforge env vars at localhost.

### Postgres

```bash
kubectl -n skyforge port-forward svc/postgres 5432:5432
```

```bash
export SKYFORGE_DB_HOST=127.0.0.1
export SKYFORGE_DB_PORT=5432
export SKYFORGE_DB_SSLMODE=disable
```

### Redis (optional)

```bash
kubectl -n skyforge port-forward svc/redis 6379:6379
```

```bash
## Cache (Redis)
Encore cache keyspaces use the `redis.default` cluster in `infra.config.json`.
```

Then start Encore:

```bash
cd skyforge/server
set -a
source .env.local
set +a
encore run --watch=false --browser=never --port=4000
```

## Notes

- Skyforge uses an Encore `sqldb` database resource; the `SKYFORGE_DB_*` env vars are consumed by the Encore infra config (`infra.config.json`) to configure the database connection.
- The Encore storage API used for artifacts is configured via `infra.config.json` for production builds (k8s/MinIO). In `encore run`, Encore may use its local storage backend instead.
- This repo runs `server/encore.app` in “unlinked” mode to avoid requiring Encore Cloud auth during development.
