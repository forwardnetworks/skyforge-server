# Using k8s Postgres with `encore run`

Encore's local runtime (`encore run`) provisions infrastructure for certain primitives using Docker.
For SQL databases, Encore currently requires Docker available locally.

If you still want to develop with `encore run` while using the Postgres instance running in your k8s cluster, the typical workflow is:

1) Port-forward the Postgres service to localhost.
2) Point Skyforge's DB config env vars at the forwarded port.
3) Run `encore run` (Docker must be installed even if you're not using the local DB).

## Example (port-forward)

Adjust namespace/service name as needed:

```bash
kubectl -n skyforge port-forward svc/postgres 5432:5432
```

## Example (env vars)

In a separate shell:

```bash
export SKYFORGE_DB_HOST=127.0.0.1
export SKYFORGE_DB_PORT=5432
export SKYFORGE_DB_NAME=skyforge_server
export SKYFORGE_DB_USER=skyforge_server
export SKYFORGE_DB_PASSWORD='...'
export SKYFORGE_DB_SSLMODE=disable
```

Then run:

```bash
cd skyforge/server
encore run --watch=false --browser=never --port=4000
```

## Notes

- The Skyforge server code uses an explicit Postgres connection (`SKYFORGE_DB_*`), so it will use the forwarded connection if those env vars are set.
- If Docker is not installed locally, `encore run` will fail before the app starts (even if Postgres is reachable over the network).
- For local `encore run`, you also need the required secrets present (see `skyforge/server/.env.local.example`).
