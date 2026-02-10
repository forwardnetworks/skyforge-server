# Forward Smoketests (Assurance + NQE + Perf)

This folder contains a small, repeatable harness for validating:

- Forward snapshot access (`latestProcessed`)
- Forward NQE execution (Skyforge embedded queries)
- Forward path computation (`paths-bulk`)
- Forward perf history availability (`interface-metrics-history`, UTILIZATION)

## Prereqs

- `curl`, `jq`
- Network access to your Forward instance

## Credentials

The script reads credentials from env, or by default from:

- `../fwdcreds.env` (relative to `skyforge-server/`)

Expected variables:

- `FWD_HOST` (host or full base URL)
- `FWD_USER`
- `FWD_PASS`
- `FWD_NETWORK_ID`

Optional:

- `FWD_INSECURE=1` to pass `-k` to curl (skip TLS verification)
- `FWD_CREDS_FILE=/path/to/fwdcreds.env` to override env file path

## Run

From `skyforge-server/`:

```bash
./scripts/fwd_assurance_smoketest.sh
```

On success it prints `PASS` and a few counts (seed endpoints, enforcement points, posture rows, perf series/points).

