# Skyforge Receiver (syslog)

This folder contains a small standalone Go binary used for UDP listeners that
don’t fit the Encore HTTP model (e.g., syslog).

- Listens on UDP/514 (configurable via `SKYFORGE_SYSLOG_LISTEN`)
- Stores events in Postgres (`sf_syslog_events`)

The receiver is deployed as a `DaemonSet` in k3s so every node can accept
native syslog without going through Traefik.
