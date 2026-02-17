-- Keep this additive (do not edit earlier migrations).

-- Capacity rollups store computed time-window summaries derived from Forward perf history.
-- period_end is the "as-of" timestamp for a rollup run (bucketed to the hour).
CREATE TABLE IF NOT EXISTS sf_capacity_rollups (
  id bigserial PRIMARY KEY,
  owner_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  deployment_id uuid NOT NULL REFERENCES sf_deployments(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  object_type text NOT NULL,
  object_id text NOT NULL,
  metric text NOT NULL,
  window_label text NOT NULL,
  period_end timestamptz NOT NULL,
  samples integer NOT NULL DEFAULT 0,
  avg double precision,
  p95 double precision,
  p99 double precision,
  max double precision,
  slope_per_day double precision,
  forecast_crossing_ts timestamptz,
  threshold double precision,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- One row per (object, metric, window) per rollup run.
CREATE UNIQUE INDEX IF NOT EXISTS sf_capacity_rollups_uq
  ON sf_capacity_rollups(owner_id, deployment_id, object_type, object_id, metric, window_label, period_end);

CREATE INDEX IF NOT EXISTS sf_capacity_rollups_lookup_idx
  ON sf_capacity_rollups(owner_id, deployment_id, metric, window_label, period_end DESC);

CREATE INDEX IF NOT EXISTS sf_capacity_rollups_object_idx
  ON sf_capacity_rollups(owner_id, deployment_id, object_type, object_id);

-- Cache for capacity-related NQE query outputs (inventory, route scale, BGP scale).
-- snapshot_id is intentionally defaulted to '' to allow a stable "latest" cache entry.
CREATE TABLE IF NOT EXISTS sf_capacity_nqe_cache (
  id bigserial PRIMARY KEY,
  owner_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  deployment_id uuid NOT NULL REFERENCES sf_deployments(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  query_id text NOT NULL,
  snapshot_id text NOT NULL DEFAULT '',
  payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS sf_capacity_nqe_cache_uq
  ON sf_capacity_nqe_cache(owner_id, deployment_id, query_id, snapshot_id);

CREATE INDEX IF NOT EXISTS sf_capacity_nqe_cache_lookup_idx
  ON sf_capacity_nqe_cache(owner_id, deployment_id, query_id, created_at DESC);
