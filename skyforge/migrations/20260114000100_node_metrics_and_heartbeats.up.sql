CREATE TABLE IF NOT EXISTS sf_node_metric_snapshots (
  node TEXT NOT NULL,
  metric_name TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  metric_json JSONB NOT NULL,
  PRIMARY KEY (node, metric_name)
);

CREATE INDEX IF NOT EXISTS idx_sf_node_metric_snapshots_updated_at
  ON sf_node_metric_snapshots (updated_at DESC);

CREATE TABLE IF NOT EXISTS sf_taskworker_heartbeats (
  instance TEXT PRIMARY KEY,
  last_seen TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sf_taskworker_heartbeats_last_seen
  ON sf_taskworker_heartbeats (last_seen DESC);

