-- Forward metrics snapshots (polled from Forward on-prem/cloud APIs).
-- This gives Skyforge a durable time series for Forward health/performance without
-- requiring direct Prometheus scraping from Forward pods.

CREATE TABLE IF NOT EXISTS sf_forward_metrics_snapshots (
  id bigserial PRIMARY KEY,
  workspace_id text REFERENCES sf_workspaces(id) ON DELETE CASCADE,
  owner_username text REFERENCES sf_users(username) ON UPDATE CASCADE,
  network_ref uuid REFERENCES sf_policy_report_forward_networks(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  snapshot_id text,
  collected_at timestamptz NOT NULL DEFAULT now(),

  num_successful_devices int,
  num_collection_failure_devices int,
  num_processing_failure_devices int,
  num_successful_endpoints int,
  num_collection_failure_endpoints int,
  num_processing_failure_endpoints int,
  collection_duration_ms bigint,
  processing_duration_ms bigint,

  source text NOT NULL DEFAULT 'forward',
  raw_metrics jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS sf_forward_metrics_snapshots_ws_network_collected_idx
  ON sf_forward_metrics_snapshots(workspace_id, forward_network_id, collected_at DESC);

CREATE INDEX IF NOT EXISTS sf_forward_metrics_snapshots_owner_network_collected_idx
  ON sf_forward_metrics_snapshots(owner_username, forward_network_id, collected_at DESC)
  WHERE owner_username IS NOT NULL;

CREATE INDEX IF NOT EXISTS sf_forward_metrics_snapshots_network_ref_collected_idx
  ON sf_forward_metrics_snapshots(network_ref, collected_at DESC)
  WHERE network_ref IS NOT NULL;

-- Single on-prem S3 backup settings profile managed by Skyforge admins.
-- Secrets are encrypted with the Skyforge session secret via secretbox.
CREATE TABLE IF NOT EXISTS sf_forward_onprem_backup_s3_settings (
  id text PRIMARY KEY DEFAULT 'default',
  enabled boolean NOT NULL DEFAULT false,

  bucket text NOT NULL DEFAULT '',
  bucket_prefix text NOT NULL DEFAULT 'forward/backups',
  region text NOT NULL DEFAULT '',
  endpoint text NOT NULL DEFAULT '',

  access_key_enc text NOT NULL DEFAULT '',
  secret_key_enc text NOT NULL DEFAULT '',

  retention_days int NOT NULL DEFAULT 30,

  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text REFERENCES sf_users(username) ON UPDATE CASCADE
);

-- Apply/reconcile run history for auditability and troubleshooting.
CREATE TABLE IF NOT EXISTS sf_forward_onprem_backup_runs (
  id bigserial PRIMARY KEY,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  status text NOT NULL,
  actor text,
  details jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS sf_forward_onprem_backup_runs_started_idx
  ON sf_forward_onprem_backup_runs(started_at DESC);
