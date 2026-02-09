CREATE TABLE IF NOT EXISTS sf_forward_assurance_summaries (
  id bigserial PRIMARY KEY,
  workspace_id text NOT NULL,
  forward_network_id text NOT NULL,
  network_ref text NOT NULL,
  snapshot_id text NOT NULL DEFAULT '',
  generated_at timestamptz NOT NULL DEFAULT now(),
  summary_json jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sf_forward_assurance_summaries_ws_fwd_generated_at
  ON sf_forward_assurance_summaries (workspace_id, forward_network_id, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_sf_forward_assurance_summaries_ws_netref_generated_at
  ON sf_forward_assurance_summaries (workspace_id, network_ref, generated_at DESC);

