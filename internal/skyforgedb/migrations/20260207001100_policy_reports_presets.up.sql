-- Policy Reports: scheduled presets (saved recurring runs) per Forward network ID and owner user.

CREATE TABLE IF NOT EXISTS sf_policy_report_presets (
  id uuid PRIMARY KEY,
  owner_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  name text NOT NULL,
  description text,
  kind text NOT NULL DEFAULT 'PACK' CHECK (kind IN ('PACK','CUSTOM')),
  pack_id text NOT NULL DEFAULT '',
  title_template text NOT NULL DEFAULT '',
  snapshot_id text NOT NULL DEFAULT '',
  checks jsonb NOT NULL DEFAULT '[]'::jsonb,
  query_options jsonb NOT NULL DEFAULT '{}'::jsonb,
  max_per_check integer NOT NULL DEFAULT 0,
  max_total integer NOT NULL DEFAULT 0,
  enabled boolean NOT NULL DEFAULT true,
  interval_minutes integer NOT NULL DEFAULT 1440, -- daily
  next_run_at timestamptz,
  last_run_id uuid,
  last_run_at timestamptz,
  last_error text,
  owner_username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_pr_presets_ws_idx
  ON sf_policy_report_presets(owner_id, created_at DESC);

CREATE INDEX IF NOT EXISTS sf_pr_presets_ws_net_idx
  ON sf_policy_report_presets(owner_id, forward_network_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS sf_pr_presets_due_idx
  ON sf_policy_report_presets(enabled, next_run_at);

CREATE UNIQUE INDEX IF NOT EXISTS sf_pr_presets_ws_net_name_uq
  ON sf_policy_report_presets(owner_id, forward_network_id, lower(name));

