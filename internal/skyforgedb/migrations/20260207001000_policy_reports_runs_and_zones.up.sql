-- Policy Reports: stored runs + normalized findings + simple "zones" (CIDR sets).
-- These tables remain read-only with respect to device config; they only store
-- execution outputs and governance metadata.

CREATE TABLE IF NOT EXISTS sf_policy_report_runs (
  id uuid PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES sf_workspaces(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  snapshot_id text NOT NULL DEFAULT '',
  pack_id text NOT NULL,
  title text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING','SUCCEEDED','FAILED')),
  error text,
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  request jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_pr_runs_ws_started_idx
  ON sf_policy_report_runs(workspace_id, started_at DESC);

CREATE INDEX IF NOT EXISTS sf_pr_runs_ws_net_started_idx
  ON sf_policy_report_runs(workspace_id, forward_network_id, started_at DESC);

CREATE INDEX IF NOT EXISTS sf_pr_runs_ws_pack_started_idx
  ON sf_policy_report_runs(workspace_id, pack_id, started_at DESC);

CREATE INDEX IF NOT EXISTS sf_pr_runs_ws_status_started_idx
  ON sf_policy_report_runs(workspace_id, status, started_at DESC);

CREATE TABLE IF NOT EXISTS sf_policy_report_run_checks (
  run_id uuid NOT NULL REFERENCES sf_policy_report_runs(id) ON DELETE CASCADE,
  check_id text NOT NULL,
  total integer NOT NULL DEFAULT 0,
  PRIMARY KEY (run_id, check_id)
);

CREATE INDEX IF NOT EXISTS sf_pr_run_checks_run_idx
  ON sf_policy_report_run_checks(run_id);

CREATE TABLE IF NOT EXISTS sf_policy_report_run_findings (
  run_id uuid NOT NULL REFERENCES sf_policy_report_runs(id) ON DELETE CASCADE,
  check_id text NOT NULL,
  finding_id text NOT NULL,
  risk_score integer NOT NULL DEFAULT 0,
  asset_key text,
  finding jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (run_id, check_id, finding_id)
);

CREATE INDEX IF NOT EXISTS sf_pr_run_findings_run_check_idx
  ON sf_policy_report_run_findings(run_id, check_id);

CREATE INDEX IF NOT EXISTS sf_pr_run_findings_run_risk_idx
  ON sf_policy_report_run_findings(run_id, risk_score DESC);

-- Aggregate / current posture view for findings (per Forward network).
CREATE TABLE IF NOT EXISTS sf_policy_report_findings_agg (
  workspace_id text NOT NULL REFERENCES sf_workspaces(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  check_id text NOT NULL,
  finding_id text NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','RESOLVED')),
  risk_score integer NOT NULL DEFAULT 0,
  asset_key text,
  finding jsonb NOT NULL DEFAULT '{}'::jsonb,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz,
  last_run_id uuid,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, forward_network_id, check_id, finding_id)
);

CREATE INDEX IF NOT EXISTS sf_pr_findings_agg_ws_net_status_idx
  ON sf_policy_report_findings_agg(workspace_id, forward_network_id, status, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS sf_pr_findings_agg_ws_status_risk_idx
  ON sf_policy_report_findings_agg(workspace_id, status, risk_score DESC);

-- "Zones" are user-defined CIDR sets used as inputs to segmentation checks.
CREATE TABLE IF NOT EXISTS sf_policy_report_zones (
  id uuid PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES sf_workspaces(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  name text NOT NULL,
  description text,
  subnets jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_pr_zones_ws_net_idx
  ON sf_policy_report_zones(workspace_id, forward_network_id, created_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS sf_pr_zones_ws_net_name_uq
  ON sf_policy_report_zones(workspace_id, forward_network_id, lower(name));

