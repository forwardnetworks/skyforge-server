-- Assurance Studio: saved run artifacts for scenarios (routing/capacity/security outputs).
-- Keep this additive (do not edit earlier migrations).

CREATE TABLE IF NOT EXISTS sf_assurance_studio_runs (
  id uuid PRIMARY KEY,
  owner_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  network_ref uuid NOT NULL REFERENCES sf_policy_report_forward_networks(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  scenario_id uuid REFERENCES sf_assurance_studio_scenarios(id) ON DELETE SET NULL,
  title text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'SUCCEEDED' CHECK (status IN ('SUCCEEDED','PARTIAL','FAILED')),
  error text,
  request jsonb NOT NULL DEFAULT '{}'::jsonb,
  results jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_assurance_runs_ws_net_started_idx
  ON sf_assurance_studio_runs(owner_id, network_ref, started_at DESC);

CREATE INDEX IF NOT EXISTS sf_assurance_runs_ws_fwd_started_idx
  ON sf_assurance_studio_runs(owner_id, forward_network_id, started_at DESC);

