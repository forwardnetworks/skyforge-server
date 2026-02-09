-- Assurance Studio: server-side saved scenarios per workspace + Forward network.
-- Keep this additive (do not edit earlier migrations).

CREATE TABLE IF NOT EXISTS sf_assurance_studio_scenarios (
  id uuid PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES sf_workspaces(id) ON DELETE CASCADE,
  network_ref uuid NOT NULL REFERENCES sf_policy_report_forward_networks(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  name text NOT NULL,
  description text,
  spec jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Postgres requires a unique index for expression-based uniqueness.
CREATE UNIQUE INDEX IF NOT EXISTS sf_assurance_scenarios_ws_net_name_uq
  ON sf_assurance_studio_scenarios (workspace_id, network_ref, lower(name));

CREATE INDEX IF NOT EXISTS sf_assurance_scenarios_ws_net_updated_idx
  ON sf_assurance_studio_scenarios(workspace_id, network_ref, updated_at DESC);

CREATE INDEX IF NOT EXISTS sf_assurance_scenarios_ws_fwd_updated_idx
  ON sf_assurance_studio_scenarios(workspace_id, forward_network_id, updated_at DESC);
