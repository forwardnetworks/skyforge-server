-- Persist Forward networks (by id) for Policy Reports so users can manage multiple networks per workspace.

CREATE TABLE IF NOT EXISTS sf_policy_report_forward_networks (
  id uuid PRIMARY KEY,
  workspace_id text NOT NULL REFERENCES sf_workspaces(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  name text NOT NULL,
  description text,
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, forward_network_id)
);

CREATE INDEX IF NOT EXISTS sf_pr_forward_networks_ws_created_idx
  ON sf_policy_report_forward_networks(workspace_id, created_at DESC);

