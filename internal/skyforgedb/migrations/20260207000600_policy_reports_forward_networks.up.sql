-- Persist Forward networks (by id) for Policy Reports so users can manage multiple networks per owner.

CREATE TABLE IF NOT EXISTS sf_policy_report_forward_networks (
  id uuid PRIMARY KEY,
  owner_id text NOT NULL REFERENCES sf_owner_contexts(id) ON DELETE CASCADE,
  forward_network_id text NOT NULL,
  name text NOT NULL,
  description text,
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (owner_id, forward_network_id)
);

CREATE INDEX IF NOT EXISTS sf_pr_forward_networks_ws_created_idx
  ON sf_policy_report_forward_networks(owner_id, created_at DESC);

