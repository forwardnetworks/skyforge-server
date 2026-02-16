CREATE TABLE IF NOT EXISTS sf_resource_shares (
  id bigserial PRIMARY KEY,
  resource_type text NOT NULL,
  resource_id text NOT NULL,
  owner_username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE ON DELETE CASCADE,
  shared_username text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('viewer', 'editor')),
  created_by text NOT NULL REFERENCES sf_users(username) ON UPDATE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (resource_type, resource_id, shared_username),
  CHECK (owner_username <> shared_username)
);

CREATE INDEX IF NOT EXISTS sf_resource_shares_resource_idx
  ON sf_resource_shares(resource_type, resource_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS sf_resource_shares_shared_user_idx
  ON sf_resource_shares(shared_username, updated_at DESC);
CREATE INDEX IF NOT EXISTS sf_resource_shares_owner_idx
  ON sf_resource_shares(owner_username, updated_at DESC);
