-- User-scoped ownership and resource sharing primitives.
--
-- This migration is additive:
-- - Introduces generic share records so collaboration is possible without relying
--   on workspace membership as the primary boundary.
-- - Adds owner_username columns to core runtime tables used by task/deployment APIs.

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

ALTER TABLE sf_deployments
  ADD COLUMN IF NOT EXISTS owner_username text REFERENCES sf_users(username) ON UPDATE CASCADE ON DELETE SET NULL;

ALTER TABLE sf_tasks
  ADD COLUMN IF NOT EXISTS owner_username text REFERENCES sf_users(username) ON UPDATE CASCADE ON DELETE SET NULL;

-- Backfill deployment owners from created_by first, then workspace created_by fallback.
UPDATE sf_deployments
   SET owner_username = lower(nullif(created_by, ''))
 WHERE owner_username IS NULL
   AND nullif(created_by, '') IS NOT NULL;

UPDATE sf_deployments d
   SET owner_username = lower(w.created_by)
  FROM sf_workspaces w
 WHERE d.owner_username IS NULL
   AND d.workspace_id = w.id
   AND nullif(w.created_by, '') IS NOT NULL;

-- Backfill task owners from deployment owner, then created_by fallback.
UPDATE sf_tasks t
   SET owner_username = d.owner_username
  FROM sf_deployments d
 WHERE t.owner_username IS NULL
   AND t.deployment_id = d.id
   AND d.owner_username IS NOT NULL;

UPDATE sf_tasks
   SET owner_username = lower(nullif(created_by, ''))
 WHERE owner_username IS NULL
   AND nullif(created_by, '') IS NOT NULL;

CREATE INDEX IF NOT EXISTS sf_deployments_owner_idx
  ON sf_deployments(owner_username, updated_at DESC);
CREATE INDEX IF NOT EXISTS sf_tasks_owner_idx
  ON sf_tasks(owner_username, created_at DESC);
