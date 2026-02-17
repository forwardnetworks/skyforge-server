DROP INDEX IF EXISTS sf_tasks_owner_idx;
DROP INDEX IF EXISTS sf_deployments_owner_idx;

ALTER TABLE IF EXISTS sf_tasks
  DROP COLUMN IF EXISTS owner_username;

ALTER TABLE IF EXISTS sf_deployments
  DROP COLUMN IF EXISTS owner_username;

DROP TABLE IF EXISTS sf_resource_shares;
