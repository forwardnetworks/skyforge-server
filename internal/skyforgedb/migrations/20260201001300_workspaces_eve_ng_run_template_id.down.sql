-- NOTE: This is a best-effort rollback and may drop data if the column is in use.
ALTER TABLE IF EXISTS sf_workspaces
  DROP COLUMN IF EXISTS eve_ng_run_template_id;

