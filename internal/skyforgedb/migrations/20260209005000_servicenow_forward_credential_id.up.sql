ALTER TABLE sf_user_servicenow_configs
  ADD COLUMN IF NOT EXISTS forward_credential_id text NOT NULL DEFAULT '';

