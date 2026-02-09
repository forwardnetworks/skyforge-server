ALTER TABLE sf_workspace_forward_credentials
  DROP COLUMN IF EXISTS credential_id;

ALTER TABLE sf_policy_report_forward_network_credentials
  DROP COLUMN IF EXISTS credential_id;

ALTER TABLE sf_user_forward_collectors
  DROP COLUMN IF EXISTS credential_id;

DROP TABLE IF EXISTS sf_credentials;
