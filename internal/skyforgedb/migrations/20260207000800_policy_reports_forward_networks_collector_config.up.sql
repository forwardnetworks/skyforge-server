ALTER TABLE sf_policy_report_forward_networks
  ADD COLUMN IF NOT EXISTS collector_config_id text;

