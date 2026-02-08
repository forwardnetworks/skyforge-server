-- Scope Policy Reports exceptions to a Forward network id.

ALTER TABLE sf_policy_report_exceptions
  ADD COLUMN IF NOT EXISTS forward_network_id text NOT NULL DEFAULT '';

-- Allow identical findingId/checkId exceptions across different Forward networks.
DROP INDEX IF EXISTS sf_pr_exceptions_ws_finding_check_uniq;

CREATE UNIQUE INDEX IF NOT EXISTS sf_pr_exceptions_ws_network_finding_check_uniq
  ON sf_policy_report_exceptions(workspace_id, forward_network_id, finding_id, check_id);

CREATE INDEX IF NOT EXISTS sf_pr_exceptions_ws_network_status_updated_idx
  ON sf_policy_report_exceptions(workspace_id, forward_network_id, status, updated_at DESC);

