-- Undo Forward network scoping for Policy Reports exceptions.

DROP INDEX IF EXISTS sf_pr_exceptions_ws_network_status_updated_idx;
DROP INDEX IF EXISTS sf_pr_exceptions_ws_network_finding_check_uniq;

ALTER TABLE sf_policy_report_exceptions
  DROP COLUMN IF EXISTS forward_network_id;

-- Restore pre-existing uniqueness constraint.
CREATE UNIQUE INDEX IF NOT EXISTS sf_pr_exceptions_ws_finding_check_uniq
  ON sf_policy_report_exceptions(workspace_id, finding_id, check_id);

