-- Add finding JSON blobs and uniqueness constraints for Policy Reports governance.

ALTER TABLE sf_policy_report_recert_assignments
  ADD COLUMN IF NOT EXISTS finding jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Prevent duplicate assignments for the same finding within a campaign.
CREATE UNIQUE INDEX IF NOT EXISTS sf_pr_rc_assignments_campaign_finding_check_uniq
  ON sf_policy_report_recert_assignments(campaign_id, finding_id, check_id);

-- Avoid a pile-up of identical exceptions per finding.
CREATE UNIQUE INDEX IF NOT EXISTS sf_pr_exceptions_ws_finding_check_uniq
  ON sf_policy_report_exceptions(workspace_id, finding_id, check_id);

