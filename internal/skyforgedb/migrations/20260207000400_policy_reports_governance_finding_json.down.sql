DROP INDEX IF EXISTS sf_pr_exceptions_ws_finding_check_uniq;
DROP INDEX IF EXISTS sf_pr_rc_assignments_campaign_finding_check_uniq;

ALTER TABLE sf_policy_report_recert_assignments
  DROP COLUMN IF EXISTS finding;

