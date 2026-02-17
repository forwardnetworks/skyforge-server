-- Roll back UUID ownership columns added in 20260216000100_user_uuid_ownership.

DO $$
BEGIN
  IF to_regclass('sf_capacity_nqe_cache') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_capacity_nqe_cache_user_id_idx;
    ALTER TABLE sf_capacity_nqe_cache DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_capacity_rollups') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_capacity_rollups_user_id_idx;
    ALTER TABLE sf_capacity_rollups DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_forward_assurance_summaries') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_forward_assurance_summaries_user_id_idx;
    ALTER TABLE sf_forward_assurance_summaries DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_assurance_studio_runs') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_assurance_studio_runs_user_id_idx;
    ALTER TABLE sf_assurance_studio_runs DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_assurance_studio_scenarios') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_assurance_studio_scenarios_user_id_idx;
    ALTER TABLE sf_assurance_studio_scenarios DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_policy_report_presets') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_policy_report_presets_user_id_idx;
    ALTER TABLE sf_policy_report_presets DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_policy_report_zones') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_policy_report_zones_user_id_idx;
    ALTER TABLE sf_policy_report_zones DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_policy_report_findings_agg') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_policy_report_findings_agg_user_id_idx;
    ALTER TABLE sf_policy_report_findings_agg DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_policy_report_runs') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_policy_report_runs_user_id_started_idx;
    ALTER TABLE sf_policy_report_runs DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_policy_report_forward_networks') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_policy_report_forward_networks_user_id_idx;
    ALTER TABLE sf_policy_report_forward_networks DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_deployments') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_deployments_user_id_updated_idx;
    ALTER TABLE sf_deployments DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_tasks') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_tasks_user_id_status_idx;
    ALTER TABLE sf_tasks DROP COLUMN IF EXISTS user_id;
  END IF;

  IF to_regclass('sf_users') IS NOT NULL THEN
    DROP INDEX IF EXISTS sf_users_id_uq;
    ALTER TABLE sf_users DROP COLUMN IF EXISTS id;
  END IF;
END $$;
