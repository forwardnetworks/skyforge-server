-- Introduce canonical UUID identities for users and add user_id ownership columns
-- to high-traffic tables while preserving existing workspace_id columns for cutover.

DO $$
BEGIN
  IF to_regclass('sf_users') IS NULL THEN
    RETURN;
  END IF;

  ALTER TABLE sf_users ADD COLUMN IF NOT EXISTS id uuid;

  -- Deterministic UUID derivation from username (no extension dependency).
  UPDATE sf_users
     SET id = (
       substr(md5('skyforge:user:' || username), 1, 8) || '-' ||
       substr(md5('skyforge:user:' || username), 9, 4) || '-' ||
       '4' || substr(md5('skyforge:user:' || username), 14, 3) || '-' ||
       'a' || substr(md5('skyforge:user:' || username), 18, 3) || '-' ||
       substr(md5('skyforge:user:' || username), 21, 12)
     )::uuid
   WHERE id IS NULL;

  ALTER TABLE sf_users ALTER COLUMN id SET NOT NULL;
  CREATE UNIQUE INDEX IF NOT EXISTS sf_users_id_uq ON sf_users(id);
END $$;

DO $$
BEGIN
  IF to_regclass('sf_tasks') IS NOT NULL THEN
    ALTER TABLE sf_tasks ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_tasks t
       SET user_id = u.id
      FROM sf_users u
     WHERE t.user_id IS NULL
       AND u.username = t.created_by;
    UPDATE sf_tasks t
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE t.user_id IS NULL
       AND t.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_tasks_user_id_status_idx ON sf_tasks(user_id, status, priority DESC, id);
  END IF;

  IF to_regclass('sf_deployments') IS NOT NULL THEN
    ALTER TABLE sf_deployments ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_deployments d
       SET user_id = u.id
      FROM sf_users u
     WHERE d.user_id IS NULL
       AND u.username = d.created_by;
    UPDATE sf_deployments d
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE d.user_id IS NULL
       AND d.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_deployments_user_id_updated_idx ON sf_deployments(user_id, updated_at DESC);
  END IF;

  IF to_regclass('sf_policy_report_forward_networks') IS NOT NULL THEN
    ALTER TABLE sf_policy_report_forward_networks ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_policy_report_forward_networks n
       SET user_id = u.id
      FROM sf_users u
     WHERE n.user_id IS NULL
       AND u.username = n.owner_username;
    UPDATE sf_policy_report_forward_networks n
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE n.user_id IS NULL
       AND n.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_policy_report_forward_networks_user_id_idx ON sf_policy_report_forward_networks(user_id, updated_at DESC);
  END IF;

  IF to_regclass('sf_policy_report_runs') IS NOT NULL THEN
    ALTER TABLE sf_policy_report_runs ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_policy_report_runs r
       SET user_id = u.id
      FROM sf_users u
     WHERE r.user_id IS NULL
       AND u.username = r.created_by;
    UPDATE sf_policy_report_runs r
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE r.user_id IS NULL
       AND r.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_policy_report_runs_user_id_started_idx ON sf_policy_report_runs(user_id, started_at DESC);
  END IF;

  IF to_regclass('sf_policy_report_findings_agg') IS NOT NULL THEN
    ALTER TABLE sf_policy_report_findings_agg ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_policy_report_findings_agg f
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE f.user_id IS NULL
       AND f.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_policy_report_findings_agg_user_id_idx ON sf_policy_report_findings_agg(user_id, last_seen_at DESC);
  END IF;

  IF to_regclass('sf_policy_report_zones') IS NOT NULL THEN
    ALTER TABLE sf_policy_report_zones ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_policy_report_zones z
       SET user_id = u.id
      FROM sf_users u
     WHERE z.user_id IS NULL
       AND u.username = z.created_by;
    UPDATE sf_policy_report_zones z
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE z.user_id IS NULL
       AND z.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_policy_report_zones_user_id_idx ON sf_policy_report_zones(user_id, updated_at DESC);
  END IF;

  IF to_regclass('sf_policy_report_presets') IS NOT NULL THEN
    ALTER TABLE sf_policy_report_presets ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_policy_report_presets p
       SET user_id = u.id
      FROM sf_users u
     WHERE p.user_id IS NULL
       AND u.username = p.owner_username;
    UPDATE sf_policy_report_presets p
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE p.user_id IS NULL
       AND p.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_policy_report_presets_user_id_idx ON sf_policy_report_presets(user_id, updated_at DESC);
  END IF;

  IF to_regclass('sf_assurance_studio_scenarios') IS NOT NULL THEN
    ALTER TABLE sf_assurance_studio_scenarios ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_assurance_studio_scenarios s
       SET user_id = u.id
      FROM sf_users u
     WHERE s.user_id IS NULL
       AND u.username = s.created_by;
    UPDATE sf_assurance_studio_scenarios s
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE s.user_id IS NULL
       AND s.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_assurance_studio_scenarios_user_id_idx ON sf_assurance_studio_scenarios(user_id, updated_at DESC);
  END IF;

  IF to_regclass('sf_assurance_studio_runs') IS NOT NULL THEN
    ALTER TABLE sf_assurance_studio_runs ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_assurance_studio_runs r
       SET user_id = u.id
      FROM sf_users u
     WHERE r.user_id IS NULL
       AND u.username = r.created_by;
    UPDATE sf_assurance_studio_runs r
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE r.user_id IS NULL
       AND r.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_assurance_studio_runs_user_id_idx ON sf_assurance_studio_runs(user_id, started_at DESC);
  END IF;

  IF to_regclass('sf_forward_assurance_summaries') IS NOT NULL THEN
    ALTER TABLE sf_forward_assurance_summaries ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_forward_assurance_summaries s
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE s.user_id IS NULL
       AND s.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_forward_assurance_summaries_user_id_idx ON sf_forward_assurance_summaries(user_id, generated_at DESC);
  END IF;

  IF to_regclass('sf_capacity_rollups') IS NOT NULL THEN
    ALTER TABLE sf_capacity_rollups ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_capacity_rollups r
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE r.user_id IS NULL
       AND r.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_capacity_rollups_user_id_idx ON sf_capacity_rollups(user_id, period_end DESC);
  END IF;

  IF to_regclass('sf_capacity_nqe_cache') IS NOT NULL THEN
    ALTER TABLE sf_capacity_nqe_cache ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES sf_users(id) ON DELETE CASCADE;
    UPDATE sf_capacity_nqe_cache c
       SET user_id = u.id
      FROM sf_workspaces w
      JOIN sf_users u ON u.username = w.created_by
     WHERE c.user_id IS NULL
       AND c.workspace_id = w.id;
    CREATE INDEX IF NOT EXISTS sf_capacity_nqe_cache_user_id_idx ON sf_capacity_nqe_cache(user_id, created_at DESC);
  END IF;
END $$;
