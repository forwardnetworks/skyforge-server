-- Drop legacy workspace ID columns.
--
-- We historically carried legacy_project_id / legacy_workspace_id for backward
-- compatibility during the project→workspace rename. Those columns are no
-- longer used by Skyforge; keep them out of the final schema state.
DO $$
BEGIN
  IF to_regclass('sf_workspaces') IS NULL THEN
    RETURN;
  END IF;

  -- Extremely old DBs could still have legacy_project_id.
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sf_workspaces'
      AND column_name = 'legacy_project_id'
  ) THEN
    ALTER TABLE sf_workspaces DROP COLUMN legacy_project_id;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sf_workspaces'
      AND column_name = 'legacy_workspace_id'
  ) THEN
    ALTER TABLE sf_workspaces DROP COLUMN legacy_workspace_id;
  END IF;
END $$;

