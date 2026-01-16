-- Ensure a legacy workspace ID column exists for backward compatibility.
--
-- Some code paths (or older deployments) may still reference legacy_workspace_id
-- during startup/bootstrap (e.g. dashboard snapshot generation). Keeping this
-- nullable column avoids hard failures while the rest of the legacy plumbing is
-- removed.
DO $$
BEGIN
  IF to_regclass('sf_workspaces') IS NULL THEN
    RETURN;
  END IF;

  -- Older databases might still have legacy_project_id (pre-rename); preserve
  -- values by renaming it rather than creating a new empty column.
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sf_workspaces'
      AND column_name = 'legacy_project_id'
  ) AND NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sf_workspaces'
      AND column_name = 'legacy_workspace_id'
  ) THEN
    ALTER TABLE sf_workspaces RENAME COLUMN legacy_project_id TO legacy_workspace_id;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sf_workspaces'
      AND column_name = 'legacy_workspace_id'
  ) THEN
    ALTER TABLE sf_workspaces ADD COLUMN legacy_workspace_id integer;
  END IF;
END $$;
