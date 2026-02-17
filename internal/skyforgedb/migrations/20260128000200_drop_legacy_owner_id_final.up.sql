-- Drop legacy owner ID columns.
--
-- We historically carried legacy_project_id / legacy_owner_id for backward
-- compatibility during the project→owner rename. Those columns are no
-- longer used by Skyforge; keep them out of the final schema state.
DO $$
BEGIN
  IF to_regclass('sf_owner_contexts') IS NULL THEN
    RETURN;
  END IF;

  -- Extremely old DBs could still have legacy_project_id.
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sf_owner_contexts'
      AND column_name = 'legacy_project_id'
  ) THEN
    ALTER TABLE sf_owner_contexts DROP COLUMN legacy_project_id;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sf_owner_contexts'
      AND column_name = 'legacy_owner_id'
  ) THEN
    ALTER TABLE sf_owner_contexts DROP COLUMN legacy_owner_id;
  END IF;
END $$;

