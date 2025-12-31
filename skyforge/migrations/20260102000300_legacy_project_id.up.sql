DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = 'sf_projects'
      AND column_name = 'semaphore_project_id'
  ) THEN
    ALTER TABLE sf_projects RENAME COLUMN semaphore_project_id TO legacy_project_id;
  END IF;
END $$;
