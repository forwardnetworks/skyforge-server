DO $$
DECLARE
  rec RECORD;
BEGIN
  FOR rec IN
    SELECT table_schema, table_name
    FROM information_schema.columns
    WHERE table_schema = 'public' AND column_name = 'workspace_id'
  LOOP
    EXECUTE format(
      'ALTER TABLE %I.%I RENAME COLUMN workspace_id TO user_id',
      rec.table_schema, rec.table_name
    );
  END LOOP;

  FOR rec IN
    SELECT table_schema, table_name
    FROM information_schema.columns
    WHERE table_schema = 'public' AND column_name = 'last_task_workspace_id'
  LOOP
    EXECUTE format(
      'ALTER TABLE %I.%I RENAME COLUMN last_task_workspace_id TO last_task_user_id',
      rec.table_schema, rec.table_name
    );
  END LOOP;
END
$$;
