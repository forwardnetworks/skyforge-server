-- Revert owner semantics back to owner semantics.
-- This migration is idempotent across mixed states.

DO $$
DECLARE
  r RECORD;
  new_name text;
BEGIN
  -- Constraint names containing owner -> owner.
  FOR r IN
    SELECT n.nspname AS schema_name, t.relname AS table_name, con.conname AS con_name
      FROM pg_constraint con
      JOIN pg_class t ON t.oid = con.conrelid
      JOIN pg_namespace n ON n.oid = t.relnamespace
     WHERE n.nspname = 'public'
       AND con.conname LIKE '%owner%'
  LOOP
    new_name := replace(r.con_name, 'owner', 'owner');
    IF new_name <> r.con_name THEN
      EXECUTE format('ALTER TABLE %I.%I RENAME CONSTRAINT %I TO %I', r.schema_name, r.table_name, r.con_name, new_name);
    END IF;
  END LOOP;

  -- Index names containing owner -> owner.
  FOR r IN
    SELECT n.nspname AS schema_name, c.relname AS rel_name
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'i'
       AND c.relname LIKE '%owner%'
  LOOP
    new_name := replace(r.rel_name, 'owner', 'owner');
    IF new_name <> r.rel_name AND to_regclass(format('%I.%I', r.schema_name, new_name)) IS NULL THEN
      EXECUTE format('ALTER INDEX %I.%I RENAME TO %I', r.schema_name, r.rel_name, new_name);
    END IF;
  END LOOP;

  -- Column renames.
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='public' AND table_name='sf_deployments' AND column_name='last_task_owner_id'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='public' AND table_name='sf_deployments' AND column_name='last_task_owner_id'
  ) THEN
    EXECUTE 'ALTER TABLE public.sf_deployments RENAME COLUMN last_task_owner_id TO last_task_owner_id';
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='public' AND table_name='sf_usage_snapshots' AND column_name='owner_context_id'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='public' AND table_name='sf_usage_snapshots' AND column_name='owner_context_id'
  ) THEN
    EXECUTE 'ALTER TABLE public.sf_usage_snapshots RENAME COLUMN owner_context_id TO owner_context_id';
  END IF;

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='public' AND table_name='sf_usage_snapshots' AND column_name='owner_type'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
     WHERE table_schema='public' AND table_name='sf_usage_snapshots' AND column_name='owner_type'
  ) THEN
    EXECUTE 'ALTER TABLE public.sf_usage_snapshots RENAME COLUMN owner_type TO owner_type';
  END IF;

  FOR r IN
    SELECT table_schema, table_name
      FROM information_schema.columns c
     WHERE c.table_schema = 'public'
       AND c.column_name = 'owner_id'
       AND c.table_name <> 'sf_usage_snapshots'
       AND NOT EXISTS (
         SELECT 1
           FROM information_schema.columns c2
          WHERE c2.table_schema = c.table_schema
            AND c2.table_name = c.table_name
            AND c2.column_name = 'owner_id'
       )
  LOOP
    EXECUTE format('ALTER TABLE %I.%I RENAME COLUMN owner_id TO owner_id', r.table_schema, r.table_name);
  END LOOP;

  -- Generic table names containing owner -> owner.
  FOR r IN
    SELECT n.nspname AS schema_name, c.relname AS rel_name
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'r'
       AND c.relname LIKE '%owner%'
  LOOP
    new_name := replace(r.rel_name, 'owner', 'owner');
    IF new_name <> r.rel_name AND to_regclass(format('%I.%I', r.schema_name, new_name)) IS NULL THEN
      EXECUTE format('ALTER TABLE %I.%I RENAME TO %I', r.schema_name, r.rel_name, new_name);
    END IF;
  END LOOP;

  -- Core table rename last.
  IF to_regclass('public.sf_owner_contexts') IS NOT NULL AND to_regclass('public.sf_owner_contexts') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_owner_contexts RENAME TO sf_owner_contexts';
  END IF;
END$$;
