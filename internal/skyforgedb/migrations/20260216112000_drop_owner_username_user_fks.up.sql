-- Legacy compatibility: current runtime stores owner context IDs in owner_username
-- columns for user-scoped data. Historical FK constraints to sf_users(username)
-- reject valid writes (for example sf_deployments inserts).
--
-- Drop owner_username -> sf_users FKs so mixed-state databases keep working.

DO $$
DECLARE
  r RECORD;
BEGIN
  FOR r IN
    SELECT n.nspname AS schema_name, c.relname AS table_name, con.conname AS constraint_name
      FROM pg_constraint con
      JOIN pg_class c ON c.oid = con.conrelid
      JOIN pg_namespace n ON n.oid = c.relnamespace
      JOIN unnest(con.conkey) AS k(attnum) ON TRUE
      JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
     WHERE con.contype = 'f'
       AND n.nspname = 'public'
       AND con.confrelid = 'public.sf_users'::regclass
       AND a.attname = 'owner_username'
  LOOP
    EXECUTE format('ALTER TABLE %I.%I DROP CONSTRAINT %I', r.schema_name, r.table_name, r.constraint_name);
  END LOOP;
END$$;
