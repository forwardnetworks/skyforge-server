-- Compatibility migration for databases that stopped at a mixed workspace/owner state.
-- Normalizes legacy sf_workspace_* tables and owner_id columns to owner_* / owner_username
-- naming expected by current server code.

DO $$
BEGIN
  IF to_regclass('public.sf_workspace_members') IS NOT NULL AND to_regclass('public.sf_owner_members') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_workspace_members RENAME TO sf_owner_members';
  END IF;
  IF to_regclass('public.sf_workspace_groups') IS NOT NULL AND to_regclass('public.sf_owner_groups') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_workspace_groups RENAME TO sf_owner_groups';
  END IF;
  IF to_regclass('public.sf_workspace_forward_credentials') IS NOT NULL AND to_regclass('public.sf_owner_forward_credentials') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_workspace_forward_credentials RENAME TO sf_owner_forward_credentials';
  END IF;
  IF to_regclass('public.sf_workspace_aws_static_credentials') IS NOT NULL AND to_regclass('public.sf_owner_aws_static_credentials') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_workspace_aws_static_credentials RENAME TO sf_owner_aws_static_credentials';
  END IF;
  IF to_regclass('public.sf_workspace_azure_credentials') IS NOT NULL AND to_regclass('public.sf_owner_azure_credentials') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_workspace_azure_credentials RENAME TO sf_owner_azure_credentials';
  END IF;
  IF to_regclass('public.sf_workspace_gcp_credentials') IS NOT NULL AND to_regclass('public.sf_owner_gcp_credentials') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_workspace_gcp_credentials RENAME TO sf_owner_gcp_credentials';
  END IF;
  IF to_regclass('public.sf_workspace_variable_groups') IS NOT NULL AND to_regclass('public.sf_owner_variable_groups') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_workspace_variable_groups RENAME TO sf_owner_variable_groups';
  END IF;
END$$;

DO $$
DECLARE
  tbl text;
BEGIN
  FOREACH tbl IN ARRAY ARRAY[
    'sf_owner_members',
    'sf_owner_groups',
    'sf_owner_forward_credentials',
    'sf_owner_aws_static_credentials',
    'sf_owner_azure_credentials',
    'sf_owner_gcp_credentials',
    'sf_owner_variable_groups',
    'sf_audit_log'
  ]
  LOOP
    IF to_regclass(format('public.%s', tbl)) IS NOT NULL
       AND EXISTS (
         SELECT 1
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = tbl AND column_name = 'owner_id'
       )
       AND NOT EXISTS (
         SELECT 1
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = tbl AND column_name = 'owner_username'
       ) THEN
      EXECUTE format('ALTER TABLE public.%I RENAME COLUMN owner_id TO owner_username', tbl);
    END IF;
  END LOOP;
END$$;
