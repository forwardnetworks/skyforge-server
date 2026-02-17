-- Best-effort rollback for 20260216103000_owner_schema_compatibility.

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
         WHERE table_schema = 'public' AND table_name = tbl AND column_name = 'owner_username'
       )
       AND NOT EXISTS (
         SELECT 1
         FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = tbl AND column_name = 'owner_id'
       ) THEN
      EXECUTE format('ALTER TABLE public.%I RENAME COLUMN owner_username TO owner_id', tbl);
    END IF;
  END LOOP;
END$$;

DO $$
BEGIN
  IF to_regclass('public.sf_owner_members') IS NOT NULL AND to_regclass('public.sf_owner_members') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_owner_members RENAME TO sf_owner_members';
  END IF;
  IF to_regclass('public.sf_owner_groups') IS NOT NULL AND to_regclass('public.sf_owner_groups') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_owner_groups RENAME TO sf_owner_groups';
  END IF;
  IF to_regclass('public.sf_owner_forward_credentials') IS NOT NULL AND to_regclass('public.sf_owner_forward_credentials') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_owner_forward_credentials RENAME TO sf_owner_forward_credentials';
  END IF;
  IF to_regclass('public.sf_owner_aws_static_credentials') IS NOT NULL AND to_regclass('public.sf_owner_aws_static_credentials') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_owner_aws_static_credentials RENAME TO sf_owner_aws_static_credentials';
  END IF;
  IF to_regclass('public.sf_owner_azure_credentials') IS NOT NULL AND to_regclass('public.sf_owner_azure_credentials') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_owner_azure_credentials RENAME TO sf_owner_azure_credentials';
  END IF;
  IF to_regclass('public.sf_owner_gcp_credentials') IS NOT NULL AND to_regclass('public.sf_owner_gcp_credentials') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_owner_gcp_credentials RENAME TO sf_owner_gcp_credentials';
  END IF;
  IF to_regclass('public.sf_owner_variable_groups') IS NOT NULL AND to_regclass('public.sf_owner_variable_groups') IS NULL THEN
    EXECUTE 'ALTER TABLE public.sf_owner_variable_groups RENAME TO sf_owner_variable_groups';
  END IF;
END$$;
