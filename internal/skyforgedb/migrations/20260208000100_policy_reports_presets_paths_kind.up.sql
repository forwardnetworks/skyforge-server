-- Policy Reports: extend presets.kind to include PATHS (for scheduled Paths Assurance suites).

DO $$
DECLARE
  t regclass;
  c record;
BEGIN
  t := to_regclass('public.sf_policy_report_presets');
  IF t IS NULL THEN
    RETURN;
  END IF;

  -- Drop the existing kind check constraint if present (name depends on how it was created).
  IF EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid=t AND conname='sf_policy_report_presets_kind_check'
  ) THEN
    EXECUTE 'ALTER TABLE sf_policy_report_presets DROP CONSTRAINT sf_policy_report_presets_kind_check';
  END IF;

  -- Defensive: drop any other CHECK constraints that mention "kind" and this table.
  FOR c IN
    SELECT conname
      FROM pg_constraint
     WHERE conrelid=t AND contype='c'
       AND pg_get_constraintdef(oid) ILIKE '%kind%'
  LOOP
    EXECUTE format('ALTER TABLE sf_policy_report_presets DROP CONSTRAINT %I', c.conname);
  END LOOP;

  -- Re-add with PATHS support.
  EXECUTE 'ALTER TABLE sf_policy_report_presets ADD CONSTRAINT sf_policy_report_presets_kind_check CHECK (kind IN (''PACK'',''CUSTOM'',''PATHS''))';
END $$;

