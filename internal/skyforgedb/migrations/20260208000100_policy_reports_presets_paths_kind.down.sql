-- Policy Reports: revert presets.kind check constraint (remove PATHS).

DO $$
DECLARE
  t regclass;
BEGIN
  t := to_regclass('public.sf_policy_report_presets');
  IF t IS NULL THEN
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_constraint
     WHERE conrelid=t AND conname='sf_policy_report_presets_kind_check'
  ) THEN
    EXECUTE 'ALTER TABLE sf_policy_report_presets DROP CONSTRAINT sf_policy_report_presets_kind_check';
  END IF;

  EXECUTE 'ALTER TABLE sf_policy_report_presets ADD CONSTRAINT sf_policy_report_presets_kind_check CHECK (kind IN (''PACK'',''CUSTOM''))';
END $$;

