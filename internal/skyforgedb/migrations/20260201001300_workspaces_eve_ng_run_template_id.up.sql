-- Ensure sf_workspaces has eve_ng_run_template_id (Skyforge uses this for the EVE-NG template pointer).
-- Older DBs may still only have labpp_run_template_id, so backfill from that when present.
ALTER TABLE IF EXISTS sf_workspaces
  ADD COLUMN IF NOT EXISTS eve_ng_run_template_id integer;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'sf_workspaces'
      AND column_name = 'labpp_run_template_id'
  ) THEN
    EXECUTE $q$
      UPDATE sf_workspaces
        SET eve_ng_run_template_id = labpp_run_template_id
        WHERE eve_ng_run_template_id IS NULL
          AND labpp_run_template_id IS NOT NULL
    $q$;
  END IF;
END $$;
