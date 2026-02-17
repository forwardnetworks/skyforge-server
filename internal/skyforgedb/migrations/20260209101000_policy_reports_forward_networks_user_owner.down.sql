-- Revert user-ownerd Forward networks support.
--
-- This is best-effort: it deletes user-ownerd rows first.

DELETE FROM sf_policy_report_forward_networks
 WHERE owner_id IS NULL;

DROP INDEX IF EXISTS sf_pr_forward_networks_owner_created_idx;
DROP INDEX IF EXISTS sf_pr_forward_networks_owner_forward_uniq;
DROP INDEX IF EXISTS sf_pr_forward_networks_ws_forward_uniq;

ALTER TABLE sf_policy_report_forward_networks
  DROP CONSTRAINT IF EXISTS sf_pr_forward_networks_owner_chk;

ALTER TABLE sf_policy_report_forward_networks
  DROP COLUMN IF EXISTS owner_username;

ALTER TABLE sf_policy_report_forward_networks
  ALTER COLUMN owner_id SET NOT NULL;

-- Restore legacy uniqueness (owner ownerd).
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conrelid = 'sf_policy_report_forward_networks'::regclass
       AND contype = 'u'
  ) THEN
    ALTER TABLE sf_policy_report_forward_networks
      ADD CONSTRAINT sf_policy_report_forward_networks_owner_forward_key
      UNIQUE (owner_id, forward_network_id);
  END IF;
END $$;

