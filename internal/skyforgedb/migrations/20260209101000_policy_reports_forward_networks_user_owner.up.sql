-- Allow saved Forward networks to be user-owned (not tied to an owner).
--
-- Rationale:
-- - Forward networks are naturally owned by a Forward account/user.
-- - Skyforge owner contexts are primarily a storage/permission boundary for cached results.
-- - We still support owner-owned saved networks, but also allow user-owned ones.

ALTER TABLE sf_policy_report_forward_networks
  ADD COLUMN IF NOT EXISTS owner_username text REFERENCES sf_users(username) ON UPDATE CASCADE;

-- Owner is optional when the network is user-owned.
ALTER TABLE sf_policy_report_forward_networks
  ALTER COLUMN owner_id DROP NOT NULL;

-- Drop the legacy UNIQUE(owner_id, forward_network_id) constraint so we can replace it with
-- owner-aware unique indexes.
DO $$
DECLARE
  c record;
  cols text[];
BEGIN
  FOR c IN
    SELECT conname, conkey
      FROM pg_constraint
     WHERE conrelid = 'sf_policy_report_forward_networks'::regclass
       AND contype = 'u'
  LOOP
    SELECT array_agg(a.attname ORDER BY u.ord)
      INTO cols
      FROM unnest(c.conkey) WITH ORDINALITY AS u(attnum, ord)
      JOIN pg_attribute a
        ON a.attrelid = 'sf_policy_report_forward_networks'::regclass
       AND a.attnum = u.attnum;

    -- Only drop the legacy UNIQUE(owner_id, forward_network_id) constraint.
    IF cols IS NOT NULL AND array_length(cols, 1) = 2 AND cols @> ARRAY['owner_id','forward_network_id'] THEN
      EXECUTE format('ALTER TABLE sf_policy_report_forward_networks DROP CONSTRAINT IF EXISTS %I', c.conname);
    END IF;
  END LOOP;
END $$;

-- Exactly one owner must be set: owner_id XOR owner_username.
ALTER TABLE sf_policy_report_forward_networks
  ADD CONSTRAINT sf_pr_forward_networks_owner_chk
  CHECK ( (owner_id IS NOT NULL) <> (owner_username IS NOT NULL) )
  NOT VALID;

ALTER TABLE sf_policy_report_forward_networks
  VALIDATE CONSTRAINT sf_pr_forward_networks_owner_chk;

-- Uniqueness per-owner.
CREATE UNIQUE INDEX IF NOT EXISTS sf_pr_forward_networks_owner_forward_id_uniq
  ON sf_policy_report_forward_networks(owner_id, forward_network_id)
  WHERE owner_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS sf_pr_forward_networks_owner_forward_uniq
  ON sf_policy_report_forward_networks(owner_username, forward_network_id)
  WHERE owner_username IS NOT NULL;

CREATE INDEX IF NOT EXISTS sf_pr_forward_networks_owner_created_idx
  ON sf_policy_report_forward_networks(owner_username, created_at DESC)
  WHERE owner_username IS NOT NULL;
