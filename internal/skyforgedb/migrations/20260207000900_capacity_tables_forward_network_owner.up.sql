-- Allow capacity rollups and NQE cache rows to be keyed by Forward Network ID alone
-- (deployment_id is NULL) to support user-managed Forward networks.

ALTER TABLE sf_capacity_rollups ALTER COLUMN deployment_id DROP NOT NULL;
ALTER TABLE sf_capacity_nqe_cache ALTER COLUMN deployment_id DROP NOT NULL;

-- Enforce uniqueness for network-ownerd rows (deployment_id IS NULL).
CREATE UNIQUE INDEX IF NOT EXISTS sf_capacity_rollups_fwd_uq
  ON sf_capacity_rollups(owner_id, forward_network_id, object_type, object_id, metric, window_label, period_end)
  WHERE deployment_id IS NULL;

CREATE INDEX IF NOT EXISTS sf_capacity_rollups_fwd_lookup_idx
  ON sf_capacity_rollups(owner_id, forward_network_id, metric, window_label, period_end DESC)
  WHERE deployment_id IS NULL;

CREATE INDEX IF NOT EXISTS sf_capacity_rollups_fwd_object_idx
  ON sf_capacity_rollups(owner_id, forward_network_id, object_type, object_id)
  WHERE deployment_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS sf_capacity_nqe_cache_fwd_uq
  ON sf_capacity_nqe_cache(owner_id, forward_network_id, query_id, snapshot_id)
  WHERE deployment_id IS NULL;

CREATE INDEX IF NOT EXISTS sf_capacity_nqe_cache_fwd_lookup_idx
  ON sf_capacity_nqe_cache(owner_id, forward_network_id, query_id, created_at DESC)
  WHERE deployment_id IS NULL;

