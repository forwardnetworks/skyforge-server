DROP INDEX IF EXISTS sf_capacity_rollups_fwd_uq;
DROP INDEX IF EXISTS sf_capacity_rollups_fwd_lookup_idx;
DROP INDEX IF EXISTS sf_capacity_rollups_fwd_object_idx;
DROP INDEX IF EXISTS sf_capacity_nqe_cache_fwd_uq;
DROP INDEX IF EXISTS sf_capacity_nqe_cache_fwd_lookup_idx;

-- Best-effort. This will fail if NULL rows exist.
ALTER TABLE sf_capacity_rollups ALTER COLUMN deployment_id SET NOT NULL;
ALTER TABLE sf_capacity_nqe_cache ALTER COLUMN deployment_id SET NOT NULL;

