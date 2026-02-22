-- Hard cut legacy Elastic integration storage.
DROP INDEX IF EXISTS idx_sf_user_elastic_config_updated_at;
DROP TABLE IF EXISTS sf_user_elastic_config;
