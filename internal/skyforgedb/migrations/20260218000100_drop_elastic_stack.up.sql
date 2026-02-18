DROP TABLE IF EXISTS sf_user_elastic_config;

DELETE FROM sf_settings
WHERE key = 'elastic_tools_last_activity_rfc3339';
