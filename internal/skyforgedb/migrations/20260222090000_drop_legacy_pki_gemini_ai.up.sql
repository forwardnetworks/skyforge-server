-- Hard cut legacy PKI/Gemini/AI tables.

DROP INDEX IF EXISTS idx_sf_user_gemini_oauth_updated_at;
DROP INDEX IF EXISTS idx_sf_user_ai_generations_user_created;

DROP TABLE IF EXISTS sf_pki_ssh_certs;
DROP TABLE IF EXISTS sf_pki_certs;
DROP TABLE IF EXISTS sf_user_gemini_oauth;
DROP TABLE IF EXISTS sf_user_ai_generations;
