package skyforge

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type userSettingsRecord struct {
	UserID                        string
	DefaultForwardCollectorConfig string
	DefaultForwardCredentialID    string
	DefaultForwardNetworkID       string
	DefaultEnvJSON                string
	ExternalTemplateReposJSON     string
	UpdatedAt                     time.Time
}

func getUserSettings(ctx context.Context, db *sql.DB, userID string) (*userSettingsRecord, error) {
	if db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("user id required").Err()
	}
	var rec userSettingsRecord
	err := db.QueryRowContext(ctx, `
		SELECT user_id,
		       default_forward_collector_config_id,
		       COALESCE(default_forward_credential_id,''),
		       COALESCE(default_forward_network_id,''),
		       default_env_json,
		       external_template_repos_json,
		       updated_at
		FROM sf_user_settings
		WHERE user_id = $1`, userID).Scan(
		&rec.UserID,
		&rec.DefaultForwardCollectorConfig,
		&rec.DefaultForwardCredentialID,
		&rec.DefaultForwardNetworkID,
		&rec.DefaultEnvJSON,
		&rec.ExternalTemplateReposJSON,
		&rec.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func upsertUserSettings(ctx context.Context, db *sql.DB, rec userSettingsRecord) (*userSettingsRecord, error) {
	if db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	rec.UserID = strings.TrimSpace(rec.UserID)
	if rec.UserID == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("user id required").Err()
	}
	if strings.TrimSpace(rec.DefaultEnvJSON) == "" {
		rec.DefaultEnvJSON = "[]"
	} else {
		var tmp any
		if err := json.Unmarshal([]byte(rec.DefaultEnvJSON), &tmp); err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("defaultEnv must be valid JSON").Err()
		}
	}
	if strings.TrimSpace(rec.ExternalTemplateReposJSON) == "" {
		rec.ExternalTemplateReposJSON = "[]"
	} else {
		var tmp any
		if err := json.Unmarshal([]byte(rec.ExternalTemplateReposJSON), &tmp); err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("externalTemplateRepos must be valid JSON").Err()
		}
	}

	_, err := db.ExecContext(ctx, `
		INSERT INTO sf_user_settings (
		  user_id,
		  default_forward_collector_config_id,
		  default_forward_credential_id,
		  default_forward_network_id,
		  default_env_json,
		  external_template_repos_json
		)
		VALUES ($1, $2, NULLIF($3,''), $4, $5, $6)
		ON CONFLICT(user_id) DO UPDATE SET
			default_forward_collector_config_id=excluded.default_forward_collector_config_id,
			default_forward_credential_id=excluded.default_forward_credential_id,
			default_forward_network_id=excluded.default_forward_network_id,
			default_env_json=excluded.default_env_json,
			external_template_repos_json=excluded.external_template_repos_json,
			updated_at=now()
	`,
		rec.UserID,
		strings.TrimSpace(rec.DefaultForwardCollectorConfig),
		strings.TrimSpace(rec.DefaultForwardCredentialID),
		strings.TrimSpace(rec.DefaultForwardNetworkID),
		rec.DefaultEnvJSON,
		rec.ExternalTemplateReposJSON,
	)
	if err != nil {
		return nil, err
	}
	return getUserSettings(ctx, db, rec.UserID)
}
