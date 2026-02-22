package skyforge

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type UserEnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type UserSettingsResponse struct {
	DefaultForwardCollectorConfigID string                 `json:"defaultForwardCollectorConfigId,omitempty"`
	DefaultEnv                      []UserEnvVar           `json:"defaultEnv,omitempty"`
	ExternalTemplateRepos           []ExternalTemplateRepo `json:"externalTemplateRepos,omitempty"`
	UpdatedAt                       string                 `json:"updatedAt,omitempty"`
}

type PutUserSettingsRequest struct {
	DefaultForwardCollectorConfigID string                 `json:"defaultForwardCollectorConfigId,omitempty"`
	DefaultEnv                      []UserEnvVar           `json:"defaultEnv,omitempty"`
	ExternalTemplateRepos           []ExternalTemplateRepo `json:"externalTemplateRepos,omitempty"`
}

// GetUserSettings returns the current user's saved defaults used to pre-fill forms (deployments, etc).
//
//encore:api auth method=GET path=/api/me/settings
func (s *Service) GetUserSettings(ctx context.Context) (*UserSettingsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserSettings(ctx, s.db, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to load user settings").Err()
	}
	if rec == nil {
		return &UserSettingsResponse{
			DefaultEnv: []UserEnvVar{},
		}, nil
	}
	var env []UserEnvVar
	if strings.TrimSpace(rec.DefaultEnvJSON) != "" {
		_ = json.Unmarshal([]byte(rec.DefaultEnvJSON), &env)
	}
	var repos []ExternalTemplateRepo
	if strings.TrimSpace(rec.ExternalTemplateReposJSON) != "" {
		_ = json.Unmarshal([]byte(rec.ExternalTemplateReposJSON), &repos)
	}
	return &UserSettingsResponse{
		DefaultForwardCollectorConfigID: strings.TrimSpace(rec.DefaultForwardCollectorConfig),
		DefaultEnv:                      env,
		ExternalTemplateRepos:           repos,
		UpdatedAt:                       rec.UpdatedAt.UTC().Format(time.RFC3339),
	}, nil
}

// PutUserSettings upserts the current user's saved defaults used to pre-fill forms (deployments, etc).
//
//encore:api auth method=PUT path=/api/me/settings
func (s *Service) PutUserSettings(ctx context.Context, req *PutUserSettingsRequest) (*UserSettingsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	for i := range req.DefaultEnv {
		req.DefaultEnv[i].Key = strings.TrimSpace(req.DefaultEnv[i].Key)
		req.DefaultEnv[i].Value = strings.TrimSpace(req.DefaultEnv[i].Value)
	}
	envJSON, err := json.Marshal(req.DefaultEnv)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid defaultEnv").Err()
	}
	validatedRepos, err := validateExternalTemplateRepos(req.ExternalTemplateRepos)
	if err != nil {
		return nil, err
	}
	reposJSON, err := json.Marshal(validatedRepos)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid externalTemplateRepos").Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := upsertUserSettings(ctx, s.db, userSettingsRecord{
		UserID:                        user.Username,
		DefaultForwardCollectorConfig: strings.TrimSpace(req.DefaultForwardCollectorConfigID),
		DefaultEnvJSON:                string(envJSON),
		ExternalTemplateReposJSON:     string(reposJSON),
	})
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to save user settings").Err()
	}
	var env []UserEnvVar
	_ = json.Unmarshal([]byte(out.DefaultEnvJSON), &env)
	var repos []ExternalTemplateRepo
	_ = json.Unmarshal([]byte(out.ExternalTemplateReposJSON), &repos)
	return &UserSettingsResponse{
		DefaultForwardCollectorConfigID: strings.TrimSpace(out.DefaultForwardCollectorConfig),
		DefaultEnv:                      env,
		ExternalTemplateRepos:           repos,
		UpdatedAt:                       out.UpdatedAt.UTC().Format(time.RFC3339),
	}, nil
}
