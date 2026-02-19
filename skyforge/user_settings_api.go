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
	ForwardSaaSCollectorConfigID    string                 `json:"forwardSaasCollectorConfigId,omitempty"`
	ForwardSaaSBaseURL              string                 `json:"forwardSaasBaseUrl,omitempty"`
	ForwardSaaSUsername             string                 `json:"forwardSaasUsername,omitempty"`
	ForwardSaaSHasPassword          bool                   `json:"forwardSaasHasPassword"`
	ForwardOnPremCollectorConfigID  string                 `json:"forwardOnPremCollectorConfigId,omitempty"`
	ForwardOnPremBaseURL            string                 `json:"forwardOnPremBaseUrl,omitempty"`
	ForwardOnPremSkipTLSVerify      bool                   `json:"forwardOnPremSkipTlsVerify"`
	ForwardOnPremUsername           string                 `json:"forwardOnPremUsername,omitempty"`
	ForwardOnPremHasPassword        bool                   `json:"forwardOnPremHasPassword"`
	DefaultEnv                      []UserEnvVar           `json:"defaultEnv,omitempty"`
	ExternalTemplateRepos           []ExternalTemplateRepo `json:"externalTemplateRepos,omitempty"`
	UpdatedAt                       string                 `json:"updatedAt,omitempty"`
}

type PutUserSettingsRequest struct {
	DefaultForwardCollectorConfigID string                 `json:"defaultForwardCollectorConfigId,omitempty"`
	ForwardSaaSBaseURL              string                 `json:"forwardSaasBaseUrl,omitempty"`
	ForwardSaaSUsername             string                 `json:"forwardSaasUsername,omitempty"`
	ForwardSaaSPassword             string                 `json:"forwardSaasPassword,omitempty"`
	ClearForwardSaaSProfile         bool                   `json:"clearForwardSaasProfile,omitempty"`
	ForwardOnPremBaseURL            string                 `json:"forwardOnPremBaseUrl,omitempty"`
	ForwardOnPremSkipTLSVerify      bool                   `json:"forwardOnPremSkipTlsVerify,omitempty"`
	ForwardOnPremUsername           string                 `json:"forwardOnPremUsername,omitempty"`
	ForwardOnPremPassword           string                 `json:"forwardOnPremPassword,omitempty"`
	ClearForwardOnPremProfile       bool                   `json:"clearForwardOnPremProfile,omitempty"`
	DefaultEnv                      []UserEnvVar           `json:"defaultEnv,omitempty"`
	ExternalTemplateRepos           []ExternalTemplateRepo `json:"externalTemplateRepos,omitempty"`
}

// GetUserSettings returns the current user's saved defaults used to pre-fill forms (deployments, etc).
//
//encore:api auth method=GET path=/api/settings
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
	box := newSecretBox(s.cfg.SessionSecret)
	saasProfile, _ := getUserForwardProfileByName(ctx, s.db, box, user.Username, forwardProfileSaaSName)
	onPremProfile, _ := getUserForwardProfileByName(ctx, s.db, box, user.Username, forwardProfileOnPremName)
	var env []UserEnvVar
	if strings.TrimSpace(rec.DefaultEnvJSON) != "" {
		_ = json.Unmarshal([]byte(rec.DefaultEnvJSON), &env)
	}
	var repos []ExternalTemplateRepo
	if strings.TrimSpace(rec.ExternalTemplateReposJSON) != "" {
		_ = json.Unmarshal([]byte(rec.ExternalTemplateReposJSON), &repos)
	}
	defaultCollector := strings.TrimSpace(rec.DefaultForwardCollectorConfig)
	if defaultCollector == "" && saasProfile != nil {
		defaultCollector = strings.TrimSpace(saasProfile.ID)
	}
	return &UserSettingsResponse{
		DefaultForwardCollectorConfigID: defaultCollector,
		ForwardSaaSCollectorConfigID:    profileIDOrEmpty(saasProfile),
		ForwardSaaSBaseURL:              profileBaseURLOrDefault(saasProfile),
		ForwardSaaSUsername:             profileUsernameOrEmpty(saasProfile),
		ForwardSaaSHasPassword:          profileHasPassword(saasProfile),
		ForwardOnPremCollectorConfigID:  profileIDOrEmpty(onPremProfile),
		ForwardOnPremBaseURL:            profileBaseURLOrEmpty(onPremProfile),
		ForwardOnPremSkipTLSVerify:      profileSkipTLSOrFalse(onPremProfile),
		ForwardOnPremUsername:           profileUsernameOrEmpty(onPremProfile),
		ForwardOnPremHasPassword:        profileHasPassword(onPremProfile),
		DefaultEnv:                      env,
		ExternalTemplateRepos:           repos,
		UpdatedAt:                       rec.UpdatedAt.UTC().Format(time.RFC3339),
	}, nil
}

// PutUserSettings upserts the current user's saved defaults used to pre-fill forms (deployments, etc).
//
//encore:api auth method=PUT path=/api/settings
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
	box := newSecretBox(s.cfg.SessionSecret)
	if req.ClearForwardSaaSProfile {
		_ = deleteUserForwardProfileByName(ctx, s.db, user.Username, forwardProfileSaaSName)
	} else if strings.TrimSpace(req.ForwardSaaSUsername) != "" || strings.TrimSpace(req.ForwardSaaSPassword) != "" {
		saasBaseURL := strings.TrimSpace(req.ForwardSaaSBaseURL)
		if saasBaseURL == "" {
			saasBaseURL = defaultForwardBaseURL
		}
		if _, err := upsertUserForwardProfile(
			ctx,
			s.db,
			box,
			user.Username,
			forwardProfileSaaSName,
			saasBaseURL,
			false,
			strings.TrimSpace(req.ForwardSaaSUsername),
			strings.TrimSpace(req.ForwardSaaSPassword),
		); err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward SaaS profile").Err()
		}
	}
	if req.ClearForwardOnPremProfile {
		_ = deleteUserForwardProfileByName(ctx, s.db, user.Username, forwardProfileOnPremName)
	} else if strings.TrimSpace(req.ForwardOnPremBaseURL) != "" || strings.TrimSpace(req.ForwardOnPremUsername) != "" || strings.TrimSpace(req.ForwardOnPremPassword) != "" {
		if _, err := upsertUserForwardProfile(
			ctx,
			s.db,
			box,
			user.Username,
			forwardProfileOnPremName,
			strings.TrimSpace(req.ForwardOnPremBaseURL),
			req.ForwardOnPremSkipTLSVerify,
			strings.TrimSpace(req.ForwardOnPremUsername),
			strings.TrimSpace(req.ForwardOnPremPassword),
		); err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid Forward On-prem profile").Err()
		}
	}
	saasProfile, _ := getUserForwardProfileByName(ctx, s.db, box, user.Username, forwardProfileSaaSName)
	onPremProfile, _ := getUserForwardProfileByName(ctx, s.db, box, user.Username, forwardProfileOnPremName)
	var env []UserEnvVar
	_ = json.Unmarshal([]byte(out.DefaultEnvJSON), &env)
	var repos []ExternalTemplateRepo
	_ = json.Unmarshal([]byte(out.ExternalTemplateReposJSON), &repos)
	defaultCollector := strings.TrimSpace(out.DefaultForwardCollectorConfig)
	if defaultCollector == "" && saasProfile != nil {
		defaultCollector = strings.TrimSpace(saasProfile.ID)
	}
	return &UserSettingsResponse{
		DefaultForwardCollectorConfigID: defaultCollector,
		ForwardSaaSCollectorConfigID:    profileIDOrEmpty(saasProfile),
		ForwardSaaSBaseURL:              profileBaseURLOrDefault(saasProfile),
		ForwardSaaSUsername:             profileUsernameOrEmpty(saasProfile),
		ForwardSaaSHasPassword:          profileHasPassword(saasProfile),
		ForwardOnPremCollectorConfigID:  profileIDOrEmpty(onPremProfile),
		ForwardOnPremBaseURL:            profileBaseURLOrEmpty(onPremProfile),
		ForwardOnPremSkipTLSVerify:      profileSkipTLSOrFalse(onPremProfile),
		ForwardOnPremUsername:           profileUsernameOrEmpty(onPremProfile),
		ForwardOnPremHasPassword:        profileHasPassword(onPremProfile),
		DefaultEnv:                      env,
		ExternalTemplateRepos:           repos,
		UpdatedAt:                       out.UpdatedAt.UTC().Format(time.RFC3339),
	}, nil
}

func profileBaseURLOrDefault(p *userForwardProfile) string {
	if p == nil {
		return defaultForwardBaseURL
	}
	base := strings.TrimSpace(p.BaseURL)
	if base == "" {
		return defaultForwardBaseURL
	}
	return base
}

func profileIDOrEmpty(p *userForwardProfile) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(p.ID)
}

func profileUsernameOrEmpty(p *userForwardProfile) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(p.Username)
}

func profileBaseURLOrEmpty(p *userForwardProfile) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(p.BaseURL)
}

func profileSkipTLSOrFalse(p *userForwardProfile) bool {
	if p == nil {
		return false
	}
	return p.SkipTLSVerify
}

func profileHasPassword(p *userForwardProfile) bool {
	return p != nil && p.HasPassword
}
