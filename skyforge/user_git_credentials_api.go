package skyforge

import (
	"context"
	"strings"

	"encore.dev/beta/errs"
)

type UserGitCredentialsResponse struct {
	Username      string `json:"username"`
	SSHPublicKey  string `json:"sshPublicKey"`
	HasHTTPSToken bool   `json:"hasHttpsToken"`
	HTTPSUsername string `json:"httpsUsername,omitempty"`
	HasSSHKey     bool   `json:"hasSshKey"`
}

type UpdateUserGitCredentialsRequest struct {
	HTTPSUsername string `json:"httpsUsername,omitempty"`
	HTTPSToken    string `json:"httpsToken,omitempty"`
	ClearToken    bool   `json:"clearToken,omitempty"`
}

// GetUserGitCredentials returns the current user's deploy key (public) and HTTPS token status.
//
//encore:api auth method=GET path=/api/me/git-credentials
func (s *Service) GetUserGitCredentials(ctx context.Context) (*UserGitCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	rec, err := ensureUserGitDeployKey(ctx, s.db, s.box, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to load git credentials").Err()
	}
	return &UserGitCredentialsResponse{
		Username:      user.Username,
		SSHPublicKey:  strings.TrimSpace(rec.SSHPublicKey),
		HTTPSUsername: strings.TrimSpace(rec.HTTPSUsername),
		HasHTTPSToken: strings.TrimSpace(rec.HTTPSToken) != "",
		HasSSHKey:     strings.TrimSpace(rec.SSHPublicKey) != "" && strings.TrimSpace(rec.SSHPrivateKey) != "",
	}, nil
}

// UpdateUserGitCredentials sets (or clears) the user's HTTPS git token.
//
//encore:api auth method=PUT path=/api/me/git-credentials
func (s *Service) UpdateUserGitCredentials(ctx context.Context, req *UpdateUserGitCredentialsRequest) (*UserGitCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("payload required").Err()
	}
	existing, err := ensureUserGitDeployKey(ctx, s.db, s.box, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to load git credentials").Err()
	}
	existing.HTTPSUsername = strings.TrimSpace(req.HTTPSUsername)
	if req.ClearToken {
		existing.HTTPSToken = ""
	} else if strings.TrimSpace(req.HTTPSToken) != "" {
		existing.HTTPSToken = strings.TrimSpace(req.HTTPSToken)
	}
	out, err := upsertUserGitCredentials(ctx, s.db, s.box, *existing)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to save git credentials").Err()
	}
	return &UserGitCredentialsResponse{
		Username:      user.Username,
		SSHPublicKey:  strings.TrimSpace(out.SSHPublicKey),
		HTTPSUsername: strings.TrimSpace(out.HTTPSUsername),
		HasHTTPSToken: strings.TrimSpace(out.HTTPSToken) != "",
		HasSSHKey:     strings.TrimSpace(out.SSHPublicKey) != "" && strings.TrimSpace(out.SSHPrivateKey) != "",
	}, nil
}

// RotateUserGitDeployKey rotates the user's SSH deploy key.
//
//encore:api auth method=POST path=/api/me/git-credentials/rotate
func (s *Service) RotateUserGitDeployKey(ctx context.Context) (*UserGitCredentialsResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil || s.box == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	existing, err := getUserGitCredentials(ctx, s.db, s.box, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to load git credentials").Err()
	}
	if existing == nil {
		existing = &userGitCredentials{Username: user.Username}
	}
	key, err := generateEd25519Keypair()
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to generate key").Err()
	}
	existing.SSHPrivateKey = key.PrivatePEM
	existing.SSHPublicKey = strings.TrimSpace(key.PublicAuthorizedKey)
	out, err := upsertUserGitCredentials(ctx, s.db, s.box, *existing)
	if err != nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to save git credentials").Err()
	}
	return &UserGitCredentialsResponse{
		Username:      user.Username,
		SSHPublicKey:  strings.TrimSpace(out.SSHPublicKey),
		HTTPSUsername: strings.TrimSpace(out.HTTPSUsername),
		HasHTTPSToken: strings.TrimSpace(out.HTTPSToken) != "",
		HasSSHKey:     strings.TrimSpace(out.SSHPublicKey) != "" && strings.TrimSpace(out.SSHPrivateKey) != "",
	}, nil
}
