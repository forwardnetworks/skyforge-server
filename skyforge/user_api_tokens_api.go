package skyforge

import (
	"context"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type UserAPIToken struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	UsedCount  int64  `json:"usedCount"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
	RevokedAt  string `json:"revokedAt,omitempty"`
}

type ListUserAPITokensResponse struct {
	Tokens []UserAPIToken `json:"tokens"`
}

type CreateUserAPITokenRequest struct {
	Name string `json:"name,omitempty"`
}

type CreateUserAPITokenResponse struct {
	Token UserAPIToken `json:"token"`
	// Secret is only returned once at creation time.
	Secret string `json:"secret"`
}

// ListUserAPITokens lists the current user's API tokens (secrets are never returned).
//
//encore:api auth method=GET path=/api/user/api-tokens
func (s *Service) ListUserAPITokens(ctx context.Context) (*ListUserAPITokensResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	recs, err := listUserAPITokens(ctx, s.db, user.Username)
	if err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list tokens").Err()
	}
	out := make([]UserAPIToken, 0, len(recs))
	for _, r := range recs {
		t := UserAPIToken{
			ID:        strings.TrimSpace(r.ID),
			Name:      strings.TrimSpace(r.Name),
			Prefix:    strings.TrimSpace(r.Prefix),
			UsedCount: r.UsedCount,
			CreatedAt: r.CreatedAt.UTC().Format(time.RFC3339),
		}
		if r.LastUsedAt.Valid {
			t.LastUsedAt = r.LastUsedAt.Time.UTC().Format(time.RFC3339)
		}
		if r.RevokedAt.Valid {
			t.RevokedAt = r.RevokedAt.Time.UTC().Format(time.RFC3339)
		}
		out = append(out, t)
	}
	return &ListUserAPITokensResponse{Tokens: out}, nil
}

// CreateUserAPIToken creates a new API token for the current user.
//
//encore:api auth method=POST path=/api/user/api-tokens
func (s *Service) CreateUserAPIToken(ctx context.Context, req *CreateUserAPITokenRequest) (*CreateUserAPITokenResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	name := ""
	if req != nil {
		name = req.Name
	}
	rec, secret, err := createUserAPIToken(ctx, s.db, user.Username, name)
	if err != nil {
		return nil, err
	}
	out := UserAPIToken{
		ID:        strings.TrimSpace(rec.ID),
		Name:      strings.TrimSpace(rec.Name),
		Prefix:    strings.TrimSpace(rec.Prefix),
		UsedCount: rec.UsedCount,
		CreatedAt: rec.CreatedAt.UTC().Format(time.RFC3339),
	}
	return &CreateUserAPITokenResponse{Token: out, Secret: secret}, nil
}

// RevokeUserAPIToken revokes an API token for the current user.
//
//encore:api auth method=DELETE path=/api/user/api-tokens/:tokenId
func (s *Service) RevokeUserAPIToken(ctx context.Context, tokenId string) error {
	user, err := requireAuthUser()
	if err != nil {
		return err
	}
	if strings.TrimSpace(tokenId) == "" {
		return errs.B().Code(errs.InvalidArgument).Msg("tokenId is required").Err()
	}
	return revokeUserAPIToken(ctx, s.db, user.Username, tokenId)
}

