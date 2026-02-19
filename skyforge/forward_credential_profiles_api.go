package skyforge

import (
	"context"
	"log"
	"sort"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type UserForwardCredentialProfile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	BaseURL       string `json:"baseUrl"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	Username      string `json:"username"`
	HasPassword   bool   `json:"hasPassword"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
}

type ListUserForwardCredentialProfilesResponse struct {
	Profiles []UserForwardCredentialProfile `json:"profiles"`
}

type UpsertUserForwardCredentialProfileRequest struct {
	Name          string `json:"name"`
	BaseURL       string `json:"baseUrl"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	Username      string `json:"username"`
	Password      string `json:"password"`
}

type DeleteUserForwardCredentialProfileResponse struct {
	Deleted bool `json:"deleted"`
}

// ListUserForwardCredentialProfiles lists named Forward credential sets for the current user.
//
//encore:api auth method=GET path=/api/forward/credential-profiles
func (s *Service) ListUserForwardCredentialProfiles(ctx context.Context) (*ListUserForwardCredentialProfilesResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := listUserForwardCredentialProfiles(ctxReq, s.db, newSecretBox(s.cfg.SessionSecret), user.Username)
	if err != nil {
		log.Printf("forward credential profiles list: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list Forward credential profiles").Err()
	}
	sort.Slice(rows, func(i, j int) bool {
		return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
	})
	out := make([]UserForwardCredentialProfile, 0, len(rows))
	for _, r := range rows {
		item := UserForwardCredentialProfile{
			ID:            strings.TrimSpace(r.ID),
			Name:          strings.TrimSpace(r.Name),
			BaseURL:       strings.TrimSpace(r.BaseURL),
			SkipTLSVerify: r.SkipTLSVerify,
			Username:      strings.TrimSpace(r.Username),
			HasPassword:   r.HasPassword,
		}
		if item.BaseURL == "" {
			item.BaseURL = defaultForwardBaseURL
		}
		if !r.UpdatedAt.IsZero() {
			item.UpdatedAt = r.UpdatedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, item)
	}
	return &ListUserForwardCredentialProfilesResponse{Profiles: out}, nil
}

// UpsertUserForwardCredentialProfile creates or updates one named Forward credential set for the current user.
//
//encore:api auth method=POST path=/api/forward/credential-profiles
func (s *Service) UpsertUserForwardCredentialProfile(ctx context.Context, req *UpsertUserForwardCredentialProfileRequest) (*UserForwardCredentialProfile, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	recordName := forwardProfileRecordName(name)
	if recordName == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	prof, err := upsertUserForwardProfile(
		ctxReq,
		s.db,
		newSecretBox(s.cfg.SessionSecret),
		user.Username,
		recordName,
		strings.TrimSpace(req.BaseURL),
		req.SkipTLSVerify,
		strings.TrimSpace(req.Username),
		strings.TrimSpace(req.Password),
	)
	if err != nil {
		log.Printf("forward credential profile upsert: %v", err)
		return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
	}
	if prof == nil {
		return nil, errs.B().Code(errs.Internal).Msg("failed to save credential profile").Err()
	}
	return &UserForwardCredentialProfile{
		ID:            strings.TrimSpace(prof.ID),
		Name:          name,
		BaseURL:       strings.TrimSpace(prof.BaseURL),
		SkipTLSVerify: prof.SkipTLSVerify,
		Username:      strings.TrimSpace(prof.Username),
		HasPassword:   prof.HasPassword,
		UpdatedAt:     prof.UpdatedAt.UTC().Format(time.RFC3339),
	}, nil
}

// DeleteUserForwardCredentialProfile deletes one named Forward credential set for the current user.
//
//encore:api auth method=DELETE path=/api/forward/credential-profiles/:name
func (s *Service) DeleteUserForwardCredentialProfile(ctx context.Context, name string) (*DeleteUserForwardCredentialProfileResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}
	displayName := strings.TrimSpace(name)
	if displayName == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}
	recordName := forwardProfileRecordName(displayName)
	if recordName == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("name is required").Err()
	}

	ctxReq, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := deleteUserForwardProfileByName(ctxReq, s.db, user.Username, recordName); err != nil {
		log.Printf("forward credential profile delete: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete Forward credential profile").Err()
	}
	return &DeleteUserForwardCredentialProfileResponse{Deleted: true}, nil
}
