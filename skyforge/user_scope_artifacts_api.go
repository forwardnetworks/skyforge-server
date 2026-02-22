package skyforge

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	"encore.dev/beta/errs"

	"encore.app/storage"
)

type UserScopeArtifactsListParams struct {
	Prefix string `query:"prefix" encore:"optional"`
	Limit  string `query:"limit" encore:"optional"`
}

type UserScopeArtifactsListResponse struct {
	UserScopeID     string                 `json:"userId"`
	UserScopeSlug   string                 `json:"userScopeSlug"`
	ArtifactsBucket string                 `json:"artifactsBucket"`
	Prefix          string                 `json:"prefix"`
	Items           []storageObjectSummary `json:"items"`
}

// ListUserScopeArtifacts lists artifact objects for a user scope.
//
//encore:api auth method=GET path=/api/users/:id/artifacts
func (s *Service) ListUserScopeArtifacts(ctx context.Context, id string, params *UserScopeArtifactsListParams) (*UserScopeArtifactsListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	prefix := ""
	limit := 200
	if params != nil {
		prefix = strings.TrimPrefix(strings.TrimSpace(params.Prefix), "/")
		if raw := strings.TrimSpace(params.Limit); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 500 {
				limit = v
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	items, err := listStorageArtifacts(ctx, s.cfg, pc.userScope.ID, prefix, limit)
	if err != nil {
		log.Printf("list artifacts: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list artifacts").Err()
	}
	return &UserScopeArtifactsListResponse{
		UserScopeID:     pc.userScope.ID,
		UserScopeSlug:   pc.userScope.Slug,
		ArtifactsBucket: storage.StorageBucketName,
		Prefix:          prefix,
		Items:           items,
	}, nil
}

func listStorageArtifacts(ctx context.Context, cfg Config, userScopeID, prefix string, limit int) ([]storageObjectSummary, error) {
	return listArtifactEntries(ctx, cfg, userScopeID, prefix, limit)
}
