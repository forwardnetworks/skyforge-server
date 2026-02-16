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

type UserArtifactsListParams struct {
	Prefix string `query:"prefix" encore:"optional"`
	Limit  string `query:"limit" encore:"optional"`
}

type UserArtifactsListResponse struct {
	OwnerUsername   string                 `json:"ownerUsername"`
	ContextSlug     string                 `json:"contextSlug"`
	UserSlug        string                 `json:"-"` // legacy internal field
	ArtifactsBucket string                 `json:"artifactsBucket"`
	Prefix          string                 `json:"prefix"`
	Items           []storageObjectSummary `json:"items"`
}

// ListUserArtifacts lists artifact objects for a user context.
func (s *Service) ListUserArtifacts(ctx context.Context, id string, params *UserArtifactsListParams) (*UserArtifactsListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	items, err := listStorageArtifacts(ctx, s.cfg, pc.context.ID, prefix, limit)
	if err != nil {
		log.Printf("list artifacts: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list artifacts").Err()
	}
	return &UserArtifactsListResponse{
		OwnerUsername:   pc.context.ID,
		ContextSlug:     pc.context.Slug,
		UserSlug:        pc.context.Slug,
		ArtifactsBucket: storage.StorageBucketName,
		Prefix:          prefix,
		Items:           items,
	}, nil
}

func listStorageArtifacts(ctx context.Context, cfg Config, ownerID, prefix string, limit int) ([]storageObjectSummary, error) {
	return listArtifactEntries(ctx, cfg, ownerID, prefix, limit)
}
