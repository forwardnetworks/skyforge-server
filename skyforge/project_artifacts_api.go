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

type ProjectArtifactsListParams struct {
	Prefix string `query:"prefix" encore:"optional"`
	Limit  string `query:"limit" encore:"optional"`
}

type ProjectArtifactsListResponse struct {
	ProjectID       string                 `json:"projectId"`
	ProjectSlug     string                 `json:"projectSlug"`
	ArtifactsBucket string                 `json:"artifactsBucket"`
	Prefix          string                 `json:"prefix"`
	Items           []storageObjectSummary `json:"items"`
}

// ListProjectArtifacts lists artifact objects for a project.
//
//encore:api auth method=GET path=/api/projects/:id/artifacts
func (s *Service) ListProjectArtifacts(ctx context.Context, id string, params *ProjectArtifactsListParams) (*ProjectArtifactsListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	items, err := listStorageArtifacts(ctx, pc.project.ID, prefix, limit)
	if err != nil {
		log.Printf("list artifacts: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list artifacts").Err()
	}
	return &ProjectArtifactsListResponse{
		ProjectID:       pc.project.ID,
		ProjectSlug:     pc.project.Slug,
		ArtifactsBucket: storage.StorageBucketName,
		Prefix:          prefix,
		Items:           items,
	}, nil
}

func listStorageArtifacts(ctx context.Context, projectID, prefix string, limit int) ([]storageObjectSummary, error) {
	return listArtifactEntries(ctx, projectID, prefix, limit)
}
