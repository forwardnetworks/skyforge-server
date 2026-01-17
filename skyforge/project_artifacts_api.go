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

type WorkspaceArtifactsListParams struct {
	Prefix string `query:"prefix" encore:"optional"`
	Limit  string `query:"limit" encore:"optional"`
}

type WorkspaceArtifactsListResponse struct {
	WorkspaceID     string                 `json:"workspaceId"`
	WorkspaceSlug   string                 `json:"workspaceSlug"`
	ArtifactsBucket string                 `json:"artifactsBucket"`
	Prefix          string                 `json:"prefix"`
	Items           []storageObjectSummary `json:"items"`
}

// ListWorkspaceArtifacts lists artifact objects for a workspace.
//
//encore:api auth method=GET path=/api/workspaces/:id/artifacts
func (s *Service) ListWorkspaceArtifacts(ctx context.Context, id string, params *WorkspaceArtifactsListParams) (*WorkspaceArtifactsListResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
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
	items, err := listStorageArtifacts(ctx, pc.workspace.ID, prefix, limit)
	if err != nil {
		log.Printf("list artifacts: %v", err)
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to list artifacts").Err()
	}
	return &WorkspaceArtifactsListResponse{
		WorkspaceID:     pc.workspace.ID,
		WorkspaceSlug:   pc.workspace.Slug,
		ArtifactsBucket: storage.StorageBucketName,
		Prefix:          prefix,
		Items:           items,
	}, nil
}

func listStorageArtifacts(ctx context.Context, workspaceID, prefix string, limit int) ([]storageObjectSummary, error) {
	return listArtifactEntries(ctx, workspaceID, prefix, limit)
}
