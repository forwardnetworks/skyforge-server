package skyforge

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"encore.dev/beta/errs"

	"encore.app/storage"
)

type WorkspaceArtifactUploadRequest struct {
	Key           string `json:"key"`
	ContentBase64 string `json:"contentBase64"`
}

type WorkspaceArtifactUploadResponse struct {
	Status        string `json:"status"`
	Bucket        string `json:"bucket"`
	Key           string `json:"key"`
	WorkspaceID   string `json:"workspaceId"`
	WorkspaceSlug string `json:"workspaceSlug"`
	UploadedBy    string `json:"uploadedBy"`
	UploadedAtUtc string `json:"uploadedAtUtc,omitempty"`
}

type WorkspaceArtifactDownloadParams struct {
	Key string `query:"key"`
}

type WorkspaceArtifactDownloadResponse struct {
	Status   string `json:"status"`
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	FileData string `json:"fileData"`
}

// UploadWorkspaceArtifact uploads or presigns an artifact to the workspace's bucket.
//
//encore:api auth method=POST path=/api/workspaces/:id/artifacts/upload
func (s *Service) UploadWorkspaceArtifact(ctx context.Context, id string, req *WorkspaceArtifactUploadRequest) (*WorkspaceArtifactUploadResponse, error) {
	return s.handleWorkspaceArtifactUpload(ctx, id, req)
}

func (s *Service) handleWorkspaceArtifactUpload(ctx context.Context, id string, req *WorkspaceArtifactUploadRequest) (*WorkspaceArtifactUploadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	if pc.access == "viewer" {
		return nil, errs.B().Code(errs.PermissionDenied).Msg("forbidden").Err()
	}
	if req == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid payload").Err()
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("key is required").Err()
	}
	if strings.TrimSpace(req.ContentBase64) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("contentBase64 is required").Err()
	}

	payload, err := base64.StdEncoding.DecodeString(req.ContentBase64)
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid contentBase64").Err()
	}
	objectName := artifactObjectName(pc.workspace.ID, key)
	if err := storage.Write(ctx, &storage.WriteRequest{ObjectName: objectName, Data: payload}); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to upload artifact").Err()
	}
	artifactUploads.Add(1)
	if s.db != nil {
		ctxAudit, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(
			ctxAudit,
			s.db,
			actor,
			actorIsAdmin,
			impersonated,
			"workspace.artifact.upload",
			pc.workspace.ID,
			fmt.Sprintf("bucket=%s key=%s size=%d", storage.StorageBucketName, key, len(payload)),
		)
	}
	return &WorkspaceArtifactUploadResponse{
		Status:        "uploaded",
		Bucket:        storage.StorageBucketName,
		Key:           key,
		WorkspaceID:   pc.workspace.ID,
		WorkspaceSlug: pc.workspace.Slug,
		UploadedBy:    pc.claims.Username,
		UploadedAtUtc: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// DownloadWorkspaceArtifact returns a presigned download redirect for the artifact.
//
//encore:api auth method=GET path=/api/workspaces/:id/artifacts/download
func (s *Service) DownloadWorkspaceArtifact(ctx context.Context, id string, params *WorkspaceArtifactDownloadParams) (*WorkspaceArtifactDownloadResponse, error) {
	return s.handleWorkspaceArtifactDownload(ctx, id, params)
}

func (s *Service) handleWorkspaceArtifactDownload(ctx context.Context, id string, params *WorkspaceArtifactDownloadParams) (*WorkspaceArtifactDownloadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.workspaceContextForUser(user, id)
	if err != nil {
		return nil, err
	}
	key := ""
	if params != nil {
		key = strings.TrimSpace(params.Key)
	}
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("key is required").Err()
	}
	objectName := artifactObjectName(pc.workspace.ID, key)
	data, err := storage.Read(ctx, &storage.ReadRequest{ObjectName: objectName})
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("artifact not found").Err()
	}
	artifactDownloads.Add(1)
	return &WorkspaceArtifactDownloadResponse{
		Status:   "ok",
		Bucket:   storage.StorageBucketName,
		Key:      key,
		FileData: base64.StdEncoding.EncodeToString(data.Data),
	}, nil
}

func artifactObjectName(workspaceID, key string) string {
	workspaceID = strings.TrimSpace(workspaceID)
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if workspaceID == "" {
		return fmt.Sprintf("artifacts/%s", key)
	}
	return fmt.Sprintf("artifacts/%s/%s", workspaceID, key)
}
