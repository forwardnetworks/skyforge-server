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

type ProjectArtifactUploadRequest struct {
	Key           string `json:"key"`
	ContentBase64 string `json:"contentBase64"`
}

type ProjectArtifactUploadResponse struct {
	Status        string `json:"status"`
	Bucket        string `json:"bucket"`
	Key           string `json:"key"`
	ProjectID     string `json:"projectId"`
	ProjectSlug   string `json:"projectSlug"`
	UploadedBy    string `json:"uploadedBy"`
	UploadedAtUtc string `json:"uploadedAtUtc,omitempty"`
}

type ProjectArtifactDownloadParams struct {
	Key string `query:"key"`
}

type ProjectArtifactDownloadResponse struct {
	Status   string `json:"status"`
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	FileData string `json:"fileData"`
}

// UploadProjectArtifact uploads or presigns an artifact to the project's bucket.
//
//encore:api auth method=POST path=/api/projects/:id/artifacts/upload
func (s *Service) UploadProjectArtifact(ctx context.Context, id string, req *ProjectArtifactUploadRequest) (*ProjectArtifactUploadResponse, error) {
	return s.handleProjectArtifactUpload(ctx, id, req)
}

// UploadProjectArtifactV1 uploads or presigns an artifact (v1 alias).
//
//encore:api auth method=POST path=/api/v1/projects/:id/artifacts/upload
func (s *Service) UploadProjectArtifactV1(ctx context.Context, id string, req *ProjectArtifactUploadRequest) (*ProjectArtifactUploadResponse, error) {
	return s.handleProjectArtifactUpload(ctx, id, req)
}

func (s *Service) handleProjectArtifactUpload(ctx context.Context, id string, req *ProjectArtifactUploadRequest) (*ProjectArtifactUploadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	objectName := artifactObjectName(pc.project.ID, key)
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
			"project.artifact.upload",
			pc.project.ID,
			fmt.Sprintf("bucket=%s key=%s size=%d", storage.StorageBucketName, key, len(payload)),
		)
	}
	return &ProjectArtifactUploadResponse{
		Status:        "uploaded",
		Bucket:        storage.StorageBucketName,
		Key:           key,
		ProjectID:     pc.project.ID,
		ProjectSlug:   pc.project.Slug,
		UploadedBy:    pc.claims.Username,
		UploadedAtUtc: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// DownloadProjectArtifact returns a presigned download redirect for the artifact.
//
//encore:api auth method=GET path=/api/projects/:id/artifacts/download
func (s *Service) DownloadProjectArtifact(ctx context.Context, id string, params *ProjectArtifactDownloadParams) (*ProjectArtifactDownloadResponse, error) {
	return s.handleProjectArtifactDownload(ctx, id, params)
}

// DownloadProjectArtifactV1 returns a presigned download redirect (v1 alias).
//
//encore:api auth method=GET path=/api/v1/projects/:id/artifacts/download
func (s *Service) DownloadProjectArtifactV1(ctx context.Context, id string, params *ProjectArtifactDownloadParams) (*ProjectArtifactDownloadResponse, error) {
	return s.handleProjectArtifactDownload(ctx, id, params)
}

func (s *Service) handleProjectArtifactDownload(ctx context.Context, id string, params *ProjectArtifactDownloadParams) (*ProjectArtifactDownloadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.projectContextForUser(user, id)
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
	objectName := artifactObjectName(pc.project.ID, key)
	data, err := storage.Read(ctx, &storage.ReadRequest{ObjectName: objectName})
	if err != nil {
		return nil, errs.B().Code(errs.NotFound).Msg("artifact not found").Err()
	}
	artifactDownloads.Add(1)
	return &ProjectArtifactDownloadResponse{
		Status:   "ok",
		Bucket:   storage.StorageBucketName,
		Key:      key,
		FileData: base64.StdEncoding.EncodeToString(data.Data),
	}, nil
}

func artifactObjectName(projectID, key string) string {
	projectID = strings.TrimSpace(projectID)
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if projectID == "" {
		return fmt.Sprintf("artifacts/%s", key)
	}
	return fmt.Sprintf("artifacts/%s/%s", projectID, key)
}
