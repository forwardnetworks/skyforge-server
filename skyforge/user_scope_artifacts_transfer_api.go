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

type UserScopeArtifactUploadRequest struct {
	Key           string `json:"key"`
	ContentBase64 string `json:"contentBase64"`
}

type UserScopeArtifactUploadResponse struct {
	Status        string `json:"status"`
	Bucket        string `json:"bucket"`
	Key           string `json:"key"`
	UserScopeID   string `json:"userId"`
	UserScopeSlug string `json:"userScopeSlug"`
	UploadedBy    string `json:"uploadedBy"`
	UploadedAtUtc string `json:"uploadedAtUtc,omitempty"`
}

type UserScopeArtifactDownloadParams struct {
	Key string `query:"key"`
}

type UserScopeArtifactDownloadResponse struct {
	Status   string `json:"status"`
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	FileData string `json:"fileData"`
}

// UploadUserScopeArtifact uploads or presigns an artifact to the user-scope bucket.
//
//encore:api auth method=POST path=/api/users/:id/artifacts/upload
func (s *Service) UploadUserScopeArtifact(ctx context.Context, id string, req *UserScopeArtifactUploadRequest) (*UserScopeArtifactUploadResponse, error) {
	return s.handleUserScopeArtifactUpload(ctx, id, req)
}

func (s *Service) handleUserScopeArtifactUpload(ctx context.Context, id string, req *UserScopeArtifactUploadRequest) (*UserScopeArtifactUploadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	objectName := artifactObjectName(pc.userScope.ID, key)

	// Prefer MinIO path-style client when available (same reason as listing/downloading).
	if c, err := objectStoreClientFor(s.cfg); err == nil && c != nil {
		if err := c.PutObjectWithContentType(ctx, artifactsBucketName, objectName, payload, "application/octet-stream"); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to upload artifact").Err()
		}
	} else {
		storageSvc, err := storage.GetService()
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("artifact storage unavailable").Err()
		}
		if err := storageSvc.Write(ctx, &storage.WriteRequest{ObjectName: objectName, Data: payload}); err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to upload artifact").Err()
		}
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
			"user-scope.artifact.upload",
			pc.userScope.ID,
			fmt.Sprintf("bucket=%s key=%s size=%d", storage.StorageBucketName, key, len(payload)),
		)
	}
	return &UserScopeArtifactUploadResponse{
		Status:        "uploaded",
		Bucket:        storage.StorageBucketName,
		Key:           key,
		UserScopeID:   pc.userScope.ID,
		UserScopeSlug: pc.userScope.Slug,
		UploadedBy:    pc.claims.Username,
		UploadedAtUtc: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// DownloadUserScopeArtifact returns a presigned download redirect for the artifact.
//
//encore:api auth method=GET path=/api/users/:id/artifacts/download
func (s *Service) DownloadUserScopeArtifact(ctx context.Context, id string, params *UserScopeArtifactDownloadParams) (*UserScopeArtifactDownloadResponse, error) {
	return s.handleUserScopeArtifactDownload(ctx, id, params)
}

func (s *Service) handleUserScopeArtifactDownload(ctx context.Context, id string, params *UserScopeArtifactDownloadParams) (*UserScopeArtifactDownloadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.userContextForUser(user, id)
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
	objectName := artifactObjectName(pc.userScope.ID, key)

	// Prefer MinIO client (path-style) to avoid bucket subdomain DNS issues when
	// using Encore's objects SDK in-cluster.
	var payload []byte
	if c, err := objectStoreClientFor(s.cfg); err == nil && c != nil {
		payload, err = c.GetObject(ctx, artifactsBucketName, objectName)
		if err != nil {
			return nil, errs.B().Code(errs.NotFound).Msg("artifact not found").Err()
		}
	} else {
		storageSvc, err := storage.GetService()
		if err != nil {
			return nil, errs.B().Code(errs.Unavailable).Msg("artifact storage unavailable").Err()
		}
		data, err := storageSvc.Read(ctx, &storage.ReadRequest{ObjectName: objectName})
		if err != nil {
			return nil, errs.B().Code(errs.NotFound).Msg("artifact not found").Err()
		}
		payload = data.Data
	}
	artifactDownloads.Add(1)
	return &UserScopeArtifactDownloadResponse{
		Status:   "ok",
		Bucket:   storage.StorageBucketName,
		Key:      key,
		FileData: base64.StdEncoding.EncodeToString(payload),
	}, nil
}

func artifactObjectName(userScopeID, key string) string {
	userScopeID = strings.TrimSpace(userScopeID)
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if userScopeID == "" {
		return fmt.Sprintf("artifacts/%s", key)
	}
	return fmt.Sprintf("artifacts/%s/%s", userScopeID, key)
}
