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

type UserArtifactUploadRequest struct {
	Key           string `json:"key"`
	ContentBase64 string `json:"contentBase64"`
}

type UserArtifactUploadResponse struct {
	Status        string `json:"status"`
	Bucket        string `json:"bucket"`
	Key           string `json:"key"`
	OwnerUsername string `json:"ownerUsername"`
	ContextSlug   string `json:"contextSlug"`
	UserSlug      string `json:"-"` // legacy internal field
	UploadedBy    string `json:"uploadedBy"`
	UploadedAtUtc string `json:"uploadedAtUtc,omitempty"`
}

type UserArtifactDownloadParams struct {
	Key string `query:"key"`
}

type UserArtifactDownloadResponse struct {
	Status   string `json:"status"`
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	FileData string `json:"fileData"`
}

// UploadUserArtifact uploads or presigns an artifact to the owner bucket.
func (s *Service) UploadUserArtifact(ctx context.Context, id string, req *UserArtifactUploadRequest) (*UserArtifactUploadResponse, error) {
	return s.handleUserArtifactUpload(ctx, id, req)
}

func (s *Service) handleUserArtifactUpload(ctx context.Context, id string, req *UserArtifactUploadRequest) (*UserArtifactUploadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	objectName := artifactObjectName(pc.context.ID, key)

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
			"context.artifact.upload",
			pc.context.ID,
			fmt.Sprintf("bucket=%s key=%s size=%d", storage.StorageBucketName, key, len(payload)),
		)
	}
	return &UserArtifactUploadResponse{
		Status:        "uploaded",
		Bucket:        storage.StorageBucketName,
		Key:           key,
		OwnerUsername: pc.context.ID,
		ContextSlug:   pc.context.Slug,
		UserSlug:      pc.context.Slug,
		UploadedBy:    pc.claims.Username,
		UploadedAtUtc: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// DownloadUserArtifact returns a presigned download redirect for the artifact.
func (s *Service) DownloadUserArtifact(ctx context.Context, id string, params *UserArtifactDownloadParams) (*UserArtifactDownloadResponse, error) {
	return s.handleUserArtifactDownload(ctx, id, params)
}

func (s *Service) handleUserArtifactDownload(ctx context.Context, id string, params *UserArtifactDownloadParams) (*UserArtifactDownloadResponse, error) {
	user, err := requireAuthUser()
	if err != nil {
		return nil, err
	}
	pc, err := s.ownerContextForUser(user, id)
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
	objectName := artifactObjectName(pc.context.ID, key)

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
	return &UserArtifactDownloadResponse{
		Status:   "ok",
		Bucket:   storage.StorageBucketName,
		Key:      key,
		FileData: base64.StdEncoding.EncodeToString(payload),
	}, nil
}

func artifactObjectName(ownerID, key string) string {
	ownerID = strings.TrimSpace(ownerID)
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if ownerID == "" {
		return fmt.Sprintf("artifacts/%s", key)
	}
	return fmt.Sprintf("artifacts/%s/%s", ownerID, key)
}
