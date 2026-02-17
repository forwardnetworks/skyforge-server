package skyforge

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"encore.dev/beta/errs"
)

type UserArtifactPutObjectRequest struct {
	Key         string `json:"key"`
	ContentB64  string `json:"contentBase64"`
	ContentType string `json:"contentType,omitempty"`
}

type UserArtifactPutObjectResponse struct {
	Status string `json:"status"`
	Key    string `json:"key"`
	Bytes  int    `json:"bytes"`
}

// PutUserArtifactObject writes/overwrites a single artifact object.
//
// This is an object-store-native alternative to the legacy `UploadUserArtifact`
// endpoint (which uses Encore's objects SDK and may require bucket subdomain DNS).
//
//encore:api auth method=POST path=/api/user-contexts/:id/artifacts/object
func (s *Service) PutUserArtifactObject(ctx context.Context, id string, req *UserArtifactPutObjectRequest) (*UserArtifactPutObjectResponse, error) {
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

	key := strings.TrimPrefix(strings.TrimSpace(req.Key), "/")
	if key == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("key is required").Err()
	}
	if strings.TrimSpace(req.ContentB64) == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("contentBase64 is required").Err()
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(req.ContentB64))
	if err != nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid contentBase64").Err()
	}
	contentType := strings.TrimSpace(req.ContentType)
	if contentType == "" {
		// Best-effort default; callers can set a specific type.
		contentType = "application/octet-stream"
	}

	client, err := objectStoreClientFor(s.cfg)
	if err != nil || client == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("object storage credentials are not configured").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	objectKey := artifactObjectName(pc.userContext.ID, key)
	if err := client.PutObjectWithContentType(ctx, artifactsBucketName, objectKey, payload, contentType); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to upload artifact").Err()
	}
	return &UserArtifactPutObjectResponse{
		Status: "ok",
		Key:    key,
		Bytes:  len(payload),
	}, nil
}

type UserArtifactDeleteParams struct {
	Key string `query:"key"`
}

type UserArtifactDeleteResponse struct {
	Status string `json:"status"`
	Key    string `json:"key"`
}

// DeleteUserArtifactObject deletes a single artifact object.
//
//encore:api auth method=DELETE path=/api/user-contexts/:id/artifacts/object
func (s *Service) DeleteUserArtifactObject(ctx context.Context, id string, params *UserArtifactDeleteParams) (*UserArtifactDeleteResponse, error) {
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
	key := ""
	if params != nil {
		key = strings.TrimPrefix(strings.TrimSpace(params.Key), "/")
	}
	if key == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("key is required").Err()
	}

	client, err := objectStoreClientFor(s.cfg)
	if err != nil || client == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("object storage credentials are not configured").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	objectKey := artifactObjectName(pc.userContext.ID, key)
	if err := client.RemoveObject(ctx, artifactsBucketName, objectKey); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to delete artifact").Err()
	}
	return &UserArtifactDeleteResponse{
		Status: "deleted",
		Key:    key,
	}, nil
}

type UserArtifactCreateFolderRequest struct {
	Prefix string `json:"prefix"`
}

type UserArtifactCreateFolderResponse struct {
	Status string `json:"status"`
	Prefix string `json:"prefix"`
}

// CreateUserArtifactFolder creates a "folder" placeholder (zero-byte object with trailing slash).
//
//encore:api auth method=POST path=/api/user-contexts/:id/artifacts/folder
func (s *Service) CreateUserArtifactFolder(ctx context.Context, id string, req *UserArtifactCreateFolderRequest) (*UserArtifactCreateFolderResponse, error) {
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
	prefix := strings.TrimPrefix(strings.TrimSpace(req.Prefix), "/")
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("prefix is required").Err()
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	client, err := objectStoreClientFor(s.cfg)
	if err != nil || client == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("object storage credentials are not configured").Err()
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	objectKey := artifactObjectName(pc.userContext.ID, prefix)
	if err := client.PutObjectWithContentType(ctx, artifactsBucketName, objectKey, []byte{}, "application/x-directory"); err != nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("failed to create folder").Err()
	}
	return &UserArtifactCreateFolderResponse{Status: "ok", Prefix: prefix}, nil
}
