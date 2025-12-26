package storage

import (
	"context"
	"encoding/base64"
	"fmt"

	"encore.dev/types/uuid"
)

// WriteFile uploads a file to storage.
//
//encore:api private method=POST path=/storage/upload
func (s *Service) WriteFile(ctx context.Context, params *UploadParams) (*UploadResponse, error) {
	storageUploadRequests.Add(1)
	id, err := uuid.NewV4()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %v", err)
	}

	err = s.Write(ctx, &WriteRequest{
		ObjectName: fmt.Sprintf("files/%s", id),
		Data:       []byte(params.FileData),
	})
	if err != nil {
		storageErrors.Add(1)
		return nil, fmt.Errorf("failed to write file: %v", err)
	}

	return &UploadResponse{
		ID:       id,
		Filename: params.Filename,
	}, nil
}

// ReadFile downloads a file from storage.
//
//encore:api private method=GET path=/storage/download/:id
func (s *Service) ReadFile(ctx context.Context, id uuid.UUID) (*DownloadResponse, error) {
	storageDownloadRequests.Add(1)
	resp, err := s.Read(ctx, &ReadRequest{
		ObjectName: fmt.Sprintf("files/%s", id),
	})
	if err != nil {
		storageErrors.Add(1)
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	storageDownloadBytes.Add(uint64(len(resp.Data)))
	return &DownloadResponse{
		FileData: base64.StdEncoding.EncodeToString(resp.Data),
	}, nil
}

// DeleteFile deletes a file from storage.
//
//encore:api private method=DELETE path=/storage/delete/:id
func (s *Service) DeleteFile(ctx context.Context, id uuid.UUID) error {
	storageDeleteRequests.Add(1)
	err := s.Delete(ctx, &DeleteRequest{
		ObjectName: fmt.Sprintf("files/%s", id),
	})
	if err != nil {
		storageErrors.Add(1)
		return fmt.Errorf("failed to delete file: %v", err)
	}
	return nil
}
