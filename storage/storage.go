package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"encore.dev/rlog"
	"encore.dev/storage/objects"
)

// Define the permissions we need.
type StoragePerms interface {
	objects.ReadWriter
}

// Service handles file storage operations.
//
//encore:service
type Service struct {
	bucket objects.ReadWriter
}

var (
	initOnce sync.Once
	instance *Service
	initErr  error

	StorageBucketName  = "skyforge"
	StorageFilesBucket = newBucket("skyforge", objects.BucketConfig{
		Versioned: false,
	})
)

func newBucket(name string, cfg objects.BucketConfig) *objects.Bucket {
	// In plain `go test` the Encore SDK stubs panic. Avoid that by returning nil.
	if os.Getenv("ENCORE_CFG") == "" {
		return nil
	}
	return objects.NewBucket(name, cfg)
}

// initService initializes the Storage service.
func initService() (*Service, error) {
	rlog.Info("initializing storage service")
	if StorageFilesBucket == nil {
		return nil, errors.New("storage service requires Encore runtime")
	}
	service := &Service{
		bucket: objects.BucketRef[StoragePerms](StorageFilesBucket),
	}
	return service, nil
}

// GetService returns the singleton instance.
func GetService() (interface {
	Write(ctx context.Context, req *WriteRequest) error
	Read(ctx context.Context, req *ReadRequest) (*ReadResponse, error)
	Delete(ctx context.Context, req *DeleteRequest) error
	List(ctx context.Context) (*ListResponse, error)
}, error) {
	initOnce.Do(func() {
		instance, initErr = initService()
	})
	return instance, initErr
}

// WriteRequest represents the parameters for writing data.
type WriteRequest struct {
	ObjectName string `json:"objectName"`
	Data       []byte `json:"data"`
}

// ReadRequest represents the parameters for reading data.
type ReadRequest struct {
	ObjectName string `json:"objectName"`
}

// ReadResponse represents the response from reading data.
type ReadResponse struct {
	Data []byte `json:"data"`
}

// DeleteRequest represents the parameters for deleting data.
type DeleteRequest struct {
	ObjectName string `json:"objectName"`
}

// ListResponse represents the response from listing objects.
type ListResponse struct {
	Files []string `json:"files"`
}

// Write stores data in the bucket.
//
//encore:api private
func (s *Service) Write(ctx context.Context, req *WriteRequest) error {
	storageUploadBytes.Add(uint64(len(req.Data)))
	writer := s.bucket.Upload(ctx, req.ObjectName)
	if _, err := writer.Write(req.Data); err != nil {
		return err
	}
	return writer.Close()
}

// Read retrieves data from the bucket.
//
//encore:api private
func (s *Service) Read(ctx context.Context, req *ReadRequest) (*ReadResponse, error) {
	reader := s.bucket.Download(ctx, req.ObjectName)
	if reader == nil {
		return nil, fmt.Errorf("failed to read object")
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return &ReadResponse{Data: data}, nil
}

// Delete removes an object from the bucket.
//
//encore:api private
func (s *Service) Delete(ctx context.Context, req *DeleteRequest) error {
	return s.bucket.Remove(ctx, req.ObjectName)
}

// List returns all objects in the bucket.
//
//encore:api private
func (s *Service) List(ctx context.Context) (*ListResponse, error) {
	var files []string
	for entry := range s.bucket.List(ctx, &objects.Query{}) {
		files = append(files, entry.Name)
	}
	return &ListResponse{Files: files}, nil
}
