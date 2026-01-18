package skyforge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"encore.dev/storage/objects"

	"encore.app/storage"
)

type artifactsBucketPerms interface {
	objects.Lister
	objects.Remover
	objects.Attrser
	objects.Downloader
}

func artifactsBucket() artifactsBucketPerms {
	return objects.BucketRef[artifactsBucketPerms](storage.StorageFilesBucket)
}

func artifactBasePrefix(workspaceID string) string {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return "artifacts/"
	}
	return fmt.Sprintf("artifacts/%s/", workspaceID)
}

func listArtifactEntries(ctx context.Context, workspaceID, prefix string, limit int) ([]storageObjectSummary, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	basePrefix := artifactBasePrefix(workspaceID)
	fullPrefix := basePrefix + strings.TrimPrefix(prefix, "/")
	query := &objects.Query{
		Prefix: fullPrefix,
		Limit:  int64(limit),
	}
	bucket := artifactsBucket()
	items := make([]storageObjectSummary, 0, limit)
	for entry, err := range bucket.List(ctx, query) {
		if err != nil {
			return nil, err
		}
		key := strings.TrimPrefix(entry.Name, basePrefix)
		items = append(items, storageObjectSummary{
			Key:  key,
			Size: entry.Size,
		})
	}
	return items, nil
}

func artifactAttrs(ctx context.Context, workspaceID, key string) (*objects.ObjectAttrs, error) {
	objectName := artifactObjectName(workspaceID, key)
	bucket := artifactsBucket()
	attrs, err := bucket.Attrs(ctx, objectName)
	if err != nil {
		if errors.Is(err, objects.ErrObjectNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return attrs, nil
}

func readWorkspaceArtifact(ctx context.Context, workspaceID, key string, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > 10<<20 {
		maxBytes = 2 << 20
	}
	objectName := artifactObjectName(workspaceID, key)
	bucket := artifactsBucket()
	r := bucket.Download(ctx, objectName)
	if r == nil {
		return nil, nil
	}
	defer r.Close()
	data, _ := io.ReadAll(io.LimitReader(r, int64(maxBytes)))
	if err := r.Err(); err != nil {
		if errors.Is(err, objects.ErrObjectNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return data, nil
}

func deleteWorkspaceArtifacts(ctx context.Context, workspaceID string) error {
	prefix := artifactBasePrefix(workspaceID)
	query := &objects.Query{Prefix: prefix}
	bucket := artifactsBucket()
	for entry, err := range bucket.List(ctx, query) {
		if err != nil {
			return err
		}
		if err := bucket.Remove(ctx, entry.Name); err != nil {
			return err
		}
	}
	return nil
}
