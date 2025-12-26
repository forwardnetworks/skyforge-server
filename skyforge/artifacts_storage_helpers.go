package skyforge

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"encore.dev/storage/objects"

	"encore.app/storage"
)

type artifactsBucketPerms interface {
	objects.Lister
	objects.Remover
	objects.Attrser
}

func artifactsBucket() artifactsBucketPerms {
	return objects.BucketRef[artifactsBucketPerms](storage.StorageFilesBucket)
}

func artifactBasePrefix(projectID string) string {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return "artifacts/"
	}
	return fmt.Sprintf("artifacts/%s/", projectID)
}

func listArtifactEntries(ctx context.Context, projectID, prefix string, limit int) ([]storageObjectSummary, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	basePrefix := artifactBasePrefix(projectID)
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

func artifactAttrs(ctx context.Context, projectID, key string) (*objects.ObjectAttrs, error) {
	objectName := artifactObjectName(projectID, key)
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

func deleteProjectArtifacts(ctx context.Context, projectID string) error {
	prefix := artifactBasePrefix(projectID)
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
