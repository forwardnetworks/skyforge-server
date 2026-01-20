package skyforge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
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

const artifactsBucketName = "skyforge-files"

func artifactBasePrefix(workspaceID string) string {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return "artifacts/"
	}
	return fmt.Sprintf("artifacts/%s/", workspaceID)
}

func listArtifactEntries(ctx context.Context, cfg Config, workspaceID, prefix string, limit int) ([]storageObjectSummary, error) {
	// Prefer explicit MinIO listing (path-style) over Encore objects SDK.
	// Encore's S3 driver uses virtual-host addressing which doesn't work in-cluster
	// without wildcard DNS for bucket subdomains.
	if c, err := objectStoreClientFor(cfg); err == nil && c != nil {
		basePrefix := artifactBasePrefix(workspaceID)
		fullPrefix := basePrefix + strings.TrimPrefix(prefix, "/")
		items, err := c.ListObjects(ctx, artifactsBucketName, fullPrefix, limit)
		if err != nil {
			return nil, err
		}
		out := make([]storageObjectSummary, 0, len(items))
		for _, it := range items {
			key := strings.TrimPrefix(it.Key, basePrefix)
			out = append(out, storageObjectSummary{Key: key, Size: it.Size})
		}
		return out, nil
	} else if err != nil {
		log.Printf("object store client unavailable (falling back to encore objects): %v", err)
	}

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
		return nil, err
	}
	return attrs, nil
}

func readWorkspaceArtifact(ctx context.Context, cfg Config, workspaceID, key string, maxBytes int) ([]byte, error) {
	if c, err := objectStoreClientFor(cfg); err == nil && c != nil {
		objectKey := artifactObjectName(workspaceID, key)
		data, err := c.GetObject(ctx, artifactsBucketName, objectKey)
		if err != nil {
			return nil, err
		}
		if maxBytes <= 0 || maxBytes > 10<<20 {
			maxBytes = 2 << 20
		}
		if len(data) > maxBytes {
			data = data[:maxBytes]
		}
		return data, nil
	} else if err != nil {
		log.Printf("object store client unavailable (falling back to encore objects): %v", err)
	}

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

func deleteWorkspaceArtifacts(ctx context.Context, cfg Config, workspaceID string) error {
	if c, err := objectStoreClientFor(cfg); err == nil && c != nil {
		return c.DeletePrefix(ctx, artifactsBucketName, artifactBasePrefix(workspaceID))
	} else if err != nil {
		log.Printf("object store client unavailable (falling back to encore objects): %v", err)
	}

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
