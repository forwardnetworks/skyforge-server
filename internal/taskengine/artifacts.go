package taskengine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/skyforgecore"
	"encore.app/internal/taskstore"
)

// Keep artifacts in the same bucket as general Skyforge file storage.
// The MinIO bootstrap creates `skyforge-files` and enables access.
const skyforgeArtifactsBucket = "skyforge-files"

func artifactObjectNameForScope(ownerID, key string) string {
	ownerID = strings.TrimSpace(ownerID)
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if ownerID == "" {
		return fmt.Sprintf("artifacts/%s", key)
	}
	return fmt.Sprintf("artifacts/%s/%s", ownerID, key)
}

func putUserArtifact(ctx context.Context, cfg skyforgecore.Config, ownerID, key string, data []byte, contentType string) (string, error) {
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if key == "" {
		return "", fmt.Errorf("artifact key is required")
	}
	obj := artifactObjectNameForScope(ownerID, key)
	client, err := objectStoreClientFor(cfg)
	if err != nil {
		return "", err
	}
	if err := client.PutObjectWithContentType(ctx, skyforgeArtifactsBucket, obj, data, contentType); err != nil {
		return "", err
	}
	return key, nil
}

func readUserArtifact(ctx context.Context, cfg skyforgecore.Config, ownerID, key string, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > 10<<20 {
		maxBytes = 2 << 20
	}
	key = strings.TrimPrefix(strings.TrimSpace(key), "/")
	if key == "" {
		return nil, fmt.Errorf("artifact key is required")
	}
	obj := artifactObjectNameForScope(ownerID, key)
	client, err := objectStoreClientFor(cfg)
	if err != nil {
		return nil, err
	}
	data, err := client.GetObject(ctx, skyforgeArtifactsBucket, obj)
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("artifact too large")
	}
	return data, nil
}

func (e *Engine) setTaskMetadataKey(taskID int, k string, v any) {
	if e == nil || e.db == nil || taskID <= 0 {
		return
	}
	k = strings.TrimSpace(k)
	if k == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rec, err := taskstore.GetTask(ctx, e.db, taskID)
	if err != nil || rec == nil {
		return
	}
	meta, _ := fromJSONMap(rec.Metadata)
	if meta == nil {
		meta = map[string]any{}
	}
	meta[k] = v
	if metaJSON, err := toJSONMap(meta); err == nil {
		_ = taskstore.UpdateTaskMetadata(ctx, e.db, taskID, metaJSON)
	}
}
