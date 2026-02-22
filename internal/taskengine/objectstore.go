package taskengine

import (
	"context"
	"strings"
	"sync"

	"encore.app/integrations/objectstore"
	"encore.app/internal/skyforgecore"
)

var (
	objectStoreMu     sync.Mutex
	objectStoreClient *objectstore.Client
	objectStoreCfgKey string
)

func objectStoreClientFor(cfg skyforgecore.Config) (*objectstore.Client, error) {
	objectStoreMu.Lock()
	defer objectStoreMu.Unlock()

	key := strings.TrimSpace(cfg.UserScopes.ObjectStorageEndpoint) + "|" +
		strings.TrimSpace(cfg.UserScopes.ObjectStorageAccessKey) + "|" +
		strings.TrimSpace(cfg.UserScopes.ObjectStorageSecretKey)
	if cfg.UserScopes.ObjectStorageUseSSL {
		key += "|ssl"
	} else {
		key += "|plain"
	}
	if objectStoreClient != nil && objectStoreCfgKey == key {
		return objectStoreClient, nil
	}
	client, err := objectstore.New(objectstore.Config{
		Endpoint:  cfg.UserScopes.ObjectStorageEndpoint,
		UseSSL:    cfg.UserScopes.ObjectStorageUseSSL,
		AccessKey: cfg.UserScopes.ObjectStorageAccessKey,
		SecretKey: cfg.UserScopes.ObjectStorageSecretKey,
	})
	if err != nil {
		return nil, err
	}
	objectStoreClient = client
	objectStoreCfgKey = key
	return objectStoreClient, nil
}

func isObjectStoreNotConfigured(err error) bool {
	if err == nil {
		return false
	}
	// Keep this tolerant: different layers wrap the error string.
	return strings.Contains(strings.ToLower(err.Error()), "object storage credentials are not configured")
}

func putTerraformStateObject(ctx context.Context, cfg skyforgecore.Config, bucket, key string, data []byte) error {
	client, err := objectStoreClientFor(cfg)
	if err != nil {
		return err
	}
	return client.PutObject(ctx, bucket, key, data)
}
