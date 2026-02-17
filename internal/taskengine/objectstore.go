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

	key := strings.TrimSpace(cfg.UserContexts.ObjectStorageEndpoint) + "|" +
		strings.TrimSpace(cfg.UserContexts.ObjectStorageAccessKey) + "|" +
		strings.TrimSpace(cfg.UserContexts.ObjectStorageSecretKey)
	if cfg.UserContexts.ObjectStorageUseSSL {
		key += "|ssl"
	} else {
		key += "|plain"
	}
	if objectStoreClient != nil && objectStoreCfgKey == key {
		return objectStoreClient, nil
	}
	client, err := objectstore.New(objectstore.Config{
		Endpoint:  cfg.UserContexts.ObjectStorageEndpoint,
		UseSSL:    cfg.UserContexts.ObjectStorageUseSSL,
		AccessKey: cfg.UserContexts.ObjectStorageAccessKey,
		SecretKey: cfg.UserContexts.ObjectStorageSecretKey,
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
