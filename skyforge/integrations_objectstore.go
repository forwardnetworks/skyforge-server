package skyforge

import (
	"context"
	"sync"

	"encore.app/integrations/objectstore"
)

var (
	objectStoreMu     sync.Mutex
	objectStoreClient *objectstore.Client
	objectStoreCfgKey string
)

func objectStoreClientFor(cfg Config) (*objectstore.Client, error) {
	objectStoreMu.Lock()
	defer objectStoreMu.Unlock()

	key := cfg.UserScopes.ObjectStorageEndpoint + "|" + cfg.UserScopes.ObjectStorageAccessKey + "|" + cfg.UserScopes.ObjectStorageSecretKey
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

func deleteTerraformStatePrefix(ctx context.Context, cfg Config, bucket, prefix string) error {
	client, err := objectStoreClientFor(cfg)
	if err != nil {
		return err
	}
	return client.DeletePrefix(ctx, bucket, prefix)
}

func getTerraformStateObject(ctx context.Context, cfg Config, bucket, key string) ([]byte, error) {
	client, err := objectStoreClientFor(cfg)
	if err != nil {
		return nil, err
	}
	return client.GetObject(ctx, bucket, key)
}

func putTerraformStateObject(ctx context.Context, cfg Config, bucket, key string, data []byte) error {
	client, err := objectStoreClientFor(cfg)
	if err != nil {
		return err
	}
	return client.PutObject(ctx, bucket, key, data)
}
