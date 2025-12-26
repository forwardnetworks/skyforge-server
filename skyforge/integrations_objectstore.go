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

	key := cfg.Projects.ObjectStorageEndpoint + "|" + cfg.Projects.ObjectStorageTerraformAccessKey + "|" + cfg.Projects.ObjectStorageTerraformSecretKey
	if cfg.Projects.ObjectStorageUseSSL {
		key += "|ssl"
	} else {
		key += "|plain"
	}
	if objectStoreClient != nil && objectStoreCfgKey == key {
		return objectStoreClient, nil
	}
	client, err := objectstore.New(objectstore.Config{
		Endpoint:  cfg.Projects.ObjectStorageEndpoint,
		UseSSL:    cfg.Projects.ObjectStorageUseSSL,
		AccessKey: cfg.Projects.ObjectStorageTerraformAccessKey,
		SecretKey: cfg.Projects.ObjectStorageTerraformSecretKey,
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
