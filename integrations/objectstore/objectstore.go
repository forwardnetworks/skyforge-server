package objectstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	minioCreds "github.com/minio/minio-go/v7/pkg/credentials"
)

type Config struct {
	Endpoint  string
	UseSSL    bool
	AccessKey string
	SecretKey string
	Timeout   time.Duration
}

type Client struct {
	cfg Config
}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.AccessKey) == "" || strings.TrimSpace(cfg.SecretKey) == "" {
		return nil, fmt.Errorf("object storage credentials are not configured")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &Client{cfg: cfg}, nil
}

func (c *Client) minioClient() (*minio.Client, error) {
	endpoint := strings.TrimSpace(c.cfg.Endpoint)
	if endpoint == "" {
		endpoint = "minio:9000"
	}
	return minio.New(endpoint, &minio.Options{
		Creds:  minioCreds.NewStaticV4(strings.TrimSpace(c.cfg.AccessKey), strings.TrimSpace(c.cfg.SecretKey), ""),
		Secure: c.cfg.UseSSL,
	})
}

func (c *Client) DeletePrefix(ctx context.Context, bucket, prefix string) error {
	client, err := c.minioClient()
	if err != nil {
		return err
	}
	opts := minio.ListObjectsOptions{Prefix: prefix, Recursive: true}
	for obj := range client.ListObjects(ctx, bucket, opts) {
		if obj.Err != nil {
			return obj.Err
		}
		if strings.TrimSpace(obj.Key) == "" {
			continue
		}
		if err := client.RemoveObject(ctx, bucket, obj.Key, minio.RemoveObjectOptions{}); err != nil {
			return err
		}
	}
	return nil
}

