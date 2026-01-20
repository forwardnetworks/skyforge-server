package objectstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

type ObjectSummary struct {
	Key  string
	Size int64
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

func (c *Client) ListObjects(ctx context.Context, bucket, prefix string, limit int) ([]ObjectSummary, error) {
	client, err := c.minioClient()
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 200
	}
	opts := minio.ListObjectsOptions{Prefix: prefix, Recursive: true}
	out := make([]ObjectSummary, 0, min(limit, 500))
	for obj := range client.ListObjects(ctx, bucket, opts) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		if strings.TrimSpace(obj.Key) == "" {
			continue
		}
		out = append(out, ObjectSummary{Key: obj.Key, Size: obj.Size})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (c *Client) GetObject(ctx context.Context, bucket, key string) ([]byte, error) {
	client, err := c.minioClient()
	if err != nil {
		return nil, err
	}
	obj, err := client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *Client) RemoveObject(ctx context.Context, bucket, key string) error {
	client, err := c.minioClient()
	if err != nil {
		return err
	}
	bucket = strings.TrimSpace(bucket)
	key = strings.TrimSpace(key)
	if bucket == "" || key == "" {
		return fmt.Errorf("bucket and key are required")
	}
	return client.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{})
}

func (c *Client) PutObject(ctx context.Context, bucket, key string, data []byte) error {
	return c.PutObjectWithContentType(ctx, bucket, key, data, "application/json")
}

func (c *Client) PutObjectWithContentType(ctx context.Context, bucket, key string, data []byte, contentType string) error {
	client, err := c.minioClient()
	if err != nil {
		return err
	}
	if strings.TrimSpace(contentType) == "" {
		contentType = "application/octet-stream"
	}
	reader := bytes.NewReader(data)
	_, err = client.PutObject(ctx, bucket, key, reader, int64(len(data)), minio.PutObjectOptions{
		ContentType: contentType,
	})
	return err
}
