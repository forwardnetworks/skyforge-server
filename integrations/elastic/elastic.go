package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL     string
	indexPrefix string
	httpClient  *http.Client
}

func New(baseURL, indexPrefix string) (*Client, error) {
	baseURL = strings.TrimSpace(baseURL)
	indexPrefix = strings.TrimSpace(indexPrefix)
	if baseURL == "" {
		return nil, fmt.Errorf("elastic baseURL is required")
	}
	if indexPrefix == "" {
		indexPrefix = "skyforge"
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid elastic baseURL: %q", baseURL)
	}
	return &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		indexPrefix: indexPrefix,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

func (c *Client) IndexDaily(ctx context.Context, category string, ts time.Time, doc any) error {
	category = strings.TrimSpace(category)
	if category == "" {
		return fmt.Errorf("elastic category is required")
	}
	ts = ts.UTC()
	index := fmt.Sprintf("%s-%s-%04d.%02d.%02d", c.indexPrefix, category, ts.Year(), ts.Month(), ts.Day())
	return c.IndexDoc(ctx, index, doc)
}

func (c *Client) IndexDoc(ctx context.Context, index string, doc any) error {
	index = strings.TrimSpace(index)
	if index == "" {
		return fmt.Errorf("elastic index is required")
	}

	body, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("elastic marshal doc: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/"+url.PathEscape(index)+"/_doc", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("elastic request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("elastic request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
		return nil
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	msg := strings.TrimSpace(string(respBody))
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("elastic index failed: %s", msg)
}
