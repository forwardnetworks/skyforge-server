package eveapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

type Client struct {
	baseURL       string
	username      string
	password      string
	skipTLSVerify bool
	client        *http.Client
}

type apiResponse[T any] struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    T      `json:"data"`
}

func New(baseURL, username, password string, skipTLSVerify bool) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("api url is required")
	}
	jar, _ := cookiejar.New(nil)
	transport := &http.Transport{}
	if skipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Client{
		baseURL:       baseURL,
		username:      strings.TrimSpace(username),
		password:      strings.TrimSpace(password),
		skipTLSVerify: skipTLSVerify,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Jar:       jar,
			Transport: transport,
		},
	}, nil
}

func (c *Client) Login(ctx context.Context) error {
	payload := map[string]string{
		"username": c.username,
		"password": c.password,
	}
	_, _, err := c.do(ctx, http.MethodPost, "/api/auth/login", payload)
	return err
}

func (c *Client) ListFolder(ctx context.Context, path string) (*FolderListing, error) {
	path = strings.TrimSpace(path)
	endpoint := "/api/folders/"
	if path != "" && path != "/" {
		endpoint = "/api/folders/" + strings.TrimPrefix(path, "/")
	}
	var out apiResponse[FolderListing]
	_, body, err := c.do(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if strings.ToLower(out.Status) != "success" {
		return nil, fmt.Errorf("eve-ng list folder failed: %s", strings.TrimSpace(out.Message))
	}
	return &out.Data, nil
}

func (c *Client) GetLab(ctx context.Context, labPath string) (*LabInfo, error) {
	labPath = strings.Trim(strings.TrimSpace(labPath), "/")
	if labPath == "" {
		return nil, fmt.Errorf("lab path required")
	}
	var out apiResponse[LabInfo]
	_, body, err := c.do(ctx, http.MethodGet, "/api/labs/"+labPath, nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if strings.ToLower(out.Status) != "success" {
		return nil, fmt.Errorf("eve-ng get lab failed: %s", strings.TrimSpace(out.Message))
	}
	return &out.Data, nil
}

func (c *Client) ListNodes(ctx context.Context, labPath string) (map[string]NodeInfo, error) {
	labPath = strings.Trim(strings.TrimSpace(labPath), "/")
	if labPath == "" {
		return nil, fmt.Errorf("lab path required")
	}
	var out apiResponse[map[string]NodeInfo]
	_, body, err := c.do(ctx, http.MethodGet, "/api/labs/"+labPath+"/nodes", nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if strings.ToLower(out.Status) != "success" {
		return nil, fmt.Errorf("eve-ng list nodes failed: %s", strings.TrimSpace(out.Message))
	}
	return out.Data, nil
}

func (c *Client) ListNodeInterfaces(ctx context.Context, labPath string, nodeID int) (*NodeInterfaces, error) {
	labPath = strings.Trim(strings.TrimSpace(labPath), "/")
	if labPath == "" {
		return nil, fmt.Errorf("lab path required")
	}
	var out apiResponse[NodeInterfaces]
	_, body, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/labs/%s/nodes/%d/interfaces", labPath, nodeID), nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if strings.ToLower(out.Status) != "success" {
		return nil, fmt.Errorf("eve-ng list node interfaces failed: %s", strings.TrimSpace(out.Message))
	}
	return &out.Data, nil
}

func (c *Client) ListNetworks(ctx context.Context, labPath string) (*LabNetworks, error) {
	labPath = strings.Trim(strings.TrimSpace(labPath), "/")
	if labPath == "" {
		return nil, fmt.Errorf("lab path required")
	}
	var out apiResponse[LabNetworks]
	_, body, err := c.do(ctx, http.MethodGet, "/api/labs/"+labPath+"/links", nil)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if strings.ToLower(out.Status) != "success" {
		return nil, fmt.Errorf("eve-ng list networks failed: %s", strings.TrimSpace(out.Message))
	}
	return &out.Data, nil
}

func (c *Client) do(ctx context.Context, method, path string, payload any) (*http.Response, []byte, error) {
	if c == nil || c.client == nil {
		return nil, nil, fmt.Errorf("client unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	body := []byte{}
	if payload != nil {
		buf, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		body = buf
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		if loginErr := c.Login(ctx); loginErr == nil {
			return c.do(ctx, method, path, payload)
		}
	}
	return resp, respBody, nil
}

// Data types from EVE-NG API.

type FolderListing struct {
	Folders []FolderEntry `json:"folders"`
	Labs    []LabEntry    `json:"labs"`
}

type FolderEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	MTime string `json:"mtime"`
}

type LabEntry struct {
	File   string `json:"file"`
	Path   string `json:"path"`
	MTime  string `json:"mtime"`
	UMTime int64  `json:"umtime"`
	Shared int    `json:"shared"`
	Lock   bool   `json:"lock"`
}

type LabInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Filename    string `json:"filename"`
	Description string `json:"description"`
	Author      string `json:"author"`
}

type NodeInfo struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Template string `json:"template"`
	Image    string `json:"image"`
	Ethernet int    `json:"ethernet"`
}

type NodeInterfaces struct {
	ID       int                      `json:"id"`
	Sort     string                   `json:"sort"`
	Ethernet map[string]NodeInterface `json:"ethernet"`
}

type NodeInterface struct {
	Name      string `json:"name"`
	NetworkID int    `json:"network_id"`
}

type LabNetworks struct {
	Ethernet map[string]string `json:"ethernet"`
	Serial   []any             `json:"serial"`
}
