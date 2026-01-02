package skyforge

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

type forwardClient struct {
	baseURL  string
	username string
	password string
	client   *http.Client
}

type forwardNetwork struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type forwardCliCredential struct {
	ID string `json:"id"`
}

type forwardJumpServer struct {
	ID string `json:"id"`
}

type forwardCollector struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type forwardCollectorCreateResponse struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Username         string `json:"username"`
	AuthorizationKey string `json:"authorizationKey"`
}

type forwardCollectorStatus struct {
	IsSet bool `json:"isSet"`
}

type forwardClassicDevice struct {
	Name            string `json:"name"`
	Host            string `json:"host"`
	Port            int    `json:"port,omitempty"`
	CliCredentialID string `json:"cliCredentialId,omitempty"`
	JumpServerID    string `json:"jumpServerId,omitempty"`
}

func normalizeForwardBaseURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("forward base url is required")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u == nil || u.Host == "" {
		return "", fmt.Errorf("invalid forward base url")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func newForwardClient(cfg forwardCredentials) (*forwardClient, error) {
	baseURL, err := normalizeForwardBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	username := strings.TrimSpace(cfg.Username)
	password := strings.TrimSpace(cfg.Password)
	if username == "" || password == "" {
		return nil, fmt.Errorf("forward credentials are required")
	}
	return &forwardClient{
		baseURL:  baseURL,
		username: username,
		password: password,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}, nil
}

func (c *forwardClient) doJSON(ctx context.Context, method, rawPath string, query url.Values, payload any) (*http.Response, []byte, error) {
	if c == nil {
		return nil, nil, fmt.Errorf("forward client not configured")
	}
	endpoint := strings.TrimRight(c.baseURL, "/") + rawPath
	if len(query) > 0 {
		endpoint = endpoint + "?" + query.Encode()
	}
	var body io.Reader
	if payload != nil {
		buf, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.SetBasicAuth(c.username, c.password)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

func forwardCreateNetwork(ctx context.Context, c *forwardClient, name string) (*forwardNetwork, error) {
	query := url.Values{}
	query.Set("name", strings.TrimSpace(name))
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks", query, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forward create network failed: %s", strings.TrimSpace(string(body)))
	}
	var network forwardNetwork
	if err := json.Unmarshal(body, &network); err != nil {
		return nil, err
	}
	if strings.TrimSpace(network.ID) == "" {
		return nil, fmt.Errorf("forward create network returned empty id")
	}
	return &network, nil
}

func forwardListCollectors(ctx context.Context, c *forwardClient) ([]forwardCollector, error) {
	resp, body, err := c.doJSON(ctx, http.MethodGet, "/api/collectors", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forward list collectors failed: %s", strings.TrimSpace(string(body)))
	}
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	collectors := []forwardCollector{}
	switch v := payload.(type) {
	case []any:
		for _, raw := range v {
			buf, _ := json.Marshal(raw)
			var item forwardCollector
			if err := json.Unmarshal(buf, &item); err == nil {
				collectors = append(collectors, item)
			}
		}
	case map[string]any:
		if raw, ok := v["collectors"]; ok {
			buf, _ := json.Marshal(raw)
			_ = json.Unmarshal(buf, &collectors)
		}
	}
	return collectors, nil
}

func forwardCreateCollector(ctx context.Context, c *forwardClient, name string) (*forwardCollectorCreateResponse, error) {
	payload := map[string]string{"collectorName": strings.TrimSpace(name)}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/collectors", nil, payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forward create collector failed: %s", strings.TrimSpace(string(body)))
	}
	var out forwardCollectorCreateResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if strings.TrimSpace(out.ID) == "" || strings.TrimSpace(out.AuthorizationKey) == "" {
		return nil, fmt.Errorf("forward create collector returned empty credentials")
	}
	return &out, nil
}

func forwardGetCollectorStatus(ctx context.Context, c *forwardClient, networkID string) (*forwardCollectorStatus, error) {
	resp, body, err := c.doJSON(ctx, http.MethodGet, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/collector/status", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forward collector status failed: %s", strings.TrimSpace(string(body)))
	}
	var out forwardCollectorStatus
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func forwardSetCollector(ctx context.Context, c *forwardClient, networkID string, collectorUsername string) error {
	payload := map[string]any{
		"username": strings.TrimSpace(collectorUsername),
	}
	resp, body, err := c.doJSON(ctx, http.MethodPut, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/collector", nil, payload)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward set collector failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func forwardStartCollection(ctx context.Context, c *forwardClient, networkID string) error {
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/startcollection", nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward start collection failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func forwardDeleteNetwork(ctx context.Context, c *forwardClient, networkID string) error {
	resp, body, err := c.doJSON(ctx, http.MethodDelete, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID)), nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward delete network failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func forwardCreateCliCredential(ctx context.Context, c *forwardClient, networkID string, username string, password string) (*forwardCliCredential, error) {
	payload := map[string]any{
		"type":          "LOGIN",
		"name":          fmt.Sprintf("Skyforge default (%s)", strings.TrimSpace(username)),
		"username":      strings.TrimSpace(username),
		"password":      strings.TrimSpace(password),
		"autoAssociate": true,
	}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(networkID)+"/cli-credentials", nil, payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forward create cli credential failed: %s", strings.TrimSpace(string(body)))
	}
	var out forwardCliCredential
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if strings.TrimSpace(out.ID) == "" {
		return nil, fmt.Errorf("forward cli credential returned empty id")
	}
	return &out, nil
}

func forwardCreateJumpServer(ctx context.Context, c *forwardClient, networkID string, host string, username string, privateKey string, cert string) (*forwardJumpServer, error) {
	payload := map[string]any{
		"host":                   strings.TrimSpace(host),
		"username":               strings.TrimSpace(username),
		"sshKey":                 strings.TrimSpace(privateKey),
		"supportsPortForwarding": true,
	}
	if cert := strings.TrimSpace(cert); cert != "" {
		payload["sshCert"] = cert
	}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(networkID)+"/jumpServers", nil, payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forward create jump server failed: %s", strings.TrimSpace(string(body)))
	}
	var out forwardJumpServer
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if strings.TrimSpace(out.ID) == "" {
		return nil, fmt.Errorf("forward jump server returned empty id")
	}
	return &out, nil
}

func forwardPutClassicDevices(ctx context.Context, c *forwardClient, networkID string, devices []forwardClassicDevice) error {
	if len(devices) == 0 {
		return nil
	}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(networkID)+"/classic-devices?action=putBatch", nil, devices)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward add devices failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}
