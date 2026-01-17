package taskengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
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

type forwardSnmpCredential struct {
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
	Name                     string `json:"name"`
	Type                     string `json:"type,omitempty"`
	Host                     string `json:"host"`
	Port                     int    `json:"port,omitempty"`
	CliCredentialID          string `json:"cliCredentialId,omitempty"`
	SnmpCredentialID         string `json:"snmpCredentialId,omitempty"`
	JumpServerID             string `json:"jumpServerId,omitempty"`
	CollectBgpAdvertisements bool   `json:"collectBgpAdvertisements"`
	BgpTableType             string `json:"bgpTableType"`
	BgpPeerType              string `json:"bgpPeerType"`
	EnableSnmpCollection     bool   `json:"enableSnmpCollection"`
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

func forwardSetCollector(ctx context.Context, c *forwardClient, networkID string, collectorUser string) error {
	payload := map[string]string{"collectorUsername": strings.TrimSpace(collectorUser)}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/collector", nil, payload)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward set collector failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func forwardCreateCliCredentialNamed(ctx context.Context, c *forwardClient, networkID string, name string, username string, password string) (*forwardCliCredential, error) {
	payload := map[string]any{
		"name":     strings.TrimSpace(name),
		"username": strings.TrimSpace(username),
		"password": strings.TrimSpace(password),
	}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/cli-credentials", nil, payload)
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
		return nil, fmt.Errorf("forward create cli credential returned empty id")
	}
	return &out, nil
}

func forwardCreateSnmpCredential(ctx context.Context, c *forwardClient, networkID string, name string, community string) (*forwardSnmpCredential, error) {
	payload := map[string]any{
		"name":      strings.TrimSpace(name),
		"community": strings.TrimSpace(community),
	}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/snmp-credentials", nil, payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forward create snmp credential failed: %s", strings.TrimSpace(string(body)))
	}
	var out forwardSnmpCredential
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if strings.TrimSpace(out.ID) == "" {
		return nil, fmt.Errorf("forward create snmp credential returned empty id")
	}
	return &out, nil
}

func forwardCreateJumpServer(ctx context.Context, c *forwardClient, networkID string, host string, username string, privateKey string, cert string) (*forwardJumpServer, error) {
	payload := map[string]any{
		"host":       strings.TrimSpace(host),
		"port":       22,
		"username":   strings.TrimSpace(username),
		"privateKey": strings.TrimSpace(privateKey),
		"certificate": func() string {
			return strings.TrimSpace(cert)
		}(),
	}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/jump-servers", nil, payload)
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
		return nil, fmt.Errorf("forward create jump server returned empty id")
	}
	return &out, nil
}

func forwardPutClassicDevices(ctx context.Context, c *forwardClient, networkID string, devices []forwardClassicDevice) error {
	payload := map[string]any{"devices": devices}
	resp, body, err := c.doJSON(ctx, http.MethodPut, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/classic-devices", nil, payload)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward put classic devices failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func forwardStartCollection(ctx context.Context, c *forwardClient, networkID string) error {
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/collector/start", nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward start collection failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

var forwardNameSanitizer = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

func sanitizeForwardName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "deployment"
	}
	value = forwardNameSanitizer.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		return "deployment"
	}
	for strings.Contains(value, "--") {
		value = strings.ReplaceAll(value, "--", "-")
	}
	return value
}

func forwardCreateNetworkWithRetry(ctx context.Context, client *forwardClient, baseName string) (*forwardNetwork, error) {
	name := strings.TrimSpace(baseName)
	if name == "" {
		name = fmt.Sprintf("deployment-%s", time.Now().UTC().Format("20060102-1504"))
	}
	for attempt := 0; attempt < 3; attempt++ {
		network, err := forwardCreateNetwork(ctx, client, name)
		if err == nil {
			return network, nil
		}
		if !strings.Contains(err.Error(), "already used") {
			return nil, err
		}
		name = fmt.Sprintf("%s-%02d", baseName, attempt+1)
	}
	return nil, fmt.Errorf("forward network name collision after retries")
}

func isForwardJumpServerMissing(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "jump server") && strings.Contains(msg, "not found")
}

func forwardGetCollectorsCached(ctx context.Context, client *forwardClient) ([]forwardCollector, error) {
	collectors, err := forwardListCollectors(ctx, client)
	if err != nil {
		return nil, err
	}
	if len(collectors) == 0 {
		return nil, fmt.Errorf("no forward collectors available")
	}
	return collectors, nil
}

func forwardEnsureCollectorUser(ctx context.Context, client *forwardClient, desired string) (string, error) {
	desired = strings.TrimSpace(desired)
	if desired == "" {
		return "", nil
	}
	collectors, err := forwardGetCollectorsCached(ctx, client)
	if err != nil {
		return "", err
	}
	for _, c := range collectors {
		if strings.EqualFold(strings.TrimSpace(c.Username), desired) {
			return strings.TrimSpace(c.Username), nil
		}
	}
	// Best-effort: create if missing.
	created, err := forwardCreateCollector(ctx, client, desired)
	if err != nil {
		log.Printf("forward create collector failed: %v", err)
		return desired, nil
	}
	return strings.TrimSpace(created.Username), nil
}
