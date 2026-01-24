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

type forwardConnectivityBulkStartRequest struct {
	Devices []string `json:"devices"`
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

func forwardBulkStartConnectivityTests(ctx context.Context, c *forwardClient, networkID string, devices []string) error {
	if len(devices) == 0 {
		return nil
	}
	payload := forwardConnectivityBulkStartRequest{Devices: devices}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/connectivityTests/bulkStart", nil, payload)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward connectivity bulkStart failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
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
	// Forward expects:
	//   PUT /api/networks/{networkId}/collector
	//   {"username":"collector-xxxx"}
	payload := map[string]any{
		"username": strings.TrimSpace(collectorUser),
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

func forwardCreateSnmpCredential(ctx context.Context, c *forwardClient, networkID string, community string) (*forwardSnmpCredential, error) {
	payload := map[string]any{
		"name":            strings.TrimSpace(community),
		"autoAssociate":   true,
		"version":         "V2C",
		"communityString": strings.TrimSpace(community),
	}

	// Forward has used multiple endpoint spellings over time. Our environment uses:
	//   POST /api/networks/{id}/snmpCredentials
	// Keep a fallback to the legacy path to avoid regressions if the API differs.
	paths := []string{
		"/api/networks/" + url.PathEscape(strings.TrimSpace(networkID)) + "/snmpCredentials",
		"/api/networks/" + url.PathEscape(strings.TrimSpace(networkID)) + "/snmp-credentials",
	}

	var (
		resp *http.Response
		body []byte
		err  error
	)
	for _, p := range paths {
		resp, body, err = c.doJSON(ctx, http.MethodPost, p, nil, payload)
		if err != nil {
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			break
		}
	}
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
	if len(devices) == 0 {
		return nil
	}

	// Forward expects:
	//   POST /api/networks/{networkId}/classic-devices?action=putBatch
	// with a JSON array payload (not wrapped).
	query := url.Values{}
	query.Set("action", "putBatch")
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/classic-devices", query, devices)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Backward-compat: older Forward versions may accept PUT with wrapped payload.
		fallbackPayload := map[string]any{"devices": devices}
		resp2, body2, err2 := c.doJSON(ctx, http.MethodPut, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/classic-devices", nil, fallbackPayload)
		if err2 != nil {
			return err
		}
		if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
			if strings.TrimSpace(string(body)) != "" {
				return fmt.Errorf("forward put classic devices failed: %s", strings.TrimSpace(string(body)))
			}
			return fmt.Errorf("forward put classic devices failed: %s", strings.TrimSpace(string(body2)))
		}
	}
	return nil
}

func forwardStartCollection(ctx context.Context, c *forwardClient, networkID string) error {
	// Prefer the public Forward API path.
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/startcollection", nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// Backward-compat: try the legacy collector/start path.
	resp2, body2, err2 := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/collector/start", nil, nil)
	if err2 != nil {
		return fmt.Errorf("forward start collection failed: %s", strings.TrimSpace(string(body)))
	}
	if resp2.StatusCode < 200 || resp2.StatusCode >= 300 {
		if strings.TrimSpace(string(body)) != "" {
			return fmt.Errorf("forward start collection failed: %s", strings.TrimSpace(string(body)))
		}
		return fmt.Errorf("forward start collection failed: %s", strings.TrimSpace(string(body2)))
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
	name := sanitizeForwardName(strings.TrimSpace(baseName))
	if name == "" {
		name = "deployment"
	}
	if len(name) > 80 {
		name = strings.TrimRight(name[:80], "-")
	}

	for attempt := 0; attempt < 4; attempt++ {
		tryName := name
		if attempt > 0 {
			suffix := time.Now().UTC().Format("1504")
			if attempt > 1 {
				suffix = fmt.Sprintf("%s-%02d", suffix, attempt-1)
			}
			tryName = sanitizeForwardName(fmt.Sprintf("%s-%s", name, suffix))
			if len(tryName) > 80 {
				tryName = strings.TrimRight(tryName[:80], "-")
			}
		}

		network, err := forwardCreateNetwork(ctx, client, tryName)
		if err == nil {
			return network, nil
		}
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "already used") && !strings.Contains(msg, "already exists") && !strings.Contains(msg, "duplicate") {
			return nil, err
		}
	}
	return nil, fmt.Errorf("forward network name collision after retries")
}

type forwardEndpoint struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	Protocol     string `json:"protocol"`
	CredentialID string `json:"credentialId,omitempty"`
	Collect      *bool  `json:"collect,omitempty"`
}

func forwardPutEndpointsBatch(ctx context.Context, c *forwardClient, networkID string, endpoints []forwardEndpoint) error {
	if len(endpoints) == 0 {
		return nil
	}
	query := url.Values{}
	query.Set("action", "addBatch")
	query.Set("type", "CLI")
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/endpoints", query, endpoints)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward put endpoints failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
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
