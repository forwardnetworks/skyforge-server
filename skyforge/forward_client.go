package skyforge

import (
	"bytes"
	"context"
	"crypto/tls"
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

type forwardSnmpV3Profile struct {
	Username        string
	AuthType        string
	AuthPassword    string
	PrivacyProtocol string
	PrivacyPassword string
}

type forwardJumpServer struct {
	ID string `json:"id"`
}

type forwardCollector struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	Status          string `json:"status,omitempty"`
	Connected       bool   `json:"connected,omitempty"`
	LastConnectedAt int64  `json:"lastConnectedAt,omitempty"`
	UpdatedAt       int64  `json:"updatedAt,omitempty"`
	// Newer Forward payload fields (preferred over Status/Connected).
	ConnectionStatus  string   `json:"connectionStatus,omitempty"`
	Version           string   `json:"version,omitempty"`
	UpdateStatus      string   `json:"updateStatus,omitempty"`
	CollectorUpdating bool     `json:"collectorUpdating,omitempty"`
	ExternalIP        string   `json:"externalIp,omitempty"`
	InternalIPs       []string `json:"internalIps,omitempty"`
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

type forwardEndpoint struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port,omitempty"`
	Protocol     string `json:"protocol"`
	CredentialID string `json:"credentialId,omitempty"`
	ProfileID    string `json:"profileId,omitempty"`
	JumpServerID string `json:"jumpServerId,omitempty"`
	FullCollect  bool   `json:"fullCollectionLog,omitempty"`
	LargeRTT     bool   `json:"largeRtt,omitempty"`
	Collect      bool   `json:"collect,omitempty"`
	Note         string `json:"note,omitempty"`
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

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Do not use environment proxy variables for Forward traffic; these often
	// break in-cluster egress and cause confusing 503s in the UI.
	transport.Proxy = func(*http.Request) (*url.URL, error) { return nil, nil }
	if cfg.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &forwardClient{
		baseURL:  baseURL,
		username: username,
		password: password,
		client: &http.Client{
			Timeout:   60 * time.Second,
			Transport: transport,
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

type forwardEndpointProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func forwardEnsureEndpointProfile(ctx context.Context, c *forwardClient, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("endpoint profile name is required")
	}
	query := url.Values{}
	query.Set("type", "CLI")
	resp, body, err := c.doJSON(ctx, http.MethodGet, "/api/endpoint-profiles", query, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var profiles []forwardEndpointProfile
		if err := json.Unmarshal(body, &profiles); err == nil {
			for _, profile := range profiles {
				if strings.EqualFold(profile.Name, name) && strings.TrimSpace(profile.ID) != "" {
					return strings.TrimSpace(profile.ID), nil
				}
			}
		}
	}
	payload := map[string]any{
		"name":           name,
		"type":           "CLI",
		"customCommands": []string{},
		"commandSets":    []string{"UNIX"},
	}
	resp, body, err = c.doJSON(ctx, http.MethodPost, "/api/endpoint-profiles", query, payload)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("forward create endpoint profile failed: %s", strings.TrimSpace(string(body)))
	}
	var profile forwardEndpointProfile
	if err := json.Unmarshal(body, &profile); err != nil {
		return "", err
	}
	if strings.TrimSpace(profile.ID) == "" {
		return "", fmt.Errorf("forward endpoint profile returned empty id")
	}
	return strings.TrimSpace(profile.ID), nil
}

func forwardPutEndpoints(ctx context.Context, c *forwardClient, networkID string, endpoints []forwardEndpoint) error {
	if strings.TrimSpace(networkID) == "" {
		return fmt.Errorf("forward network id is required")
	}
	if len(endpoints) == 0 {
		return nil
	}
	query := url.Values{}
	query.Set("action", "addBatch")
	query.Set("type", "CLI")
	path := fmt.Sprintf("/api/networks/%s/endpoints", url.PathEscape(strings.TrimSpace(networkID)))
	resp, body, err := c.doJSON(ctx, http.MethodPost, path, query, endpoints)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward put endpoints failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func forwardListCollectors(ctx context.Context, c *forwardClient) ([]forwardCollector, error) {
	resp, body, err := c.doJSON(ctx, http.MethodGet, "/api/collectors", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forward list collectors failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
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
		for _, key := range []string{"collectors", "items", "data"} {
			if raw, ok := v[key]; ok {
				buf, _ := json.Marshal(raw)
				_ = json.Unmarshal(buf, &collectors)
				if len(collectors) > 0 {
					break
				}
			}
		}
	}
	return collectors, nil
}

func forwardGetCollector(ctx context.Context, c *forwardClient, collectorIDOrName string) (map[string]any, error) {
	collectorIDOrName = strings.TrimSpace(collectorIDOrName)
	if collectorIDOrName == "" {
		return nil, fmt.Errorf("collector id is required")
	}
	resp, body, err := c.doJSON(ctx, http.MethodGet, "/api/collectors/"+url.PathEscape(collectorIDOrName), nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forward get collector failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func forwardCreateCollector(ctx context.Context, c *forwardClient, name string) (*forwardCollectorCreateResponse, error) {
	payload := map[string]string{"collectorName": strings.TrimSpace(name)}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/collectors", nil, payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("forward create collector failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
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

func forwardDeleteCollector(ctx context.Context, c *forwardClient, collectorIDOrName string) error {
	collectorIDOrName = strings.TrimSpace(collectorIDOrName)
	if collectorIDOrName == "" {
		return nil
	}
	resp, body, err := c.doJSON(ctx, http.MethodDelete, "/api/collectors/"+url.PathEscape(collectorIDOrName), nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward delete collector failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
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
	// Ensure Forward global performance collection is enabled for this network.
	// This drives SNMP/perf ingestion required by Capacity analytics.
	if err := forwardEnablePerformanceCollection(ctx, c, networkID); err != nil {
		return err
	}

	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/startcollection", nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward start collection failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func forwardEnablePerformanceCollection(ctx context.Context, c *forwardClient, networkID string) error {
	networkID = strings.TrimSpace(networkID)
	if networkID == "" {
		return fmt.Errorf("forward network id is required")
	}
	path := "/api/networks/" + url.PathEscape(networkID) + "/performance/settings"
	payload := map[string]any{"enabled": true}

	resp, body, err := c.doJSON(ctx, http.MethodPatch, path, nil, payload)
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("forward enable performance failed: %s", strings.TrimSpace(string(body)))
}

func forwardDeleteNetwork(ctx context.Context, c *forwardClient, networkID string) error {
	resp, body, err := c.doJSON(ctx, http.MethodDelete, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID)), nil, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward delete network failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func forwardCreateCliCredential(ctx context.Context, c *forwardClient, networkID string, username string, password string) (*forwardCliCredential, error) {
	return forwardCreateCliCredentialNamed(ctx, c, networkID, "", username, password)
}

func forwardCreateCliCredentialNamed(ctx context.Context, c *forwardClient, networkID string, name string, username string, password string) (*forwardCliCredential, error) {
	credentialName := strings.TrimSpace(name)
	if credentialName == "" {
		credentialName = fmt.Sprintf("Skyforge default (%s) %d", strings.TrimSpace(username), time.Now().UTC().UnixNano())
	}
	payload := map[string]any{
		"type":          "LOGIN",
		"name":          credentialName,
		"username":      strings.TrimSpace(username),
		"password":      strings.TrimSpace(password),
		"autoAssociate": true,
	}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(networkID)+"/cli-credentials", nil, payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyText := strings.TrimSpace(string(body))
		if id := parseForwardCredentialID(bodyText); id != "" {
			return &forwardCliCredential{ID: id}, nil
		}
		return nil, fmt.Errorf("forward create cli credential failed: %s", bodyText)
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

func parseForwardCredentialID(body string) string {
	if body == "" {
		return ""
	}
	if match := regexp.MustCompile(`credential\s+(L-\d+)`).FindStringSubmatch(body); len(match) > 1 {
		return match[1]
	}
	return ""
}

func forwardCreateSnmpCredential(ctx context.Context, c *forwardClient, networkID string, name string, profile forwardSnmpV3Profile) (*forwardSnmpCredential, error) {
	credentialName := strings.TrimSpace(name)
	if credentialName == "" {
		credentialName = fmt.Sprintf("Skyforge SNMPv3 %d", time.Now().UTC().UnixNano())
	}
	if strings.TrimSpace(profile.Username) == "" || strings.TrimSpace(profile.AuthPassword) == "" || strings.TrimSpace(profile.PrivacyPassword) == "" {
		return nil, fmt.Errorf("forward snmpv3 profile is required")
	}
	payload := map[string]any{
		"name":          credentialName,
		"version":       "V3",
		"autoAssociate": true,
		"authSettings": map[string]any{
			"username":        strings.TrimSpace(profile.Username),
			"authType":        strings.TrimSpace(profile.AuthType),
			"password":        strings.TrimSpace(profile.AuthPassword),
			"privacyProtocol": strings.TrimSpace(profile.PrivacyProtocol),
			"privacyPassword": strings.TrimSpace(profile.PrivacyPassword),
		},
	}
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(strings.TrimSpace(networkID))+"/snmpCredentials", nil, payload)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyText := strings.TrimSpace(string(body))
		if id := parseForwardSnmpCredentialID(bodyText); id != "" {
			return &forwardSnmpCredential{ID: id}, nil
		}
		return nil, fmt.Errorf("forward create snmp credential failed: %s", bodyText)
	}
	var out forwardSnmpCredential
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if strings.TrimSpace(out.ID) == "" {
		return nil, fmt.Errorf("forward snmp credential returned empty id")
	}
	return &out, nil
}

func parseForwardSnmpCredentialID(body string) string {
	if body == "" {
		return ""
	}
	if match := regexp.MustCompile(`\b(S-\d+)\b`).FindStringSubmatch(body); len(match) > 1 {
		return match[1]
	}
	return ""
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
	payload, err := json.Marshal(devices)
	if err != nil {
		return fmt.Errorf("forward add devices marshal failed: %w", err)
	}
	log.Printf("forward add devices putBatch network=%s payload=%s", networkID, string(payload))
	resp, body, err := c.doJSON(ctx, http.MethodPost, "/api/networks/"+url.PathEscape(networkID)+"/classic-devices?action=putBatch", nil, devices)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("forward add devices failed: %s", strings.TrimSpace(string(body)))
	}
	return nil
}
