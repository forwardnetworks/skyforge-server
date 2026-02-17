package skyforge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type containerlabJWTClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type containerlabDeployRequest struct {
	TopologyContent map[string]any `json:"topologyContent,omitempty"`
	TopologySource  string         `json:"topologySourceUrl,omitempty"`
}

func containerlabLabName(ownerSlug, deploymentName string) string {
	ownerSlug = strings.TrimSpace(ownerSlug)
	deploymentName = strings.TrimSpace(deploymentName)
	if ownerSlug == "" {
		return deploymentName
	}
	if deploymentName == "" {
		return ownerSlug
	}
	return fmt.Sprintf("%s-%s", ownerSlug, deploymentName)
}

func containerlabTokenForUser(cfg Config, username string) (string, error) {
	secret := strings.TrimSpace(cfg.ContainerlabJWTSecret)
	if secret == "" {
		return "", fmt.Errorf("containerlab jwt secret is not configured")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	now := time.Now()
	claims := containerlabJWTClaims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}
	return signed, nil
}

func containerlabAPIURL(cfg Config, server NetlabServerConfig) string {
	if raw := strings.TrimRight(strings.TrimSpace(server.ContainerlabAPIURL), "/"); raw != "" {
		return raw
	}
	apiPath := strings.TrimSpace(cfg.ContainerlabAPIPath)
	if apiPath == "" {
		apiPath = "/containerlab"
	}
	if !strings.HasPrefix(apiPath, "/") {
		apiPath = "/" + apiPath
	}
	host := strings.TrimSpace(server.SSHHost)
	if host == "" {
		return ""
	}
	return strings.TrimRight(fmt.Sprintf("https://%s%s", host, apiPath), "/")
}

func containerlabSkipTLS(cfg Config, server NetlabServerConfig) bool {
	if server.ContainerlabSkipTLSVerify {
		return true
	}
	return cfg.ContainerlabSkipTLSVerify
}

func containerlabAPIDo(ctx context.Context, url string, token string, payload any, skipTLS bool) (*http.Response, []byte, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

func containerlabAPIGet(ctx context.Context, url string, token string, skipTLS bool) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}

func containerlabAPIDelete(ctx context.Context, url string, token string, skipTLS bool) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data, nil
}
