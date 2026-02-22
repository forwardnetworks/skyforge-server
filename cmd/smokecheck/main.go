package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type workspaceCreateRequest struct {
	Name      string `json:"name"`
	Blueprint string `json:"blueprint,omitempty"`
}

type workspaceResponse struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func mustEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return ""
	}
	return v
}

func loadSmokePasswordFromSecretsFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	secrets, _ := doc["secrets"].(map[string]any)
	items, _ := secrets["items"].(map[string]any)
	entry, _ := items["skyforge-admin-shared"].(map[string]any)
	password, _ := entry["password"].(string)
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("skyforge-admin-shared.password not set")
	}
	return password, nil
}

func doJSON(client *http.Client, method, url string, body any, headers map[string]string) (*http.Response, []byte, error) {
	var r io.Reader
	if body != nil {
		enc, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		r = bytes.NewReader(enc)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b, nil
}

func main() {
	baseURL := strings.TrimRight(getenv("SKYFORGE_BASE_URL", "https://skyforge.local.forwardnetworks.com"), "/")
	username := getenv("SKYFORGE_SMOKE_USERNAME", "skyforge")
	password := mustEnv("SKYFORGE_SMOKE_PASSWORD")
	if password == "" {
		// Convenience: use local deploy secrets file (keeps the password out of shell history).
		secretsPath := strings.TrimSpace(getenv("SKYFORGE_SECRETS_FILE", "../deploy/skyforge-secrets.yaml"))
		abs, _ := filepath.Abs(secretsPath)
		loaded, err := loadSmokePasswordFromSecretsFile(abs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "missing SKYFORGE_SMOKE_PASSWORD and failed to load from %s: %v\n", abs, err)
			os.Exit(2)
		}
		password = loaded
	}

	timeout := 20 * time.Second
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // intended for internal/self-signed lab env
	}
	client := &http.Client{Timeout: timeout, Transport: tr}

	healthURL := baseURL + "/api/skyforge/api/health"
	resp, body, err := doJSON(client, http.MethodGet, healthURL, nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "health request failed: %v\n", err)
		os.Exit(1)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "health failed: %s\n", strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	fmt.Printf("OK health: %s\n", healthURL)

	loginURL := baseURL + "/api/skyforge/api/login"
	resp, body, err = doJSON(client, http.MethodPost, loginURL, loginRequest{Username: username, Password: password}, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "login request failed: %v\n", err)
		os.Exit(1)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "login failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	setCookie := resp.Header.Get("Set-Cookie")
	if strings.TrimSpace(setCookie) == "" {
		fmt.Fprintln(os.Stderr, "login missing Set-Cookie header")
		os.Exit(1)
	}
	fmt.Printf("OK login: %s\n", username)

	wsName := fmt.Sprintf("smoke-%s", time.Now().UTC().Format("20060102-150405"))
	createURL := baseURL + "/api/skyforge/api/users"
	resp, body, err = doJSON(client, http.MethodPost, createURL, workspaceCreateRequest{Name: wsName}, map[string]string{
		"Cookie": setCookie,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "workspace create request failed: %v\n", err)
		os.Exit(1)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "workspace create failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	var ws workspaceResponse
	if err := json.Unmarshal(body, &ws); err != nil {
		fmt.Fprintf(os.Stderr, "workspace create parse failed: %v\n", err)
		os.Exit(1)
	}
	if strings.TrimSpace(ws.ID) == "" {
		fmt.Fprintf(os.Stderr, "workspace create returned empty id: %s\n", strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	fmt.Printf("OK workspace create: %s (%s)\n", ws.Name, ws.ID)

	deleteURL := baseURL + "/api/skyforge/api/users/" + ws.ID + "?confirm=" + ws.Slug
	resp, body, err = doJSON(client, http.MethodDelete, deleteURL, nil, map[string]string{
		"Cookie": setCookie,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "workspace delete request failed: %v\n", err)
		os.Exit(1)
	}
	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("OK workspace delete (already gone): %s\n", ws.ID)
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "workspace delete failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	if len(body) > 0 && !bytes.Equal(bytes.TrimSpace(body), []byte(`{}`)) {
		// Some endpoints return an empty JSON response; tolerate either.
		var okAny map[string]any
		if err := json.Unmarshal(body, &okAny); err != nil {
			fmt.Fprintf(os.Stderr, "workspace delete returned unexpected body: %s\n", strings.TrimSpace(string(body)))
			os.Exit(1)
		}
	}
	fmt.Printf("OK workspace delete: %s\n", ws.ID)
}
