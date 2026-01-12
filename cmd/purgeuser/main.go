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

type purgeUserRequest struct {
	Username string `json:"username"`
	Confirm  string `json:"confirm"`
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func loadAdminPasswordFromSecretsFile(path string) (string, error) {
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
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: purgeuser <username>")
		os.Exit(2)
	}
	target := strings.TrimSpace(os.Args[1])
	if target == "" {
		fmt.Fprintln(os.Stderr, "username is required")
		os.Exit(2)
	}

	baseURL := strings.TrimRight(getenv("SKYFORGE_BASE_URL", "https://skyforge.local.forwardnetworks.com"), "/")
	username := getenv("SKYFORGE_ADMIN_USERNAME", "skyforge")
	password := strings.TrimSpace(os.Getenv("SKYFORGE_ADMIN_PASSWORD"))
	if password == "" {
		secretsPath := strings.TrimSpace(getenv("SKYFORGE_SECRETS_FILE", "../deploy/skyforge-secrets.yaml"))
		abs, _ := filepath.Abs(secretsPath)
		loaded, err := loadAdminPasswordFromSecretsFile(abs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "missing SKYFORGE_ADMIN_PASSWORD and failed to load from %s: %v\n", abs, err)
			os.Exit(2)
		}
		password = loaded
	}

	timeout := 20 * time.Second
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // internal/self-signed lab env
	}
	client := &http.Client{Timeout: timeout, Transport: tr}

	loginURL := baseURL + "/api/skyforge/api/login"
	resp, body, err := doJSON(client, http.MethodPost, loginURL, loginRequest{Username: username, Password: password}, nil)
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

	purgeURL := baseURL + "/api/skyforge/api/admin/users/purge"
	resp, body, err = doJSON(client, http.MethodPost, purgeURL, purgeUserRequest{Username: target, Confirm: target}, map[string]string{
		"Cookie": setCookie,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "purge request failed: %v\n", err)
		os.Exit(1)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "purge failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}
	fmt.Printf("OK purged user: %s\n", target)
}
