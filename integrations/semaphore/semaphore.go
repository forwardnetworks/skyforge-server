package semaphore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	BaseURL      string
	Token        string
	Username     string
	Password     string
	PasswordFile string
	Timeout      time.Duration
}

type Client struct {
	mu       sync.Mutex
	cfg      Config
	client   *http.Client
	loggedIn bool
}

func New(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 20 * time.Second
	}
	return &Client{cfg: cfg}
}

func (c *Client) authMode() string {
	if strings.TrimSpace(c.cfg.Username) != "" && (strings.TrimSpace(c.cfg.Password) != "" || strings.TrimSpace(c.cfg.PasswordFile) != "") {
		return "cookie"
	}
	// Token auth is supported, but cookie auth is preferred when both are configured
	// to match the common deployment setup (service user + password).
	if strings.TrimSpace(c.cfg.Token) != "" {
		return "bearer"
	}
	return "none"
}

func (c *Client) ensureSession() (*http.Client, error) {
	mode := c.authMode()
	if mode != "cookie" {
		return &http.Client{Timeout: c.cfg.Timeout}, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.client != nil && c.loggedIn {
		return c.client, nil
	}

	password := strings.TrimSpace(c.cfg.Password)
	if password == "" && strings.TrimSpace(c.cfg.PasswordFile) != "" {
		if data, err := os.ReadFile(strings.TrimSpace(c.cfg.PasswordFile)); err == nil {
			password = strings.TrimSpace(string(data))
		}
	}
	if strings.TrimSpace(c.cfg.Username) == "" || password == "" {
		return nil, fmt.Errorf("missing semaphore username/password")
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: c.cfg.Timeout, Jar: jar}

	loginURL := strings.TrimRight(c.cfg.BaseURL, "/") + "/auth/login"
	payload := map[string]any{
		"auth":     c.cfg.Username,
		"password": password,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, loginURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("semaphore login failed (%d)", resp.StatusCode)
	}

	c.client = client
	c.loggedIn = true
	return client, nil
}

func (c *Client) Do(method, path string, payload any) (*http.Response, []byte, error) {
	client, err := c.ensureSession()
	if err != nil {
		return nil, nil, err
	}

	var payloadBytes []byte
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		payloadBytes = encoded
	}

	doOnce := func(client *http.Client) (*http.Response, []byte, error) {
		var body io.Reader
		if payloadBytes != nil {
			body = bytes.NewReader(payloadBytes)
		}
		req, err := http.NewRequest(method, strings.TrimRight(c.cfg.BaseURL, "/")+path, body)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.authMode() == "bearer" {
			req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(c.cfg.Token))
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, data, nil
	}

	resp, data, err := doOnce(client)
	if err != nil {
		return resp, data, err
	}

	if resp.StatusCode == http.StatusUnauthorized && c.authMode() == "cookie" {
		c.mu.Lock()
		c.loggedIn = false
		c.mu.Unlock()

		client, err := c.ensureSession()
		if err != nil {
			return resp, data, err
		}
		return doOnce(client)
	}

	return resp, data, nil
}
