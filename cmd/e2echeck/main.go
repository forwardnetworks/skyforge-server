package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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

type netlabValidateRequest struct {
	Source       string            `json:"source"`
	Repo         string            `json:"repo"`
	Dir          string            `json:"dir"`
	Template     string            `json:"template"`
	Environment  map[string]string `json:"environment"`
	SetOverrides []string          `json:"setOverrides"`
}

type netlabValidateResponse struct {
	WorkspaceID string         `json:"workspaceId"`
	User        string         `json:"user"`
	Task        map[string]any `json:"task"`
}

type matrixFile struct {
	Tests []matrixTest `yaml:"tests"`
}

type matrixTest struct {
	Name string `yaml:"name"`
	Kind string `yaml:"kind"`

	NetlabValidate *struct {
		Source       string            `yaml:"source"`
		Repo         string            `yaml:"repo"`
		Dir          string            `yaml:"dir"`
		Template     string            `yaml:"template"`
		Environment  map[string]string `yaml:"environment"`
		SetOverrides []string          `yaml:"setOverrides"`
		Timeout      string            `yaml:"timeout"`
	} `yaml:"netlab_validate"`
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

func loadPasswordFromSecretsFile(path string) (string, error) {
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

func parseTaskID(task map[string]any) int {
	if task == nil {
		return 0
	}
	if v, ok := task["id"]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		case string:
			id, _ := strconv.Atoi(strings.TrimSpace(t))
			return id
		}
	}
	return 0
}

func waitForTaskFinished(client *http.Client, baseURL string, cookie string, taskID int, timeout time.Duration) (status string, errMsg string, err error) {
	if taskID <= 0 {
		return "", "", fmt.Errorf("invalid task id")
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	url := fmt.Sprintf("%s/api/skyforge/api/runs/%d/lifecycle", strings.TrimRight(baseURL, "/"), taskID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return "", "", fmt.Errorf("task lifecycle SSE failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	defer resp.Body.Close()

	deadline := time.Now().Add(timeout)
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	var currentData strings.Builder
	for sc.Scan() {
		if time.Now().After(deadline) {
			return "", "", fmt.Errorf("timeout waiting for task %d", taskID)
		}
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			// end of event
			if currentData.Len() > 0 {
				var evt struct {
					Type    string         `json:"type"`
					Time    string         `json:"time"`
					Payload map[string]any `json:"payload"`
				}
				_ = json.Unmarshal([]byte(currentData.String()), &evt)
				currentData.Reset()
				if strings.TrimSpace(evt.Type) == "task.finished" {
					st, _ := evt.Payload["status"].(string)
					er, _ := evt.Payload["error"].(string)
					return strings.TrimSpace(st), strings.TrimSpace(er), nil
				}
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			currentData.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			continue
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", err
	}
	return "", "", fmt.Errorf("task lifecycle stream ended before task.finished")
}

func main() {
	baseURL := strings.TrimRight(getenv("SKYFORGE_BASE_URL", "https://skyforge.local.forwardnetworks.com"), "/")
	username := getenv("SKYFORGE_E2E_USERNAME", getenv("SKYFORGE_SMOKE_USERNAME", "skyforge"))
	password := mustEnv("SKYFORGE_E2E_PASSWORD")
	if password == "" {
		password = mustEnv("SKYFORGE_SMOKE_PASSWORD")
	}
	if password == "" {
		secretsPath := strings.TrimSpace(getenv("SKYFORGE_SECRETS_FILE", "../deploy/skyforge-secrets.yaml"))
		abs, _ := filepath.Abs(secretsPath)
		loaded, err := loadPasswordFromSecretsFile(abs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "missing SKYFORGE_E2E_PASSWORD and failed to load from %s: %v\n", abs, err)
			os.Exit(2)
		}
		password = loaded
	}

	timeout := 30 * time.Second
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
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
	cookie := resp.Header.Get("Set-Cookie")
	if strings.TrimSpace(cookie) == "" {
		fmt.Fprintln(os.Stderr, "login missing Set-Cookie header")
		os.Exit(1)
	}
	fmt.Printf("OK login: %s\n", username)

	wsName := fmt.Sprintf("e2e-%s", time.Now().UTC().Format("20060102-150405"))
	createURL := baseURL + "/api/skyforge/api/workspaces"
	resp, body, err = doJSON(client, http.MethodPost, createURL, workspaceCreateRequest{Name: wsName}, map[string]string{"Cookie": cookie})
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

	defer func() {
		deleteURL := baseURL + "/api/skyforge/api/workspaces/" + ws.ID + "?confirm=" + ws.Slug
		resp, body, err := doJSON(client, http.MethodDelete, deleteURL, nil, map[string]string{"Cookie": cookie})
		if err != nil {
			fmt.Fprintf(os.Stderr, "workspace delete request failed: %v\n", err)
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			fmt.Fprintf(os.Stderr, "workspace delete failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
			return
		}
		fmt.Printf("OK workspace delete: %s\n", ws.ID)
	}()

	matrixPath := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_MATRIX_FILE"))
	if matrixPath == "" {
		fmt.Println("OK e2echeck: no SKYFORGE_E2E_MATRIX_FILE set (skipping template validation)")
		return
	}
	raw, err := os.ReadFile(matrixPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read matrix file %s: %v\n", matrixPath, err)
		os.Exit(2)
	}
	var m matrixFile
	if err := yaml.Unmarshal(raw, &m); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse matrix file %s: %v\n", matrixPath, err)
		os.Exit(2)
	}
	for _, t := range m.Tests {
		name := strings.TrimSpace(t.Name)
		kind := strings.TrimSpace(t.Kind)
		if name == "" {
			name = kind
		}
		switch kind {
		case "netlab_validate":
			if t.NetlabValidate == nil {
				fmt.Fprintf(os.Stderr, "test %q: missing netlab_validate section\n", name)
				os.Exit(2)
			}
			reqIn := netlabValidateRequest{
				Source:       strings.TrimSpace(t.NetlabValidate.Source),
				Repo:         strings.TrimSpace(t.NetlabValidate.Repo),
				Dir:          strings.TrimSpace(t.NetlabValidate.Dir),
				Template:     strings.TrimSpace(t.NetlabValidate.Template),
				Environment:  t.NetlabValidate.Environment,
				SetOverrides: t.NetlabValidate.SetOverrides,
			}
			if reqIn.Environment == nil {
				reqIn.Environment = map[string]string{}
			}
			if reqIn.SetOverrides == nil {
				reqIn.SetOverrides = []string{}
			}
			timeoutStr := strings.TrimSpace(t.NetlabValidate.Timeout)
			wait := 10 * time.Minute
			if timeoutStr != "" {
				if parsed, err := time.ParseDuration(timeoutStr); err == nil && parsed > 0 {
					wait = parsed
				}
			}
			url := fmt.Sprintf("%s/api/skyforge/api/workspaces/%s/netlab/validate", baseURL, ws.ID)
			resp, body, err := doJSON(client, http.MethodPost, url, reqIn, map[string]string{"Cookie": cookie})
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: request failed: %v\n", name, err)
				os.Exit(1)
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "test %q: validate failed (%d): %s\n", name, resp.StatusCode, strings.TrimSpace(string(body)))
				os.Exit(1)
			}
			var out netlabValidateResponse
			if err := json.Unmarshal(body, &out); err != nil {
				fmt.Fprintf(os.Stderr, "test %q: validate response parse failed: %v\n", name, err)
				os.Exit(1)
			}
			taskID := parseTaskID(out.Task)
			if taskID <= 0 {
				fmt.Fprintf(os.Stderr, "test %q: validate returned missing task id: %s\n", name, strings.TrimSpace(string(body)))
				os.Exit(1)
			}
			fmt.Printf("OK %s: task=%d (waiting)\n", name, taskID)

			// Use a separate client without request timeout to allow long-lived SSE.
			sseClient := &http.Client{Transport: tr}
			status, errMsg, err := waitForTaskFinished(sseClient, baseURL, cookie, taskID, wait)
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: wait failed: %v\n", name, err)
				os.Exit(1)
			}
			if strings.TrimSpace(status) != "succeeded" {
				fmt.Fprintf(os.Stderr, "test %q: task finished with status=%q error=%q\n", name, status, errMsg)
				os.Exit(1)
			}
			fmt.Printf("OK %s: succeeded\n", name)
		default:
			fmt.Fprintf(os.Stderr, "unknown test kind %q (%s)\n", kind, name)
			os.Exit(2)
		}
	}
	fmt.Printf("OK e2echeck: %d test(s)\n", len(m.Tests))
}
