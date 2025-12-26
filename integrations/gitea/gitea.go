package gitea

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	APIURL       string
	Username     string
	Password     string
	Timeout      time.Duration
	RepoPrivate  bool
	DefaultEmail string
}

type Client struct {
	cfg Config
}

func New(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &Client{cfg: cfg}
}

func (c *Client) Do(method, path string, payload any) (*http.Response, []byte, error) {
	if strings.TrimSpace(c.cfg.APIURL) == "" || strings.TrimSpace(c.cfg.Username) == "" || strings.TrimSpace(c.cfg.Password) == "" {
		return nil, nil, fmt.Errorf("gitea provisioning is not configured")
	}
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		body = strings.NewReader(string(encoded))
	}
	req, err := http.NewRequest(method, strings.TrimRight(c.cfg.APIURL, "/")+path, body)
	if err != nil {
		return nil, nil, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(c.cfg.Username + ":" + c.cfg.Password))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: c.cfg.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, data, nil
}

func (c *Client) GetRepoDefaultBranch(owner, repo string) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo))
	resp, body, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		fullURL := strings.TrimRight(c.cfg.APIURL, "/") + path
		return "", fmt.Errorf("gitea %s responded %d: %s", fullURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if branch, ok := parsed["default_branch"].(string); ok && strings.TrimSpace(branch) != "" {
		return strings.TrimSpace(branch), nil
	}
	return "master", nil
}

type ContentEntry struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Path string `json:"path"`
}

func (c *Client) ListDirectory(owner, repo, dir, ref string) ([]ContentEntry, error) {
	dir = strings.Trim(dir, "/")
	path := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(dir))
	if strings.TrimSpace(ref) != "" {
		path += "?ref=" + url.QueryEscape(ref)
	}
	resp, body, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		fullURL := strings.TrimRight(c.cfg.APIURL, "/") + path
		return nil, fmt.Errorf("gitea %s responded %d: %s", fullURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var entries []ContentEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func Identity(name, username, email string) map[string]any {
	name = strings.TrimSpace(name)
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)
	if name == "" {
		name = username
	}
	if email == "" && strings.Contains(username, "@") {
		email = username
	}
	if email == "" {
		domain := strings.TrimSpace(os.Getenv("SKYFORGE_CORP_EMAIL_DOMAIN"))
		if domain == "" {
			domain = strings.TrimSpace(os.Getenv("SKYFORGE_HOSTNAME"))
			domain = strings.Split(domain, ",")[0]
			domain = strings.TrimPrefix(domain, "https://")
			domain = strings.TrimPrefix(domain, "http://")
			domain = strings.TrimPrefix(domain, "*.")
			if idx := strings.Index(domain, "."); idx != -1 && idx+1 < len(domain) {
				domain = domain[idx+1:]
			}
		}
		if strings.TrimSpace(domain) != "" {
			email = fmt.Sprintf("%s@%s", username, domain)
		}
	}
	return map[string]any{"name": name, "email": email}
}

func (c *Client) EnsureFile(owner, repo, filePath, content, message, branch string, author map[string]any) error {
	filePath = strings.TrimPrefix(filePath, "/")
	refSuffix := ""
	if strings.TrimSpace(branch) != "" {
		refSuffix = "?ref=" + url.QueryEscape(branch)
	}

	resp, body, err := c.Do(http.MethodGet, fmt.Sprintf("/repos/%s/%s/contents/%s%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(filePath), refSuffix), nil)
	if err != nil {
		return err
	}

	contentB64 := base64.StdEncoding.EncodeToString([]byte(content))

	createFile := func() error {
		createPayload := map[string]any{
			"content": contentB64,
			"message": message,
		}
		if strings.TrimSpace(branch) != "" {
			createPayload["branch"] = branch
		}
		if author != nil {
			createPayload["author"] = author
			createPayload["committer"] = author
		}
		resp, body, err := c.Do(http.MethodPost, fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(filePath)), createPayload)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusCreated {
			return fmt.Errorf("gitea create file failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return nil
	}

	switch resp.StatusCode {
	case http.StatusOK:
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var listing []any
			if err := json.Unmarshal(body, &listing); err == nil {
				if len(listing) > 0 {
					return fmt.Errorf("gitea contents path is a directory (%s)", filePath)
				}
				return createFile()
			}
		}
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			return err
		}
		sha, _ := parsed["sha"].(string)
		if sha == "" {
			return fmt.Errorf("gitea contents missing sha for %s", filePath)
		}
		updatePayload := map[string]any{
			"sha":     sha,
			"content": contentB64,
			"message": message,
		}
		if strings.TrimSpace(branch) != "" {
			updatePayload["branch"] = branch
		}
		if author != nil {
			updatePayload["author"] = author
			updatePayload["committer"] = author
		}
		resp, body, err := c.Do(http.MethodPut, fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(filePath)), updatePayload)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("gitea update file failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return nil
	case http.StatusNotFound:
		return createFile()
	default:
		return fmt.Errorf("gitea get contents failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
}

func (c *Client) EnsureRepo(owner, repo string) error {
	resp, _, err := c.Do(http.MethodGet, fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo)), nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("gitea responded %d", resp.StatusCode)
	}
	createPayload := map[string]any{
		"name":      repo,
		"private":   c.cfg.RepoPrivate,
		"auto_init": false,
	}
	resp, body, err := c.Do(http.MethodPost, "/user/repos", createPayload)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gitea create repo failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) EnsureRepoFromBlueprint(owner, repo, blueprint string) error {
	blueprint = strings.TrimSpace(blueprint)
	if blueprint == "" {
		return c.EnsureRepo(owner, repo)
	}
	cloneAddr := blueprint
	if !strings.Contains(cloneAddr, "://") {
		cloneAddr = strings.TrimPrefix(cloneAddr, "/")
		cloneAddr = fmt.Sprintf("http://gitea:3000/%s.git", cloneAddr)
	}
	payload := map[string]any{
		"clone_addr":    cloneAddr,
		"repo_name":     repo,
		"repo_owner":    owner,
		"private":       c.cfg.RepoPrivate,
		"mirror":        false,
		"service":       "gitea",
		"issues":        false,
		"pull_requests": false,
		"wiki":          false,
		"releases":      false,
		"labels":        false,
		"milestones":    false,
		"lfs":           false,
		"auth_username": c.cfg.Username,
		"auth_password": c.cfg.Password,
	}
	resp, body, err := c.Do(http.MethodPost, "/repos/migrate", payload)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusConflict {
		return nil
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gitea migrate repo failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) EnsureCollaborator(owner, repo, username, permission string) error {
	path := fmt.Sprintf("/repos/%s/%s/collaborators/%s?permission=%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(username), url.QueryEscape(permission))
	resp, body, err := c.Do(http.MethodPut, path, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gitea add collaborator failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) RemoveCollaborator(owner, repo, username string) error {
	path := fmt.Sprintf("/repos/%s/%s/collaborators/%s", url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(username))
	resp, body, err := c.Do(http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gitea remove collaborator failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (c *Client) ListCollaborators(owner, repo string) ([]string, error) {
	path := fmt.Sprintf("/repos/%s/%s/collaborators", url.PathEscape(owner), url.PathEscape(repo))
	resp, body, err := c.Do(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitea list collaborators failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed []map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(parsed))
	for _, item := range parsed {
		if u, ok := item["login"].(string); ok && strings.TrimSpace(u) != "" {
			out = append(out, strings.TrimSpace(u))
		}
	}
	return out, nil
}
