package taskengine

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"encore.app/internal/jsonmap"
	"encore.app/internal/secretbox"
	"encore.app/internal/skyforgecore"
)

type JSONMap = jsonmap.JSONMap

func fromJSONMap(value JSONMap) (map[string]any, error) { return jsonmap.FromJSONMap(value) }
func toJSONMap(value map[string]any) (JSONMap, error)   { return jsonmap.ToJSONMap(value) }

type secretBox struct {
	box *secretbox.Box
}

func newSecretBox(secret string) *secretBox {
	return &secretBox{box: secretbox.New(secret)}
}

func (sb *secretBox) encrypt(plaintext string) (string, error) {
	if sb == nil || sb.box == nil {
		return "", fmt.Errorf("secret box unavailable")
	}
	return sb.box.Encrypt(plaintext)
}

func (sb *secretBox) decrypt(value string) (string, error) {
	if sb == nil || sb.box == nil {
		return "", fmt.Errorf("secret box unavailable")
	}
	return sb.box.Decrypt(value)
}

type ExternalTemplateRepo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Repo          string `json:"repo"`
	DefaultBranch string `json:"defaultBranch,omitempty"`
}

type Workspace struct {
	ID                         string
	Slug                       string
	Name                       string
	CreatedBy                  string
	DefaultBranch              string
	Blueprint                  string
	AllowExternalTemplateRepos bool
	ExternalTemplateRepos      []ExternalTemplateRepo
	NetlabServer               string
	EveServer                  string
	GiteaOwner                 string
	GiteaRepo                  string
	TerraformStateKey          string
	AWSRegion                  string
}

func (w Workspace) primaryOwner() string {
	if strings.TrimSpace(w.CreatedBy) != "" {
		return strings.TrimSpace(w.CreatedBy)
	}
	return ""
}

type userContext struct {
	userContext Workspace
	claims      SessionClaims
}

type SessionClaims struct {
	Username    string
	DisplayName string
	Email       string
	Groups      []string
}

type netlabServerRecord struct {
	ID          string
	WorkspaceID string
	Name        string
	APIURL      string
	APIInsecure bool
	APIToken    string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type NetlabServerConfig = skyforgecore.NetlabServerConfig
type NetlabConfig = skyforgecore.NetlabConfig

func normalizeNetlabServer(s NetlabServerConfig, fallback NetlabConfig) NetlabServerConfig {
	s.Name = strings.TrimSpace(s.Name)
	s.SSHHost = strings.TrimSpace(s.SSHHost)
	s.SSHUser = strings.TrimSpace(s.SSHUser)
	s.SSHKeyFile = strings.TrimSpace(s.SSHKeyFile)
	s.APIURL = strings.TrimRight(strings.TrimSpace(s.APIURL), "/")
	s.APIToken = strings.TrimSpace(s.APIToken)
	s.StateRoot = strings.TrimSpace(s.StateRoot)
	if s.StateRoot == "" {
		s.StateRoot = strings.TrimSpace(fallback.StateRoot)
	}
	if s.SSHUser == "" {
		s.SSHUser = strings.TrimSpace(fallback.SSHUser)
	}
	if s.SSHKeyFile == "" {
		s.SSHKeyFile = strings.TrimSpace(fallback.SSHKeyFile)
	}
	if s.APIURL == "" && s.SSHHost != "" {
		s.APIURL = strings.TrimRight(fmt.Sprintf("https://%s/netlab", s.SSHHost), "/")
	}
	return s
}

type UserDeployment struct {
	ID          string
	WorkspaceID string
	Name        string
	Type        string
	Config      JSONMap
}

func parseExternalTemplateRepos(raw []byte) []ExternalTemplateRepo {
	if len(raw) == 0 {
		return nil
	}
	var out []ExternalTemplateRepo
	_ = json.Unmarshal(raw, &out)
	return out
}

func nullIfEmpty(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

// sqlNullString helper used when scanning user-context rows.
type sqlNullString = sql.NullString
