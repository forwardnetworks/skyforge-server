package skyforge

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"encore.dev"
	"encore.dev/rlog"

	secretreader "encore.app/internal/secrets"

	"encore.app/storage"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidcTypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-ldap/ldap/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var cloudCredentialStatusCache struct {
	mu    sync.Mutex
	items map[string]bool
}

type Config struct {
	ListenAddr                string
	SessionSecret             string
	SessionTTL                time.Duration
	SessionCookie             string
	CookieSecure              string
	CookieDomain              string
	InternalToken             string
	StaticRoot                string
	PlatformDataDir           string
	MaxGroups                 int
	AdminUsers                []string
	AdminUsername             string
	AdminPassword             string
	WorkspaceSyncSeconds      int
	UI                        UIConfig
	NotificationsEnabled      bool
	NotificationsInterval     time.Duration
	CloudCredentialChecks     time.Duration
	CorpEmailDomain           string
	AwsSSOAccountID           string
	AwsSSORoleName            string
	AwsSSOStartURL            string
	AwsSSORegion              string
	GiteaBaseURL              string
	NetboxBaseURL             string
	NautobotBaseURL           string
	YaadeBaseURL              string
	StateBackend              string
	DBHost                    string
	DBPort                    int
	DBName                    string
	DBUser                    string
	DBPassword                string
	DBPasswordFile            string
	DBSSLMode                 string
	Netlab                    NetlabConfig
	NetlabServers             []NetlabServerConfig
	Labs                      LabsConfig
	OIDC                      OIDCConfig
	LDAP                      LDAPConfig
	LDAPLookupBindDN          string
	LDAPLookupBindPassword    string
	Workspaces                WorkspacesConfig
	EveServers                []EveServerConfig
	LabppRunnerImage          string
	LabppRunnerPullPolicy     string
	LabppRunnerPVCName        string
	LabppConfigDirBase        string
	LabppConfigVersion        string
	LabppNetboxURL            string
	LabppNetboxUsername       string
	LabppNetboxPassword       string
	LabppNetboxToken          string
	LabppNetboxMgmtSubnet     string
	LabppS3AccessKey          string
	LabppS3SecretKey          string
	LabppS3Region             string
	LabppS3BucketName         string
	LabppS3Endpoint           string
	LabppS3DisableSSL         bool
	LabppS3DisableChecksum    bool
	YaadeAdminUsername        string
	YaadeAdminPassword        string
	ContainerlabAPIPath       string
	ContainerlabJWTSecret     string
	ContainerlabSkipTLSVerify bool
	PKICACert                 string
	PKICAKey                  string
	PKIDefaultDays            int
	SSHCAKey                  string
	SSHCADefaultDays          int
	DNSURL                    string
	DNSAdminUsername          string
	DNSUserZoneSuffix         string
	TaskWorkerEnabled         bool
}

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type RunRequest struct {
	TemplateID  int     `json:"templateId"`
	WorkspaceID *string `json:"workspaceId,omitempty"`
	Debug       bool    `json:"debug,omitempty"`
	DryRun      bool    `json:"dryRun,omitempty"`
	Diff        bool    `json:"diff,omitempty"`
	Playbook    string  `json:"playbook,omitempty"`
	Environment JSONMap `json:"environment,omitempty"`
	Limit       string  `json:"limit,omitempty"`
	GitBranch   string  `json:"gitBranch,omitempty"`
	Message     string  `json:"message,omitempty"`
	Arguments   string  `json:"arguments,omitempty"`
	InventoryID *int    `json:"inventoryId,omitempty"`
	Extra       JSONMap `json:"extra,omitempty"`
}

type TemplateSummary struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	WorkspaceID string `json:"workspaceId"`
	Repository  string `json:"repository,omitempty"`
	Playbook    string `json:"playbook,omitempty"`
	Description string `json:"description,omitempty"`
	InventoryID int    `json:"inventoryId,omitempty"`
}

type NotificationSettings struct {
	PollingEnabled    bool  `json:"pollingEnabled"`
	PollingIntervalMs int64 `json:"pollingIntervalMs"`
}

type NotificationRecord struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Title       string    `json:"title"`
	Message     string    `json:"message"`
	Type        string    `json:"type"`
	Category    string    `json:"category,omitempty"`
	ReferenceID string    `json:"reference_id,omitempty"`
	Priority    string    `json:"priority,omitempty"`
	IsRead      bool      `json:"is_read"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type LDAPConfig struct {
	URL             string
	BindTemplate    string
	BaseDN          string
	DisplayNameAttr string
	MailAttr        string
	GroupAttr       string
	UseStartTLS     bool
	SkipTLSVerify   bool
}

type UIConfig struct {
	ProductName      string
	ProductSubtitle  string
	LogoURL          string
	LogoAlt          string
	HeaderBackground string
	SupportText      string
	SupportURL       string
	ThemeDefault     string
	OIDCEnabled      bool
	OIDCLoginURL     string
}

type NetlabConfig struct {
	SSHHost    string
	SSHUser    string
	SSHKeyFile string
	StateRoot  string
}

type NetlabServerConfig struct {
	Name                      string `json:"name,omitempty"`
	SSHHost                   string `json:"sshHost,omitempty"`
	SSHUser                   string `json:"sshUser,omitempty"`
	SSHKeyFile                string `json:"sshKeyFile,omitempty"`
	StateRoot                 string `json:"stateRoot,omitempty"`
	APIURL                    string `json:"apiUrl,omitempty"`
	APIInsecure               bool   `json:"apiInsecure,omitempty"`
	APIToken                  string `json:"apiToken,omitempty"`
	ContainerlabAPIURL        string `json:"containerlabApiUrl,omitempty"`
	ContainerlabSkipTLSVerify bool   `json:"containerlabSkipTlsVerify,omitempty"`
}

type LabsConfig struct {
	PublicURL        string
	EveAPIURL        string
	EveUsername      string
	EvePassword      string
	EveSkipTLSVerify bool
	EveSSHKeyFile    string
	EveSSHUser       string
	EveSSHTunnel     bool
	EveLabsPath      string
	EveTmpPath       string
}

type EveServerConfig struct {
	Name          string `json:"name"`
	APIURL        string `json:"apiUrl"`
	WebURL        string `json:"webUrl,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	SkipTLSVerify bool   `json:"skipTlsVerify,omitempty"`
	SSHHost       string `json:"sshHost,omitempty"`
	SSHUser       string `json:"sshUser,omitempty"`
	LabsPath      string `json:"labsPath,omitempty"`
	TmpPath       string `json:"tmpPath,omitempty"`
}

type WorkspacesConfig struct {
	DataDir                         string
	GiteaAPIURL                     string
	GiteaUsername                   string
	GiteaPassword                   string
	GiteaRepoPrivate                bool
	DeleteMode                      string
	ObjectStorageEndpoint           string
	ObjectStorageUseSSL             bool
	ObjectStorageTerraformAccessKey string
	ObjectStorageTerraformSecretKey string
}

type SkyforgeWorkspace struct {
	ID                        string    `json:"id"`
	Slug                      string    `json:"slug"`
	Name                      string    `json:"name"`
	Description               string    `json:"description,omitempty"`
	CreatedAt                 time.Time `json:"createdAt"`
	CreatedBy                 string    `json:"createdBy"`
	IsPublic                  bool      `json:"isPublic"`
	Owners                    []string  `json:"owners,omitempty"`
	OwnerGroups               []string  `json:"ownerGroups,omitempty"`
	Editors                   []string  `json:"editors,omitempty"`
	EditorGroups              []string  `json:"editorGroups,omitempty"`
	Viewers                   []string  `json:"viewers,omitempty"`
	ViewerGroups              []string  `json:"viewerGroups,omitempty"`
	Blueprint                 string    `json:"blueprint,omitempty"`
	DefaultBranch             string    `json:"defaultBranch,omitempty"`
	TerraformStateKey         string    `json:"terraformStateKey,omitempty"`
	TerraformInitTemplateID   int       `json:"terraformInitTemplateId,omitempty"`
	TerraformPlanTemplateID   int       `json:"terraformPlanTemplateId,omitempty"`
	TerraformApplyTemplateID  int       `json:"terraformApplyTemplateId,omitempty"`
	AnsibleRunTemplateID      int       `json:"ansibleRunTemplateId,omitempty"`
	NetlabRunTemplateID       int       `json:"netlabRunTemplateId,omitempty"`
	LabppRunTemplateID        int       `json:"labppRunTemplateId,omitempty"`
	ContainerlabRunTemplateID int       `json:"containerlabRunTemplateId,omitempty"`
	AWSAccountID              string    `json:"awsAccountId,omitempty"`
	AWSRoleName               string    `json:"awsRoleName,omitempty"`
	AWSRegion                 string    `json:"awsRegion,omitempty"`
	AWSAuthMethod             string    `json:"awsAuthMethod,omitempty"`
	ArtifactsBucket           string    `json:"artifactsBucket,omitempty"`
	EveServer                 string    `json:"eveServer,omitempty"`
	NetlabServer              string    `json:"netlabServer,omitempty"`
	LegacyWorkspaceID         int       `json:"-"`
	GiteaOwner                string    `json:"giteaOwner"`
	GiteaRepo                 string    `json:"giteaRepo"`
}

type LabSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Owner     string `json:"owner,omitempty"`
	Status    string `json:"status"`
	Provider  string `json:"provider"`
	UpdatedAt string `json:"updatedAt"`
	LaunchURL string `json:"launchUrl,omitempty"`
}

func getenv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func inferEmailDomain(explicit string) string {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		return explicit
	}
	raw := strings.TrimSpace(os.Getenv("SKYFORGE_HOSTNAME"))
	if raw == "" {
		return ""
	}
	raw = strings.Split(raw, ",")[0]
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "*.")
	if idx := strings.Index(raw, "."); idx != -1 && idx+1 < len(raw) {
		return raw[idx+1:]
	}
	return ""
}

func isSafeRelativePath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return true
	}
	if strings.HasPrefix(path, "/") || strings.Contains(path, "\\") {
		return false
	}
	parts := strings.Split(path, "/")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

func workspacePrimaryOwner(p SkyforgeWorkspace) string {
	if strings.TrimSpace(p.CreatedBy) != "" {
		return strings.TrimSpace(p.CreatedBy)
	}
	if len(p.Owners) > 0 {
		return strings.TrimSpace(p.Owners[0])
	}
	return ""
}

func mustGetSecret(key string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	if fromFile := loadSecretFromFile(key + "_FILE"); fromFile != "" {
		return fromFile
	}
	secretName := secretFileNameForEnv(key)
	if secretName != "" {
		if fromFile, err := secretreader.ReadSecretFromEnvOrFile(key, secretName); err == nil && strings.TrimSpace(fromFile) != "" {
			_ = os.Setenv(key, fromFile)
			return strings.TrimSpace(fromFile)
		}
	}
	if fromEncore := getEncoreSecret(key); strings.TrimSpace(fromEncore) != "" {
		return strings.TrimSpace(fromEncore)
	}
	log.Fatalf("missing required secret env var %s", key)
	return ""
}

func getOptionalSecret(key string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	if fromFile := loadSecretFromFile(key + "_FILE"); fromFile != "" {
		return fromFile
	}
	secretName := secretFileNameForEnv(key)
	if secretName != "" {
		if fromFile, err := secretreader.ReadSecretFromEnvOrFile(key, secretName); err == nil && strings.TrimSpace(fromFile) != "" {
			_ = os.Setenv(key, fromFile)
			return strings.TrimSpace(fromFile)
		}
	}
	return strings.TrimSpace(getEncoreSecret(key))
}

func secretFileNameForEnv(key string) string {
	switch key {
	case "SKYFORGE_ADMIN_PASSWORD":
		return "skyforge-admin-password"
	case "SKYFORGE_SESSION_SECRET":
		return "skyforge-session-secret"
	case "SKYFORGE_LDAP_URL":
		return "skyforge-ldap-url"
	case "SKYFORGE_LDAP_BIND_TEMPLATE":
		return "skyforge-ldap-bind-template"
	case "SKYFORGE_LDAP_LOOKUP_BINDDN":
		return "skyforge-ldap-lookup-binddn"
	case "SKYFORGE_LDAP_LOOKUP_BINDPASSWORD":
		return "skyforge-ldap-lookup-bindpassword"
	case "SKYFORGE_DB_PASSWORD":
		return "db-skyforge-server-password"
	case "SKYFORGE_GITEA_PASSWORD":
		return "gitea-admin-password"
	case "SKYFORGE_CONTAINERLAB_JWT_SECRET":
		return "skyforge-containerlab-jwt-secret"
	case "SKYFORGE_PKI_CA_CERT":
		return "skyforge-pki-ca-cert"
	case "SKYFORGE_PKI_CA_KEY":
		return "skyforge-pki-ca-key"
	case "SKYFORGE_SSH_CA_KEY":
		return "skyforge-ssh-ca-key"
	case "SKYFORGE_OBJECT_STORAGE_TERRAFORM_ACCESS_KEY":
		return "object-storage-terraform-access-key"
	case "SKYFORGE_OBJECT_STORAGE_TERRAFORM_SECRET_KEY":
		return "object-storage-terraform-secret-key"
	case "SKYFORGE_INTERNAL_TOKEN":
		return "skyforge-internal-token"
	default:
		return ""
	}
}

func readOptionalFile(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func parseEveServers(raw string) ([]EveServerConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var decoded any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}

	switch v := decoded.(type) {
	case []any:
		payload, _ := json.Marshal(v)
		var servers []EveServerConfig
		if err := json.Unmarshal(payload, &servers); err != nil {
			return nil, err
		}
		return servers, nil
	case map[string]any:
		if serversRaw, ok := v["servers"]; ok {
			payload, _ := json.Marshal(serversRaw)
			var servers []EveServerConfig
			if err := json.Unmarshal(payload, &servers); err != nil {
				return nil, err
			}
			return servers, nil
		}
		return nil, fmt.Errorf("invalid eve servers json (expected array or {\"servers\": [...]})")
	default:
		return nil, fmt.Errorf("invalid eve servers json (expected array or object)")
	}
}

func parseNetlabServers(raw string) ([]NetlabServerConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var decoded any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}

	switch v := decoded.(type) {
	case []any:
		payload, _ := json.Marshal(v)
		var rawServers []map[string]any
		if err := json.Unmarshal(payload, &rawServers); err != nil {
			return nil, err
		}
		servers := make([]NetlabServerConfig, 0, len(rawServers))
		for _, entry := range rawServers {
			b, _ := json.Marshal(entry)
			var s NetlabServerConfig
			if err := json.Unmarshal(b, &s); err != nil {
				return nil, err
			}
			if _, ok := entry["apiInsecure"]; !ok {
				s.APIInsecure = true
			}
			servers = append(servers, s)
		}
		return servers, nil
	case map[string]any:
		if serversRaw, ok := v["servers"]; ok {
			payload, _ := json.Marshal(serversRaw)
			var rawServers []map[string]any
			if err := json.Unmarshal(payload, &rawServers); err != nil {
				return nil, err
			}
			servers := make([]NetlabServerConfig, 0, len(rawServers))
			for _, entry := range rawServers {
				b, _ := json.Marshal(entry)
				var s NetlabServerConfig
				if err := json.Unmarshal(b, &s); err != nil {
					return nil, err
				}
				if _, ok := entry["apiInsecure"]; !ok {
					s.APIInsecure = true
				}
				servers = append(servers, s)
			}
			return servers, nil
		}
		return nil, fmt.Errorf("invalid netlab servers json (expected array or {\"servers\": [...]})")
	default:
		return nil, fmt.Errorf("invalid netlab servers json (expected array or object)")
	}
}

func normalizeEveServer(s EveServerConfig, fallback LabsConfig) EveServerConfig {
	s.Name = strings.TrimSpace(s.Name)
	s.APIURL = strings.TrimRight(strings.TrimSpace(s.APIURL), "/")
	s.WebURL = strings.TrimRight(strings.TrimSpace(s.WebURL), "/")
	s.Username = strings.TrimSpace(s.Username)
	s.Password = strings.TrimSpace(s.Password)
	s.SSHHost = strings.TrimSpace(s.SSHHost)
	s.SSHUser = strings.TrimSpace(s.SSHUser)
	s.LabsPath = strings.TrimSpace(s.LabsPath)
	s.TmpPath = strings.TrimSpace(s.TmpPath)

	if s.Username == "" {
		s.Username = strings.TrimSpace(fallback.EveUsername)
	}
	if s.Password == "" {
		s.Password = strings.TrimSpace(fallback.EvePassword)
	}
	if !s.SkipTLSVerify && fallback.EveSkipTLSVerify {
		s.SkipTLSVerify = true
	}
	if s.APIURL == "" && strings.TrimSpace(fallback.EveAPIURL) != "" {
		s.APIURL = strings.TrimRight(strings.TrimSpace(fallback.EveAPIURL), "/")
	}
	if s.WebURL == "" && strings.TrimSpace(fallback.PublicURL) != "" {
		s.WebURL = strings.TrimRight(strings.TrimSpace(fallback.PublicURL), "/")
	}

	if s.WebURL == "" && s.APIURL != "" {
		web := s.APIURL
		if strings.HasSuffix(web, "/api") {
			web = strings.TrimSuffix(web, "/api")
		}
		s.WebURL = strings.TrimRight(web, "/")
	}
	if s.SSHHost == "" && s.APIURL != "" {
		if u, err := url.Parse(s.APIURL); err == nil && u != nil {
			s.SSHHost = strings.TrimSpace(u.Hostname())
		}
	}
	if s.SSHHost == "" && s.WebURL != "" {
		if u, err := url.Parse(s.WebURL); err == nil && u != nil {
			s.SSHHost = strings.TrimSpace(u.Hostname())
		}
	}
	if s.SSHUser == "" {
		s.SSHUser = strings.TrimSpace(fallback.EveSSHUser)
	}
	if s.LabsPath == "" {
		s.LabsPath = strings.TrimSpace(fallback.EveLabsPath)
	}
	if s.TmpPath == "" {
		s.TmpPath = strings.TrimSpace(fallback.EveTmpPath)
	}
	return s
}

func normalizeNetlabServer(s NetlabServerConfig, fallback NetlabConfig) NetlabServerConfig {
	s.Name = strings.TrimSpace(s.Name)
	s.SSHHost = strings.TrimSpace(s.SSHHost)
	s.SSHUser = strings.TrimSpace(s.SSHUser)
	s.SSHKeyFile = strings.TrimSpace(s.SSHKeyFile)
	s.StateRoot = strings.TrimSpace(s.StateRoot)
	s.APIURL = strings.TrimRight(strings.TrimSpace(s.APIURL), "/")
	s.ContainerlabAPIURL = strings.TrimRight(strings.TrimSpace(s.ContainerlabAPIURL), "/")

	if s.SSHUser == "" {
		s.SSHUser = strings.TrimSpace(fallback.SSHUser)
	}
	if s.SSHKeyFile == "" {
		s.SSHKeyFile = strings.TrimSpace(fallback.SSHKeyFile)
	}
	if s.StateRoot == "" {
		s.StateRoot = strings.TrimSpace(fallback.StateRoot)
	}
	if s.APIURL == "" && s.SSHHost != "" {
		s.APIURL = strings.TrimRight(fmt.Sprintf("https://%s/netlab", s.SSHHost), "/")
	}
	if s.Name == "" {
		if s.SSHHost != "" {
			s.Name = s.SSHHost
		} else {
			s.Name = "netlab-default"
		}
	}
	return s
}

func eveServerByName(servers []EveServerConfig, name string) *EveServerConfig {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	for i := range servers {
		if strings.EqualFold(strings.TrimSpace(servers[i].Name), name) {
			return &servers[i]
		}
	}
	return nil
}

func netlabServerByName(servers []NetlabServerConfig, name string) *NetlabServerConfig {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	for i := range servers {
		if strings.EqualFold(servers[i].Name, name) {
			return &servers[i]
		}
	}
	return nil
}

func netlabServerFromEve(server EveServerConfig, fallback NetlabConfig, labsCfg LabsConfig) NetlabServerConfig {
	eve := normalizeEveServer(server, labsCfg)
	netlab := NetlabServerConfig{
		Name:        strings.TrimSpace(eve.Name),
		SSHHost:     strings.TrimSpace(eve.SSHHost),
		SSHUser:     strings.TrimSpace(eve.SSHUser),
		SSHKeyFile:  strings.TrimSpace(fallback.SSHKeyFile),
		StateRoot:   strings.TrimSpace(fallback.StateRoot),
		APIInsecure: true,
	}
	return normalizeNetlabServer(netlab, fallback)
}

func netlabServerByNameForConfig(cfg Config, name string) *NetlabServerConfig {
	if s := netlabServerByName(cfg.NetlabServers, name); s != nil {
		normalized := normalizeNetlabServer(*s, cfg.Netlab)
		return &normalized
	}
	if eve := eveServerByName(cfg.EveServers, name); eve != nil {
		mapped := netlabServerFromEve(*eve, cfg.Netlab, cfg.Labs)
		return &mapped
	}
	return nil
}

func eveServerNames(servers []EveServerConfig) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		if strings.TrimSpace(s.Name) != "" {
			out = append(out, strings.TrimSpace(s.Name))
		}
	}
	return out
}

func netlabServerNames(servers []NetlabServerConfig) []string {
	names := make([]string, 0, len(servers))
	for _, s := range servers {
		if name := strings.TrimSpace(s.Name); name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func netlabServerNamesForConfig(cfg Config) []string {
	if len(cfg.NetlabServers) == 0 {
		return eveServerNames(cfg.EveServers)
	}
	return netlabServerNames(cfg.NetlabServers)
}

func resolveNetlabServer(cfg Config, name string) (*NetlabServerConfig, string) {
	name = strings.TrimSpace(name)
	if len(cfg.NetlabServers) == 0 {
		if name != "" {
			if eve := eveServerByName(cfg.EveServers, name); eve != nil {
				mapped := netlabServerFromEve(*eve, cfg.Netlab, cfg.Labs)
				return &mapped, mapped.Name
			}
		}
		// If a dedicated Netlab pool isn't configured, treat the first configured EVE-NG server
		// as the default Netlab runner. This keeps "Netlab runs default to EVE" working without
		// requiring a separate SKYFORGE_NETLAB_SSH_HOST override.
		if len(cfg.EveServers) > 0 {
			mapped := netlabServerFromEve(cfg.EveServers[0], cfg.Netlab, cfg.Labs)
			return &mapped, mapped.Name
		}
		if strings.TrimSpace(cfg.Netlab.SSHHost) == "" {
			return nil, ""
		}
		s := normalizeNetlabServer(NetlabServerConfig{
			Name:        "netlab-default",
			SSHHost:     cfg.Netlab.SSHHost,
			SSHUser:     cfg.Netlab.SSHUser,
			SSHKeyFile:  cfg.Netlab.SSHKeyFile,
			StateRoot:   cfg.Netlab.StateRoot,
			APIInsecure: true,
		}, cfg.Netlab)
		return &s, s.Name
	}
	if name != "" {
		if s := netlabServerByNameForConfig(cfg, name); s != nil {
			return s, s.Name
		}
		return nil, ""
	}
	s := normalizeNetlabServer(cfg.NetlabServers[0], cfg.Netlab)
	return &s, s.Name
}

func netlabConfigFromServer(server NetlabServerConfig, fallback NetlabConfig) NetlabConfig {
	server = normalizeNetlabServer(server, fallback)
	return NetlabConfig{
		SSHHost:    server.SSHHost,
		SSHUser:    server.SSHUser,
		SSHKeyFile: server.SSHKeyFile,
		StateRoot:  server.StateRoot,
	}
}

func loadConfig() Config {
	sessionTTL := 8 * time.Hour
	if raw := getenv("SKYFORGE_SESSION_TTL", "8h"); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			sessionTTL = parsed
		} else {
			log.Printf("invalid SKYFORGE_SESSION_TTL (%s), defaulting to %s", raw, sessionTTL)
		}
	}

	maxGroups := 50
	if raw := getenv("SKYFORGE_MAX_GROUPS", "50"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 500 {
			maxGroups = v
		}
	}

	adminUsers := parseUserList(getenv("SKYFORGE_ADMIN_USERS", ""))
	adminUsername := strings.TrimSpace(getenv("SKYFORGE_ADMIN_USERNAME", "skyforge"))
	adminPassword := strings.TrimSpace(getOptionalSecret("SKYFORGE_ADMIN_PASSWORD"))
	corpEmailDomain := inferEmailDomain(getenv("SKYFORGE_CORP_EMAIL_DOMAIN", ""))
	awsSSOStartURL := strings.TrimSpace(getenv("SKYFORGE_AWS_SSO_START_URL", ""))
	awsSSORegion := strings.TrimSpace(getenv("SKYFORGE_AWS_SSO_REGION", ""))
	awsSSOAccountID := strings.TrimSpace(getenv("SKYFORGE_AWS_SSO_ACCOUNT_ID", ""))
	awsSSORoleName := strings.TrimSpace(getenv("SKYFORGE_AWS_SSO_ROLE_NAME", ""))
	giteaBaseURL := strings.TrimRight(getenv("SKYFORGE_GITEA_URL", ""), "/")
	netboxBaseURL := strings.TrimRight(getenv("SKYFORGE_NETBOX_URL", ""), "/")
	nautobotBaseURL := strings.TrimRight(getenv("SKYFORGE_NAUTOBOT_URL", ""), "/")
	yaadeBaseURL := strings.TrimRight(getenv("SKYFORGE_YAADE_URL", ""), "/")
	oidcIssuerURL := strings.TrimSpace(getenv("SKYFORGE_OIDC_ISSUER_URL", ""))
	oidcClientID := strings.TrimSpace(getOptionalSecret("SKYFORGE_OIDC_CLIENT_ID"))
	oidcClientSecret := strings.TrimSpace(getOptionalSecret("SKYFORGE_OIDC_CLIENT_SECRET"))
	oidcRedirectURL := strings.TrimSpace(getenv("SKYFORGE_OIDC_REDIRECT_URL", ""))
	stateBackend := strings.TrimSpace(getenv("SKYFORGE_STATE_BACKEND", "file"))
	dbHost := strings.TrimSpace(getenv("SKYFORGE_DB_HOST", ""))
	dbPort := 5432
	if raw := strings.TrimSpace(getenv("SKYFORGE_DB_PORT", "")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 65535 {
			dbPort = v
		}
	}
	dbName := strings.TrimSpace(getenv("SKYFORGE_DB_NAME", ""))
	dbUser := strings.TrimSpace(getenv("SKYFORGE_DB_USER", ""))
	dbPassword := strings.TrimSpace(getenv("SKYFORGE_DB_PASSWORD", ""))
	dbPasswordFile := strings.TrimSpace(getenv("SKYFORGE_DB_PASSWORD_FILE", ""))
	dbSSLMode := strings.TrimSpace(getenv("SKYFORGE_DB_SSLMODE", "disable"))

	ldapURL := strings.TrimSpace(getOptionalSecret("SKYFORGE_LDAP_URL"))
	ldapBindTemplate := strings.TrimSpace(getOptionalSecret("SKYFORGE_LDAP_BIND_TEMPLATE"))
	ldapCfg := LDAPConfig{
		URL:             ldapURL,
		BindTemplate:    ldapBindTemplate,
		BaseDN:          getenv("SKYFORGE_LDAP_BASEDN", ""),
		DisplayNameAttr: getenv("SKYFORGE_LDAP_DISPLAY_ATTR", ""),
		MailAttr:        getenv("SKYFORGE_LDAP_MAIL_ATTR", ""),
		GroupAttr:       getenv("SKYFORGE_LDAP_GROUP_ATTR", ""),
		UseStartTLS:     getenv("SKYFORGE_LDAP_STARTTLS", "false") == "true",
		SkipTLSVerify:   getenv("SKYFORGE_LDAP_SKIP_TLS_VERIFY", "false") == "true",
	}
	ldapLookupBindDN := strings.TrimSpace(getOptionalSecret("SKYFORGE_LDAP_LOOKUP_BINDDN"))
	ldapLookupBindPassword := getOptionalSecret("SKYFORGE_LDAP_LOOKUP_BINDPASSWORD")

	netlabCfg := NetlabConfig{
		SSHHost:    getenv("SKYFORGE_NETLAB_SSH_HOST", strings.TrimSpace(skyforgeEncoreCfg.Netlab.SSHHost)),
		SSHUser:    getenv("SKYFORGE_NETLAB_SSH_USER", strings.TrimSpace(skyforgeEncoreCfg.Netlab.SSHUser)),
		SSHKeyFile: getenv("SKYFORGE_NETLAB_SSH_KEY_FILE", strings.TrimSpace(skyforgeEncoreCfg.Netlab.SSHKeyFile)),
		StateRoot:  getenv("SKYFORGE_NETLAB_STATE_ROOT", strings.TrimSpace(skyforgeEncoreCfg.Netlab.StateRoot)),
	}

	labsCfg := LabsConfig{
		PublicURL:        strings.TrimRight(getenv("SKYFORGE_EVE_URL", ""), "/"),
		EveAPIURL:        strings.TrimRight(getenv("SKYFORGE_EVE_API_URL", ""), "/"),
		EveUsername:      getenv("SKYFORGE_EVE_USERNAME", ""),
		EvePassword:      getOptionalSecret("SKYFORGE_EVE_PASSWORD"),
		EveSkipTLSVerify: getenv("SKYFORGE_EVE_SKIP_TLS_VERIFY", "false") == "true",
		EveSSHKeyFile:    getenv("SKYFORGE_EVE_SSH_KEY_FILE", ""),
		EveSSHUser:       getenv("SKYFORGE_EVE_SSH_USER", ""),
		EveSSHTunnel:     getenv("SKYFORGE_EVE_SSH_TUNNEL_ENABLED", "true") == "true",
		EveLabsPath:      getenv("SKYFORGE_EVE_LABS_PATH", "/opt/unetlab/labs"),
		EveTmpPath:       getenv("SKYFORGE_EVE_TMP_PATH", "/opt/unetlab/tmp"),
	}

	labppRunnerImage := strings.TrimSpace(getenv("SKYFORGE_LABPP_RUNNER_IMAGE", strings.TrimSpace(skyforgeEncoreCfg.Labpp.RunnerImage)))
	labppRunnerPullPolicy := strings.TrimSpace(getenv("SKYFORGE_LABPP_RUNNER_PULL_POLICY", strings.TrimSpace(skyforgeEncoreCfg.Labpp.RunnerPullPolicy)))
	labppRunnerPVCName := strings.TrimSpace(getenv("SKYFORGE_LABPP_RUNNER_PVC", strings.TrimSpace(skyforgeEncoreCfg.Labpp.RunnerPVCName)))
	labppConfigDirBase := strings.TrimSpace(getenv("SKYFORGE_LABPP_CONFIG_DIR_BASE", strings.TrimSpace(skyforgeEncoreCfg.Labpp.ConfigDirBase)))
	labppConfigVersion := strings.TrimSpace(getenv("SKYFORGE_LABPP_CONFIG_VERSION", strings.TrimSpace(skyforgeEncoreCfg.Labpp.ConfigVersion)))
	labppNetboxURL := strings.TrimSpace(getenv("SKYFORGE_LABPP_NETBOX_URL", strings.TrimSpace(skyforgeEncoreCfg.Labpp.NetboxURL)))
	labppNetboxUsername := strings.TrimSpace(getOptionalSecret("SKYFORGE_LABPP_NETBOX_USERNAME"))
	labppNetboxPassword := strings.TrimSpace(getOptionalSecret("SKYFORGE_LABPP_NETBOX_PASSWORD"))
	labppNetboxToken := strings.TrimSpace(getOptionalSecret("SKYFORGE_LABPP_NETBOX_TOKEN"))
	labppNetboxMgmtSubnet := strings.TrimSpace(getenv("SKYFORGE_LABPP_NETBOX_MGMT_SUBNET", strings.TrimSpace(skyforgeEncoreCfg.Labpp.NetboxMgmtSubnet)))
	labppS3AccessKey := strings.TrimSpace(getOptionalSecret("SKYFORGE_LABPP_S3_ACCESS_KEY"))
	labppS3SecretKey := strings.TrimSpace(getOptionalSecret("SKYFORGE_LABPP_S3_SECRET_KEY"))
	labppS3Region := strings.TrimSpace(getenv("SKYFORGE_LABPP_S3_REGION", strings.TrimSpace(skyforgeEncoreCfg.Labpp.S3Region)))
	labppS3BucketName := strings.TrimSpace(getenv("SKYFORGE_LABPP_S3_BUCKET", strings.TrimSpace(skyforgeEncoreCfg.Labpp.S3BucketName)))
	labppS3Endpoint := strings.TrimSpace(getenv("SKYFORGE_LABPP_S3_ENDPOINT", strings.TrimSpace(skyforgeEncoreCfg.Labpp.S3Endpoint)))
	labppS3DisableSSL := getenvBool("SKYFORGE_LABPP_S3_DISABLE_SSL", skyforgeEncoreCfg.Labpp.S3DisableSSL)
	labppS3DisableChecksum := getenvBool("SKYFORGE_LABPP_S3_DISABLE_CHECKSUM", skyforgeEncoreCfg.Labpp.S3DisableChecksum)
	yaadeAdminUsername := strings.TrimSpace(getenv("SKYFORGE_YAADE_ADMIN_USERNAME", getenv("YAADE_ADMIN_USERNAME", "admin")))
	yaadeAdminPassword := strings.TrimSpace(getOptionalSecret("YAADE_ADMIN_PASSWORD"))

	containerlabAPIPath := strings.TrimSpace(getenv("SKYFORGE_CONTAINERLAB_API_PATH", "/containerlab"))
	if containerlabAPIPath == "" {
		containerlabAPIPath = "/containerlab"
	}
	if !strings.HasPrefix(containerlabAPIPath, "/") {
		containerlabAPIPath = "/" + containerlabAPIPath
	}
	containerlabJWTSecret := strings.TrimSpace(getOptionalSecret("SKYFORGE_CONTAINERLAB_JWT_SECRET"))
	containerlabSkipTLSVerify := getenv("SKYFORGE_CONTAINERLAB_SKIP_TLS_VERIFY", "false") == "true"

	pkiCACert := strings.TrimSpace(getOptionalSecret("SKYFORGE_PKI_CA_CERT"))
	pkiCAKey := strings.TrimSpace(getOptionalSecret("SKYFORGE_PKI_CA_KEY"))
	pkiDefaultDays := 365
	if raw := strings.TrimSpace(getenv("SKYFORGE_PKI_DEFAULT_DAYS", "")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			pkiDefaultDays = v
		}
	}
	sshCAKey := strings.TrimSpace(getOptionalSecret("SKYFORGE_SSH_CA_KEY"))
	sshDefaultDays := 30
	if raw := strings.TrimSpace(getenv("SKYFORGE_SSH_DEFAULT_DAYS", "")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			sshDefaultDays = v
		}
	}

	dnsURL := strings.TrimRight(strings.TrimSpace(getenv("SKYFORGE_DNS_URL", "http://technitium-dns:5380")), "/")
	dnsAdminUsername := strings.TrimSpace(getenv("SKYFORGE_DNS_ADMIN_USERNAME", "admin"))
	dnsUserZoneSuffix := strings.TrimSpace(getenv("SKYFORGE_DNS_USER_ZONE_SUFFIX", "skyforge"))
	dnsUserZoneSuffix = strings.TrimPrefix(dnsUserZoneSuffix, ".")

	taskWorkerEnabled := getenv("SKYFORGE_TASK_WORKER_ENABLED", strconv.FormatBool(skyforgeEncoreCfg.TaskWorkerEnabled)) == "true"

	eveServersRaw := strings.TrimSpace(os.Getenv("SKYFORGE_EVE_SERVERS_JSON"))
	if eveServersRaw == "" {
		eveServersRaw = readOptionalFile(getenv("SKYFORGE_EVE_SERVERS_FILE", ""))
	}
	eveServers, err := parseEveServers(eveServersRaw)
	if err != nil {
		log.Printf("invalid EVE servers config: %v", err)
	}
	filteredEveServers := make([]EveServerConfig, 0, len(eveServers))
	for _, s := range eveServers {
		s = normalizeEveServer(s, labsCfg)
		if s.Name == "" || (s.APIURL == "" && s.WebURL == "" && s.SSHHost == "") {
			continue
		}
		filteredEveServers = append(filteredEveServers, s)
	}
	if len(filteredEveServers) == 0 && labsCfg.EveAPIURL != "" {
		filteredEveServers = append(filteredEveServers, EveServerConfig{
			Name:          "eve-default",
			APIURL:        labsCfg.EveAPIURL,
			WebURL:        strings.TrimSuffix(strings.TrimRight(labsCfg.EveAPIURL, "/"), "/api"),
			Username:      labsCfg.EveUsername,
			Password:      labsCfg.EvePassword,
			SkipTLSVerify: labsCfg.EveSkipTLSVerify,
			SSHHost: func() string {
				u, _ := url.Parse(labsCfg.EveAPIURL)
				if u != nil {
					return u.Hostname()
				}
				return ""
			}(),
			SSHUser:  labsCfg.EveSSHUser,
			LabsPath: labsCfg.EveLabsPath,
			TmpPath:  labsCfg.EveTmpPath,
		})
	}

	netlabServersRaw := strings.TrimSpace(os.Getenv("SKYFORGE_NETLAB_SERVERS_JSON"))
	if netlabServersRaw == "" {
		netlabServersRaw = readOptionalFile(getenv("SKYFORGE_NETLAB_SERVERS_FILE", ""))
	}
	netlabServers, err := parseNetlabServers(netlabServersRaw)
	if err != nil {
		log.Printf("invalid Netlab servers config: %v", err)
	}
	filteredNetlabServers := make([]NetlabServerConfig, 0, len(netlabServers))
	for _, s := range netlabServers {
		s = normalizeNetlabServer(s, netlabCfg)
		if s.SSHHost == "" || s.SSHKeyFile == "" {
			continue
		}
		filteredNetlabServers = append(filteredNetlabServers, s)
	}
	if len(filteredNetlabServers) == 0 && strings.TrimSpace(netlabCfg.SSHHost) != "" && strings.TrimSpace(netlabCfg.SSHKeyFile) != "" {
		filteredNetlabServers = append(filteredNetlabServers, normalizeNetlabServer(NetlabServerConfig{
			Name:       "netlab-default",
			SSHHost:    netlabCfg.SSHHost,
			SSHUser:    netlabCfg.SSHUser,
			SSHKeyFile: netlabCfg.SSHKeyFile,
			StateRoot:  netlabCfg.StateRoot,
		}, netlabCfg))
	}

	workspacesCfg := WorkspacesConfig{
		DataDir:                         getenv("SKYFORGE_WORKSPACES_DATA_DIR", getenv("SKYFORGE_PROJECTS_DATA_DIR", "/var/lib/skyforge")),
		GiteaAPIURL:                     strings.TrimRight(getenv("SKYFORGE_GITEA_API_URL", ""), "/"),
		GiteaUsername:                   getenv("SKYFORGE_GITEA_USERNAME", getenv("GITEA_ADMIN_USER", "skyforge")),
		GiteaPassword:                   strings.TrimSpace(getOptionalSecret("SKYFORGE_GITEA_PASSWORD")),
		GiteaRepoPrivate:                getenv("SKYFORGE_GITEA_REPO_PRIVATE", "false") == "true",
		DeleteMode:                      strings.TrimSpace(getenv("SKYFORGE_WORKSPACE_DELETE_MODE", getenv("SKYFORGE_PROJECT_DELETE_MODE", "live"))),
		ObjectStorageEndpoint:           strings.TrimRight(getenv("SKYFORGE_OBJECT_STORAGE_ENDPOINT", "minio:9000"), "/"),
		ObjectStorageUseSSL:             getenv("SKYFORGE_OBJECT_STORAGE_USE_SSL", "false") == "true",
		ObjectStorageTerraformAccessKey: strings.TrimSpace(getOptionalSecret("SKYFORGE_OBJECT_STORAGE_TERRAFORM_ACCESS_KEY")),
		ObjectStorageTerraformSecretKey: strings.TrimSpace(getOptionalSecret("SKYFORGE_OBJECT_STORAGE_TERRAFORM_SECRET_KEY")),
	}

	workspaceSyncSeconds := 0
	if raw := strings.TrimSpace(getenv("SKYFORGE_WORKSPACE_SYNC_SECONDS", getenv("SKYFORGE_PROJECT_SYNC_SECONDS", "0"))); raw != "" {
		if val, err := strconv.Atoi(raw); err == nil {
			workspaceSyncSeconds = val
		} else {
			log.Printf("invalid SKYFORGE_WORKSPACE_SYNC_SECONDS: %s", raw)
		}
	}
	uiCfg := UIConfig{
		ProductName:      strings.TrimSpace(getenv("SKYFORGE_UI_PRODUCT_NAME", "Skyforge")),
		ProductSubtitle:  strings.TrimSpace(getenv("SKYFORGE_UI_PRODUCT_SUBTITLE", "Automation Hub")),
		LogoURL:          strings.TrimSpace(getenv("SKYFORGE_UI_LOGO_URL", "")),
		LogoAlt:          strings.TrimSpace(getenv("SKYFORGE_UI_LOGO_ALT", "Skyforge")),
		HeaderBackground: strings.TrimSpace(getenv("SKYFORGE_UI_HEADER_BG_URL", "")),
		SupportText:      strings.TrimSpace(getenv("SKYFORGE_UI_SUPPORT_TEXT", "Need access? Contact your platform admin.")),
		SupportURL:       strings.TrimSpace(getenv("SKYFORGE_UI_SUPPORT_URL", "")),
		ThemeDefault:     strings.TrimSpace(getenv("SKYFORGE_UI_THEME_DEFAULT", "")),
		OIDCEnabled:      strings.TrimSpace(oidcIssuerURL) != "" && strings.TrimSpace(oidcClientID) != "" && strings.TrimSpace(oidcClientSecret) != "" && strings.TrimSpace(oidcRedirectURL) != "",
		OIDCLoginURL:     "/api/skyforge/api/oidc/login",
	}
	notificationsEnabled := getenv("SKYFORGE_NOTIFICATIONS_ENABLED", "true") == "true"
	notificationsInterval := 30 * time.Second
	if skyforgeEncoreCfg.NotificationsIntervalSeconds > 0 && skyforgeEncoreCfg.NotificationsIntervalSeconds <= 3600 {
		notificationsInterval = time.Duration(skyforgeEncoreCfg.NotificationsIntervalSeconds) * time.Second
	}
	if raw := strings.TrimSpace(getenv("SKYFORGE_NOTIFICATIONS_INTERVAL", "")); raw != "" {
		if dur, err := time.ParseDuration(raw); err == nil {
			notificationsInterval = dur
		} else if ms, err := strconv.Atoi(raw); err == nil {
			notificationsInterval = time.Duration(ms) * time.Millisecond
		} else {
			log.Printf("invalid SKYFORGE_NOTIFICATIONS_INTERVAL: %s", raw)
		}
	}
	cloudCredentialChecks := 30 * time.Minute
	if skyforgeEncoreCfg.CloudCheckIntervalMinutes > 0 && skyforgeEncoreCfg.CloudCheckIntervalMinutes <= 24*60 {
		cloudCredentialChecks = time.Duration(skyforgeEncoreCfg.CloudCheckIntervalMinutes) * time.Minute
	}
	if raw := strings.TrimSpace(getenv("SKYFORGE_CLOUD_CHECK_INTERVAL", "")); raw != "" {
		if dur, err := time.ParseDuration(raw); err == nil {
			cloudCredentialChecks = dur
		} else if ms, err := strconv.Atoi(raw); err == nil {
			cloudCredentialChecks = time.Duration(ms) * time.Millisecond
		} else {
			log.Printf("invalid SKYFORGE_CLOUD_CHECK_INTERVAL: %s", raw)
		}
	}

	return Config{
		ListenAddr:            getenv("SKYFORGE_LISTEN_ADDR", ":8085"),
		SessionSecret:         mustGetSecret("SKYFORGE_SESSION_SECRET"),
		SessionTTL:            sessionTTL,
		SessionCookie:         getenv("SKYFORGE_SESSION_COOKIE", "skyforge_session"),
		CookieSecure:          getenv("SKYFORGE_COOKIE_SECURE", "auto"),
		CookieDomain:          strings.TrimSpace(getenv("SKYFORGE_COOKIE_DOMAIN", "")),
		InternalToken:         strings.TrimSpace(getOptionalSecret("SKYFORGE_INTERNAL_TOKEN")),
		StaticRoot:            strings.TrimSpace(getenv("SKYFORGE_STATIC_ROOT", "/opt/skyforge/static")),
		PlatformDataDir:       strings.TrimSpace(getenv("SKYFORGE_PLATFORM_DATA_DIR", "/var/lib/skyforge/platform-data")),
		MaxGroups:             maxGroups,
		AdminUsers:            adminUsers,
		AdminUsername:         adminUsername,
		AdminPassword:         adminPassword,
		WorkspaceSyncSeconds:  workspaceSyncSeconds,
		UI:                    uiCfg,
		NotificationsEnabled:  notificationsEnabled,
		NotificationsInterval: notificationsInterval,
		CloudCredentialChecks: cloudCredentialChecks,
		CorpEmailDomain:       corpEmailDomain,
		AwsSSOAccountID:       awsSSOAccountID,
		AwsSSORoleName:        awsSSORoleName,
		AwsSSOStartURL:        awsSSOStartURL,
		AwsSSORegion:          awsSSORegion,
		GiteaBaseURL:          giteaBaseURL,
		NetboxBaseURL:         netboxBaseURL,
		NautobotBaseURL:       nautobotBaseURL,
		YaadeBaseURL:          yaadeBaseURL,
		OIDC: OIDCConfig{
			IssuerURL:    oidcIssuerURL,
			ClientID:     oidcClientID,
			ClientSecret: oidcClientSecret,
			RedirectURL:  oidcRedirectURL,
		},
		StateBackend:              stateBackend,
		DBHost:                    dbHost,
		DBPort:                    dbPort,
		DBName:                    dbName,
		DBUser:                    dbUser,
		DBPassword:                dbPassword,
		DBPasswordFile:            dbPasswordFile,
		DBSSLMode:                 dbSSLMode,
		Netlab:                    netlabCfg,
		NetlabServers:             filteredNetlabServers,
		Labs:                      labsCfg,
		LDAP:                      ldapCfg,
		LDAPLookupBindDN:          ldapLookupBindDN,
		LDAPLookupBindPassword:    ldapLookupBindPassword,
		Workspaces:                workspacesCfg,
		EveServers:                filteredEveServers,
		LabppRunnerImage:          labppRunnerImage,
		LabppRunnerPullPolicy:     labppRunnerPullPolicy,
		LabppRunnerPVCName:        labppRunnerPVCName,
		LabppConfigDirBase:        labppConfigDirBase,
		LabppConfigVersion:        labppConfigVersion,
		LabppNetboxURL:            labppNetboxURL,
		LabppNetboxUsername:       labppNetboxUsername,
		LabppNetboxPassword:       labppNetboxPassword,
		LabppNetboxToken:          labppNetboxToken,
		LabppNetboxMgmtSubnet:     labppNetboxMgmtSubnet,
		LabppS3AccessKey:          labppS3AccessKey,
		LabppS3SecretKey:          labppS3SecretKey,
		LabppS3Region:             labppS3Region,
		LabppS3BucketName:         labppS3BucketName,
		LabppS3Endpoint:           labppS3Endpoint,
		LabppS3DisableSSL:         labppS3DisableSSL,
		LabppS3DisableChecksum:    labppS3DisableChecksum,
		YaadeAdminUsername:        yaadeAdminUsername,
		YaadeAdminPassword:        yaadeAdminPassword,
		ContainerlabAPIPath:       containerlabAPIPath,
		ContainerlabJWTSecret:     containerlabJWTSecret,
		ContainerlabSkipTLSVerify: containerlabSkipTLSVerify,
		PKICACert:                 pkiCACert,
		PKICAKey:                  pkiCAKey,
		PKIDefaultDays:            pkiDefaultDays,
		SSHCAKey:                  sshCAKey,
		SSHCADefaultDays:          sshDefaultDays,
		DNSURL:                    dnsURL,
		DNSAdminUsername:          dnsAdminUsername,
		DNSUserZoneSuffix:         dnsUserZoneSuffix,
		TaskWorkerEnabled:         taskWorkerEnabled,
	}
}

type workspacesStore interface {
	load() ([]SkyforgeWorkspace, error)
	save(workspaces []SkyforgeWorkspace) error
}

type fileWorkspacesStore struct {
	mu   sync.Mutex
	path string
}

func newFileWorkspacesStore(dataDir string) *fileWorkspacesStore {
	return &fileWorkspacesStore{path: filepath.Join(dataDir, "workspaces.json")}
}

func (ps *fileWorkspacesStore) load() ([]SkyforgeWorkspace, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	content, err := os.ReadFile(ps.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []SkyforgeWorkspace{}, nil
		}
		return nil, err
	}
	var workspaces []SkyforgeWorkspace
	if err := json.Unmarshal(content, &workspaces); err != nil {
		return nil, err
	}
	return workspaces, nil
}

func (ps *fileWorkspacesStore) save(workspaces []SkyforgeWorkspace) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(ps.path), 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(workspaces, "", "  ")
	if err != nil {
		return err
	}
	tmp := ps.path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ps.path)
}

type usersStore interface {
	load() ([]string, error)
	upsert(username string) error
	remove(username string) error
}

type fileUsersStore struct {
	mu   sync.Mutex
	path string
}

func newFileUsersStore(dataDir string) *fileUsersStore {
	return &fileUsersStore{path: filepath.Join(dataDir, "users.json")}
}

func (us *fileUsersStore) load() ([]string, error) {
	us.mu.Lock()
	defer us.mu.Unlock()
	content, err := os.ReadFile(us.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []string{}, nil
		}
		return nil, err
	}
	var users []string
	if err := json.Unmarshal(content, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (us *fileUsersStore) save(users []string) error {
	us.mu.Lock()
	defer us.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(us.path), 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	tmp := us.path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, us.path)
}

func (us *fileUsersStore) upsert(username string) error {
	username = strings.TrimSpace(username)
	if !isValidUsername(username) {
		return nil
	}
	users, err := us.load()
	if err != nil {
		return err
	}
	for _, u := range users {
		if strings.EqualFold(u, username) {
			return nil
		}
	}
	users = append(users, username)
	return us.save(users)
}

func (us *fileUsersStore) remove(username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}
	users, err := us.load()
	if err != nil {
		return err
	}
	next := make([]string, 0, len(users))
	changed := false
	for _, u := range users {
		if strings.EqualFold(strings.TrimSpace(u), username) {
			changed = true
			continue
		}
		next = append(next, u)
	}
	if !changed {
		return nil
	}
	return us.save(next)
}

type secretBox struct {
	key [32]byte
}

func newSecretBox(secret string) *secretBox {
	return &secretBox{key: sha256.Sum256([]byte(secret))}
}

func (sb *secretBox) encrypt(plaintext string) (string, error) {
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(sb.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	out := append(nonce, ciphertext...)
	return "enc:" + base64.RawStdEncoding.EncodeToString(out), nil
}

func (sb *secretBox) decrypt(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, "enc:") {
		return value, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, "enc:"))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(sb.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("invalid encrypted secret")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

type awsSSOTokenRecord struct {
	StartURL               string    `json:"startUrl"`
	Region                 string    `json:"region"`
	ClientID               string    `json:"clientId,omitempty"`
	ClientSecret           string    `json:"clientSecret,omitempty"`
	ClientSecretExpiresAt  time.Time `json:"clientSecretExpiresAt,omitempty"`
	AccessToken            string    `json:"accessToken,omitempty"`
	AccessTokenExpiresAt   time.Time `json:"accessTokenExpiresAt,omitempty"`
	RefreshToken           string    `json:"refreshToken,omitempty"`
	RefreshTokenExpiresAt  time.Time `json:"refreshTokenExpiresAt,omitempty"`
	LastAuthenticatedAtUTC time.Time `json:"lastAuthenticatedAtUtc,omitempty"`
}

type awsSSOTokenStore interface {
	get(username string) (*awsSSOTokenRecord, error)
	put(username string, rec awsSSOTokenRecord) error
	clear(username string) error
	loadAll() (map[string]awsSSOTokenRecord, error)
}

type fileAWSStore struct {
	mu   sync.Mutex
	path string
	box  *secretBox
}

func newFileAWSStore(dataDir string, box *secretBox) *fileAWSStore {
	return &fileAWSStore{path: filepath.Join(dataDir, "aws_sso.json"), box: box}
}

func (s *fileAWSStore) loadAll() (map[string]awsSSOTokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	content, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]awsSSOTokenRecord{}, nil
		}
		return nil, err
	}
	out := map[string]awsSSOTokenRecord{}
	if err := json.Unmarshal(content, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *fileAWSStore) saveAll(records map[string]awsSSOTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *fileAWSStore) get(username string) (*awsSSOTokenRecord, error) {
	records, err := s.loadAll()
	if err != nil {
		return nil, err
	}
	rec, ok := records[username]
	if !ok {
		return nil, nil
	}
	if rec.AccessToken != "" {
		if decrypted, err := s.box.decrypt(rec.AccessToken); err == nil {
			rec.AccessToken = decrypted
		}
	}
	if rec.RefreshToken != "" {
		if decrypted, err := s.box.decrypt(rec.RefreshToken); err == nil {
			rec.RefreshToken = decrypted
		}
	}
	if rec.ClientSecret != "" {
		if decrypted, err := s.box.decrypt(rec.ClientSecret); err == nil {
			rec.ClientSecret = decrypted
		}
	}
	return &rec, nil
}

func (s *fileAWSStore) put(username string, rec awsSSOTokenRecord) error {
	records, err := s.loadAll()
	if err != nil {
		return err
	}
	if rec.AccessToken != "" {
		enc, err := s.box.encrypt(rec.AccessToken)
		if err != nil {
			return err
		}
		rec.AccessToken = enc
	}
	if rec.RefreshToken != "" {
		enc, err := s.box.encrypt(rec.RefreshToken)
		if err != nil {
			return err
		}
		rec.RefreshToken = enc
	}
	if rec.ClientSecret != "" {
		enc, err := s.box.encrypt(rec.ClientSecret)
		if err != nil {
			return err
		}
		rec.ClientSecret = enc
	}
	records[username] = rec
	return s.saveAll(records)
}

func (s *fileAWSStore) clear(username string) error {
	records, err := s.loadAll()
	if err != nil {
		return err
	}
	delete(records, username)
	return s.saveAll(records)
}

type pgUsersStore struct {
	db *sql.DB
}

func newPGUsersStore(db *sql.DB) *pgUsersStore {
	return &pgUsersStore{db: db}
}

func (s *pgUsersStore) load() ([]string, error) {
	rows, err := s.db.Query(`SELECT username FROM sf_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, err
		}
		out = append(out, username)
	}
	return out, rows.Err()
}

func (s *pgUsersStore) upsert(username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if !isValidUsername(username) {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO sf_users (username, last_seen_at) VALUES ($1, now())
ON CONFLICT (username) DO UPDATE SET last_seen_at=excluded.last_seen_at`, username)
	return err
}

func (s *pgUsersStore) remove(username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM sf_users WHERE username = $1`, username)
	return err
}

type pgAWSStore struct {
	db  *sql.DB
	box *secretBox
}

func newPGAWSStore(db *sql.DB, box *secretBox) *pgAWSStore {
	return &pgAWSStore{db: db, box: box}
}

func encryptIfPlain(box *secretBox, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, "enc:") {
		return value, nil
	}
	return box.encrypt(value)
}

func nullIfEmpty(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func (s *pgAWSStore) loadAll() (map[string]awsSSOTokenRecord, error) {
	rows, err := s.db.Query(`SELECT username, start_url, region, client_id, client_secret, client_secret_expires_at,
access_token, access_token_expires_at, refresh_token, refresh_token_expires_at, last_authenticated_at_utc
FROM sf_aws_sso_tokens`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]awsSSOTokenRecord{}
	for rows.Next() {
		var (
			username, startURL, region                                         string
			clientID                                                           sql.NullString
			clientSecret, accessToken, refreshToken                            sql.NullString
			clientSecretExpiresAt, accessTokenExpiresAt, refreshTokenExpiresAt sql.NullTime
			lastAuthenticatedAt                                                sql.NullTime
		)
		if err := rows.Scan(&username, &startURL, &region, &clientID, &clientSecret, &clientSecretExpiresAt, &accessToken, &accessTokenExpiresAt, &refreshToken, &refreshTokenExpiresAt, &lastAuthenticatedAt); err != nil {
			return nil, err
		}
		rec := awsSSOTokenRecord{
			StartURL:     startURL,
			Region:       region,
			ClientID:     clientID.String,
			ClientSecret: clientSecret.String,
			AccessToken:  accessToken.String,
			RefreshToken: refreshToken.String,
		}
		if clientSecretExpiresAt.Valid {
			rec.ClientSecretExpiresAt = clientSecretExpiresAt.Time
		}
		if accessTokenExpiresAt.Valid {
			rec.AccessTokenExpiresAt = accessTokenExpiresAt.Time
		}
		if refreshTokenExpiresAt.Valid {
			rec.RefreshTokenExpiresAt = refreshTokenExpiresAt.Time
		}
		if lastAuthenticatedAt.Valid {
			rec.LastAuthenticatedAtUTC = lastAuthenticatedAt.Time
		}
		out[username] = rec
	}
	return out, rows.Err()
}

func (s *pgAWSStore) get(username string) (*awsSSOTokenRecord, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	var (
		startURL, region                                                   string
		clientID                                                           sql.NullString
		clientSecret, accessToken, refreshToken                            sql.NullString
		clientSecretExpiresAt, accessTokenExpiresAt, refreshTokenExpiresAt sql.NullTime
		lastAuthenticatedAt                                                sql.NullTime
	)
	err := s.db.QueryRow(`SELECT start_url, region, client_id, client_secret, client_secret_expires_at,
access_token, access_token_expires_at, refresh_token, refresh_token_expires_at, last_authenticated_at_utc
FROM sf_aws_sso_tokens WHERE username=$1`, username).Scan(
		&startURL, &region, &clientID, &clientSecret, &clientSecretExpiresAt,
		&accessToken, &accessTokenExpiresAt, &refreshToken, &refreshTokenExpiresAt, &lastAuthenticatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	rec := awsSSOTokenRecord{
		StartURL:     startURL,
		Region:       region,
		ClientID:     clientID.String,
		ClientSecret: clientSecret.String,
		AccessToken:  accessToken.String,
		RefreshToken: refreshToken.String,
	}
	if clientSecretExpiresAt.Valid {
		rec.ClientSecretExpiresAt = clientSecretExpiresAt.Time
	}
	if accessTokenExpiresAt.Valid {
		rec.AccessTokenExpiresAt = accessTokenExpiresAt.Time
	}
	if refreshTokenExpiresAt.Valid {
		rec.RefreshTokenExpiresAt = refreshTokenExpiresAt.Time
	}
	if lastAuthenticatedAt.Valid {
		rec.LastAuthenticatedAtUTC = lastAuthenticatedAt.Time
	}
	if rec.AccessToken != "" {
		if decrypted, err := s.box.decrypt(rec.AccessToken); err == nil {
			rec.AccessToken = decrypted
		}
	}
	if rec.RefreshToken != "" {
		if decrypted, err := s.box.decrypt(rec.RefreshToken); err == nil {
			rec.RefreshToken = decrypted
		}
	}
	if rec.ClientSecret != "" {
		if decrypted, err := s.box.decrypt(rec.ClientSecret); err == nil {
			rec.ClientSecret = decrypted
		}
	}
	return &rec, nil
}

func (s *pgAWSStore) put(username string, rec awsSSOTokenRecord) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return fmt.Errorf("username is required")
	}
	isSystemKey := strings.HasPrefix(username, "__client__:")
	if !isSystemKey && !isValidUsername(username) {
		return nil
	}
	if !isSystemKey {
		if _, err := s.db.Exec(`INSERT INTO sf_users (username) VALUES ($1) ON CONFLICT (username) DO NOTHING`, username); err != nil {
			return err
		}
	}

	clientSecret, err := encryptIfPlain(s.box, rec.ClientSecret)
	if err != nil {
		return err
	}
	accessToken, err := encryptIfPlain(s.box, rec.AccessToken)
	if err != nil {
		return err
	}
	refreshToken, err := encryptIfPlain(s.box, rec.RefreshToken)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`INSERT INTO sf_aws_sso_tokens (
  username, start_url, region, client_id, client_secret, client_secret_expires_at,
  access_token, access_token_expires_at, refresh_token, refresh_token_expires_at, last_authenticated_at_utc, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())
ON CONFLICT (username) DO UPDATE SET
  start_url=excluded.start_url,
  region=excluded.region,
  client_id=excluded.client_id,
  client_secret=excluded.client_secret,
  client_secret_expires_at=excluded.client_secret_expires_at,
  access_token=excluded.access_token,
  access_token_expires_at=excluded.access_token_expires_at,
  refresh_token=excluded.refresh_token,
  refresh_token_expires_at=excluded.refresh_token_expires_at,
  last_authenticated_at_utc=excluded.last_authenticated_at_utc,
  updated_at=now()`,
		username, strings.TrimSpace(rec.StartURL), strings.TrimSpace(rec.Region), nullIfEmpty(strings.TrimSpace(rec.ClientID)),
		nullIfEmpty(clientSecret), nullTime(rec.ClientSecretExpiresAt),
		nullIfEmpty(accessToken), nullTime(rec.AccessTokenExpiresAt),
		nullIfEmpty(refreshToken), nullTime(rec.RefreshTokenExpiresAt),
		nullTime(rec.LastAuthenticatedAtUTC),
	)
	return err
}

func (s *pgAWSStore) clear(username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM sf_aws_sso_tokens WHERE username=$1`, username)
	return err
}

type pgWorkspacesStore struct {
	db *sql.DB
}

func newPGWorkspacesStore(db *sql.DB) *pgWorkspacesStore {
	return &pgWorkspacesStore{db: db}
}

type awsStaticCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	UpdatedAt       time.Time
}

type azureServicePrincipal struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
	UpdatedAt      time.Time
}

type gcpServiceAccount struct {
	ServiceAccountJSON string
	ProjectIDOverride  string
	UpdatedAt          time.Time
}

type AuditEvent struct {
	ID               int64     `json:"id"`
	CreatedAt        time.Time `json:"createdAt"`
	ActorUsername    string    `json:"actorUsername"`
	ActorIsAdmin     bool      `json:"actorIsAdmin"`
	ImpersonatedUser string    `json:"impersonatedUsername,omitempty"`
	Action           string    `json:"action"`
	WorkspaceID      string    `json:"workspaceId,omitempty"`
	Details          string    `json:"details,omitempty"`
}

func auditRequestDetails(r *http.Request) string {
	if r == nil {
		return ""
	}
	ip := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if ip == "" {
		ip = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	details := map[string]any{
		"method": r.Method,
		"path":   r.URL.Path,
		"host":   r.Host,
		"proto":  r.Proto,
		"ip":     ip,
		"ua":     r.UserAgent(),
	}
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); v != "" {
		details["x_forwarded_proto"] = v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); v != "" {
		details["x_forwarded_host"] = v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Uri")); v != "" {
		details["x_forwarded_uri"] = v
	}
	if v := strings.TrimSpace(r.Referer()); v != "" {
		details["referer"] = v
	}
	b, _ := json.Marshal(details)
	return string(b)
}

func ensureAuditActor(ctx context.Context, db *sql.DB, username string) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" || db == nil {
		return
	}
	_, _ = db.ExecContext(ctx, `INSERT INTO sf_users (username, created_at) VALUES ($1, now()) ON CONFLICT (username) DO NOTHING`, username)
}

func writeAuditEvent(ctx context.Context, db *sql.DB, actor string, actorIsAdmin bool, impersonated string, action string, workspaceID string, details string) {
	if db == nil {
		return
	}
	actor = strings.ToLower(strings.TrimSpace(actor))
	impersonated = strings.ToLower(strings.TrimSpace(impersonated))
	action = strings.TrimSpace(action)
	workspaceID = strings.TrimSpace(workspaceID)
	details = strings.TrimSpace(details)
	if actor == "" || action == "" {
		return
	}
	ensureAuditActor(ctx, db, actor)
	if impersonated != "" {
		ensureAuditActor(ctx, db, impersonated)
	}
	if len(details) > 4000 {
		details = details[:4000]
	}
	_, err := db.ExecContext(ctx, `INSERT INTO sf_audit_log (
  actor_username, actor_is_admin, impersonated_username, action, workspace_id, details
) VALUES ($1,$2,NULLIF($3,''),$4,NULLIF($5,''),NULLIF($6,''))`,
		actor, actorIsAdmin, impersonated, action, workspaceID, details,
	)
	if err != nil {
		log.Printf("audit log insert failed: %v", err)
	}
}

func getWorkspaceAWSStaticCredentials(ctx context.Context, db *sql.DB, box *secretBox, workspaceID string) (*awsStaticCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, fmt.Errorf("workspace id is required")
	}
	var akid, sak, st sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT access_key_id, secret_access_key, session_token, updated_at
FROM sf_workspace_aws_static_credentials WHERE workspace_id=$1`, workspaceID).Scan(&akid, &sak, &st, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	accessKeyID, err := box.decrypt(akid.String)
	if err != nil {
		return nil, err
	}
	secretAccessKey, err := box.decrypt(sak.String)
	if err != nil {
		return nil, err
	}
	sessionToken, err := box.decrypt(st.String)
	if err != nil {
		return nil, err
	}
	rec := &awsStaticCredentials{
		AccessKeyID:     strings.TrimSpace(accessKeyID),
		SecretAccessKey: strings.TrimSpace(secretAccessKey),
		SessionToken:    strings.TrimSpace(sessionToken),
	}
	if updatedAt.Valid {
		rec.UpdatedAt = updatedAt.Time
	}
	return rec, nil
}

func putWorkspaceAWSStaticCredentials(ctx context.Context, db *sql.DB, box *secretBox, workspaceID string, accessKeyID string, secretAccessKey string, sessionToken string) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	accessKeyID = strings.TrimSpace(accessKeyID)
	secretAccessKey = strings.TrimSpace(secretAccessKey)
	sessionToken = strings.TrimSpace(sessionToken)
	if workspaceID == "" {
		return fmt.Errorf("workspace id is required")
	}
	if accessKeyID == "" || secretAccessKey == "" {
		return fmt.Errorf("accessKeyId and secretAccessKey are required")
	}
	encAKID, err := encryptIfPlain(box, accessKeyID)
	if err != nil {
		return err
	}
	encSAK, err := encryptIfPlain(box, secretAccessKey)
	if err != nil {
		return err
	}
	encST, err := encryptIfPlain(box, sessionToken)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_workspace_aws_static_credentials (workspace_id, access_key_id, secret_access_key, session_token, updated_at)
VALUES ($1,$2,$3,NULLIF($4,''),now())
ON CONFLICT (workspace_id) DO UPDATE SET
  access_key_id=excluded.access_key_id,
  secret_access_key=excluded.secret_access_key,
  session_token=excluded.session_token,
  updated_at=now()`, workspaceID, encAKID, encSAK, encST)
	return err
}

func deleteWorkspaceAWSStaticCredentials(ctx context.Context, db *sql.DB, workspaceID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_workspace_aws_static_credentials WHERE workspace_id=$1`, workspaceID)
	return err
}

type forwardCredentials struct {
	BaseURL        string
	Username       string
	Password       string
	CollectorID    string
	CollectorUser  string
	DeviceUsername string
	DevicePassword string
	JumpHost       string
	JumpUsername   string
	JumpPrivateKey string
	JumpCert       string
	UpdatedAt      time.Time
}

func getWorkspaceForwardCredentials(ctx context.Context, db *sql.DB, box *secretBox, workspaceID string) (*forwardCredentials, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, fmt.Errorf("workspace id is required")
	}
	var baseURL, username, password sql.NullString
	var collectorID, collectorUser sql.NullString
	var deviceUser, devicePass sql.NullString
	var jumpHost, jumpUser, jumpKey, jumpCert sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT base_url, username, password,
  COALESCE(collector_id, ''), COALESCE(collector_username, ''),
  COALESCE(device_username, ''), COALESCE(device_password, ''),
  COALESCE(jump_host, ''), COALESCE(jump_username, ''), COALESCE(jump_private_key, ''), COALESCE(jump_cert, ''),
  updated_at
FROM sf_workspace_forward_credentials WHERE workspace_id=$1`, workspaceID).Scan(
		&baseURL,
		&username,
		&password,
		&collectorID,
		&collectorUser,
		&deviceUser,
		&devicePass,
		&jumpHost,
		&jumpUser,
		&jumpKey,
		&jumpCert,
		&updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	baseURLValue, err := box.decrypt(baseURL.String)
	if err != nil {
		return nil, err
	}
	usernameValue, err := box.decrypt(username.String)
	if err != nil {
		return nil, err
	}
	passwordValue, err := box.decrypt(password.String)
	if err != nil {
		return nil, err
	}
	collectorIDValue, err := box.decrypt(collectorID.String)
	if err != nil {
		return nil, err
	}
	collectorUserValue, err := box.decrypt(collectorUser.String)
	if err != nil {
		return nil, err
	}
	deviceUserValue, err := box.decrypt(deviceUser.String)
	if err != nil {
		return nil, err
	}
	devicePassValue, err := box.decrypt(devicePass.String)
	if err != nil {
		return nil, err
	}
	jumpHostValue, err := box.decrypt(jumpHost.String)
	if err != nil {
		return nil, err
	}
	jumpUserValue, err := box.decrypt(jumpUser.String)
	if err != nil {
		return nil, err
	}
	jumpKeyValue, err := box.decrypt(jumpKey.String)
	if err != nil {
		return nil, err
	}
	jumpCertValue, err := box.decrypt(jumpCert.String)
	if err != nil {
		return nil, err
	}
	rec := &forwardCredentials{
		BaseURL:        strings.TrimSpace(baseURLValue),
		Username:       strings.TrimSpace(usernameValue),
		Password:       strings.TrimSpace(passwordValue),
		CollectorID:    strings.TrimSpace(collectorIDValue),
		CollectorUser:  strings.TrimSpace(collectorUserValue),
		DeviceUsername: strings.TrimSpace(deviceUserValue),
		DevicePassword: strings.TrimSpace(devicePassValue),
		JumpHost:       strings.TrimSpace(jumpHostValue),
		JumpUsername:   strings.TrimSpace(jumpUserValue),
		JumpPrivateKey: strings.TrimSpace(jumpKeyValue),
		JumpCert:       strings.TrimSpace(jumpCertValue),
	}
	if updatedAt.Valid {
		rec.UpdatedAt = updatedAt.Time
	}
	return rec, nil
}

func putWorkspaceForwardCredentials(ctx context.Context, db *sql.DB, box *secretBox, workspaceID string, rec forwardCredentials) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return fmt.Errorf("workspace id is required")
	}
	baseURL := strings.TrimSpace(rec.BaseURL)
	username := strings.TrimSpace(rec.Username)
	password := strings.TrimSpace(rec.Password)
	if baseURL == "" || username == "" || password == "" {
		return fmt.Errorf("baseUrl, username, and password are required")
	}
	encBaseURL, err := encryptIfPlain(box, baseURL)
	if err != nil {
		return err
	}
	encUser, err := encryptIfPlain(box, username)
	if err != nil {
		return err
	}
	encPass, err := encryptIfPlain(box, password)
	if err != nil {
		return err
	}
	encCollectorID, err := encryptIfPlain(box, rec.CollectorID)
	if err != nil {
		return err
	}
	encCollectorUser, err := encryptIfPlain(box, rec.CollectorUser)
	if err != nil {
		return err
	}
	encDeviceUser, err := encryptIfPlain(box, rec.DeviceUsername)
	if err != nil {
		return err
	}
	encDevicePass, err := encryptIfPlain(box, rec.DevicePassword)
	if err != nil {
		return err
	}
	encJumpHost, err := encryptIfPlain(box, rec.JumpHost)
	if err != nil {
		return err
	}
	encJumpUser, err := encryptIfPlain(box, rec.JumpUsername)
	if err != nil {
		return err
	}
	encJumpKey, err := encryptIfPlain(box, rec.JumpPrivateKey)
	if err != nil {
		return err
	}
	encJumpCert, err := encryptIfPlain(box, rec.JumpCert)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_workspace_forward_credentials (
  workspace_id, base_url, username, password,
  collector_id, collector_username,
  device_username, device_password,
  jump_host, jump_username, jump_private_key, jump_cert,
  updated_at
) VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),NULLIF($8,''),NULLIF($9,''),NULLIF($10,''),NULLIF($11,''),NULLIF($12,''),now())
ON CONFLICT (workspace_id) DO UPDATE SET
  base_url=excluded.base_url,
  username=excluded.username,
  password=excluded.password,
  collector_id=excluded.collector_id,
  collector_username=excluded.collector_username,
  device_username=excluded.device_username,
  device_password=excluded.device_password,
  jump_host=excluded.jump_host,
  jump_username=excluded.jump_username,
  jump_private_key=excluded.jump_private_key,
  jump_cert=excluded.jump_cert,
  updated_at=now()`,
		workspaceID,
		encBaseURL,
		encUser,
		encPass,
		encCollectorID,
		encCollectorUser,
		encDeviceUser,
		encDevicePass,
		encJumpHost,
		encJumpUser,
		encJumpKey,
		encJumpCert,
	)
	return err
}

func deleteWorkspaceForwardCredentials(ctx context.Context, db *sql.DB, workspaceID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_workspace_forward_credentials WHERE workspace_id=$1`, workspaceID)
	return err
}

func getWorkspaceAzureCredentials(ctx context.Context, db *sql.DB, box *secretBox, workspaceID string) (*azureServicePrincipal, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, fmt.Errorf("workspace id is required")
	}
	var tenantID, clientID, clientSecret, subscriptionID sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT tenant_id, client_id, client_secret, COALESCE(subscription_id, ''), updated_at
FROM sf_workspace_azure_credentials WHERE workspace_id=$1`, workspaceID).Scan(&tenantID, &clientID, &clientSecret, &subscriptionID, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	tenantValue, err := box.decrypt(tenantID.String)
	if err != nil {
		return nil, err
	}
	clientValue, err := box.decrypt(clientID.String)
	if err != nil {
		return nil, err
	}
	secretValue, err := box.decrypt(clientSecret.String)
	if err != nil {
		return nil, err
	}
	subscriptionValue := strings.TrimSpace(subscriptionID.String)
	if subscriptionValue != "" {
		if decrypted, err := box.decrypt(subscriptionValue); err == nil {
			subscriptionValue = decrypted
		}
	}
	rec := &azureServicePrincipal{
		TenantID:       strings.TrimSpace(tenantValue),
		ClientID:       strings.TrimSpace(clientValue),
		ClientSecret:   strings.TrimSpace(secretValue),
		SubscriptionID: strings.TrimSpace(subscriptionValue),
	}
	if updatedAt.Valid {
		rec.UpdatedAt = updatedAt.Time
	}
	return rec, nil
}

func putWorkspaceAzureCredentials(ctx context.Context, db *sql.DB, box *secretBox, workspaceID string, cred azureServicePrincipal) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return fmt.Errorf("workspace id is required")
	}
	cred.TenantID = strings.TrimSpace(cred.TenantID)
	cred.ClientID = strings.TrimSpace(cred.ClientID)
	cred.ClientSecret = strings.TrimSpace(cred.ClientSecret)
	cred.SubscriptionID = strings.TrimSpace(cred.SubscriptionID)
	if cred.TenantID == "" || cred.ClientID == "" || cred.ClientSecret == "" {
		return fmt.Errorf("tenantId, clientId, and clientSecret are required")
	}
	encTenant, err := encryptIfPlain(box, cred.TenantID)
	if err != nil {
		return err
	}
	encClient, err := encryptIfPlain(box, cred.ClientID)
	if err != nil {
		return err
	}
	encSecret, err := encryptIfPlain(box, cred.ClientSecret)
	if err != nil {
		return err
	}
	encSubscription := ""
	if cred.SubscriptionID != "" {
		encSubscription, err = encryptIfPlain(box, cred.SubscriptionID)
		if err != nil {
			return err
		}
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_workspace_azure_credentials (
  workspace_id, tenant_id, client_id, client_secret, subscription_id, updated_at
) VALUES ($1,$2,$3,$4,NULLIF($5,''),now())
ON CONFLICT (workspace_id) DO UPDATE SET
  tenant_id=excluded.tenant_id,
  client_id=excluded.client_id,
  client_secret=excluded.client_secret,
  subscription_id=excluded.subscription_id,
  updated_at=now()`, workspaceID, encTenant, encClient, encSecret, encSubscription)
	return err
}

func deleteWorkspaceAzureCredentials(ctx context.Context, db *sql.DB, workspaceID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_workspace_azure_credentials WHERE workspace_id=$1`, workspaceID)
	return err
}

func getWorkspaceGCPCredentials(ctx context.Context, db *sql.DB, box *secretBox, workspaceID string) (*gcpServiceAccount, error) {
	if db == nil || box == nil {
		return nil, fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, fmt.Errorf("workspace id is required")
	}
	var raw sql.NullString
	var projectOverride sql.NullString
	var updatedAt sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT service_account_json, COALESCE(project_id_override, ''), updated_at
FROM sf_workspace_gcp_credentials WHERE workspace_id=$1`, workspaceID).Scan(&raw, &projectOverride, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	decoded, err := box.decrypt(raw.String)
	if err != nil {
		return nil, err
	}
	rec := &gcpServiceAccount{ServiceAccountJSON: strings.TrimSpace(decoded), ProjectIDOverride: strings.TrimSpace(projectOverride.String)}
	if updatedAt.Valid {
		rec.UpdatedAt = updatedAt.Time
	}
	return rec, nil
}

func putWorkspaceGCPCredentials(ctx context.Context, db *sql.DB, box *secretBox, workspaceID string, jsonBlob string, projectOverride string) error {
	if db == nil || box == nil {
		return fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	jsonBlob = strings.TrimSpace(jsonBlob)
	projectOverride = strings.TrimSpace(projectOverride)
	if workspaceID == "" {
		return fmt.Errorf("workspace id is required")
	}
	if jsonBlob == "" {
		return fmt.Errorf("service account json is required")
	}
	encJSON, err := encryptIfPlain(box, jsonBlob)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sf_workspace_gcp_credentials (
  workspace_id, service_account_json, project_id_override, updated_at
) VALUES ($1,$2,NULLIF($3,''),now())
ON CONFLICT (workspace_id) DO UPDATE SET
  service_account_json=excluded.service_account_json,
  project_id_override=excluded.project_id_override,
  updated_at=now()`, workspaceID, encJSON, projectOverride)
	return err
}

func deleteWorkspaceGCPCredentials(ctx context.Context, db *sql.DB, workspaceID string) error {
	if db == nil {
		return fmt.Errorf("db is not configured")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM sf_workspace_gcp_credentials WHERE workspace_id=$1`, workspaceID)
	return err
}

func (s *pgWorkspacesStore) load() ([]SkyforgeWorkspace, error) {
	rows, err := s.db.Query(`SELECT id, slug, name, description, created_at, created_by,
		blueprint, default_branch, terraform_state_key, terraform_init_template_id, terraform_plan_template_id, terraform_apply_template_id, ansible_run_template_id, netlab_run_template_id, labpp_run_template_id, containerlab_run_template_id,
		aws_account_id, aws_role_name, aws_region, aws_auth_method, artifacts_bucket, is_public,
		eve_server, netlab_server, legacy_workspace_id, gitea_owner, gitea_repo
	FROM sf_workspaces ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	workspaces := []SkyforgeWorkspace{}
	workspaceByID := map[string]*SkyforgeWorkspace{}
	for rows.Next() {
		var (
			id, slug, name, createdBy                                                                      string
			description, blueprint, defaultBranch                                                          sql.NullString
			terraformStateKey                                                                              sql.NullString
			terraformInit, terraformPlan, terraformApply, ansibleRun, netlabRun, labppRun, containerlabRun sql.NullInt64
			awsAccountID, awsRoleName, awsRegion, awsAuthMethod                                            sql.NullString
			artifactsBucket                                                                                sql.NullString
			isPublic                                                                                       bool
			eveServer                                                                                      sql.NullString
			netlabServer                                                                                   sql.NullString
			createdAt                                                                                      time.Time
			legacyWorkspaceID                                                                              int
			giteaOwner, giteaRepo                                                                          string
		)
		if err := rows.Scan(&id, &slug, &name, &description, &createdAt, &createdBy,
			&blueprint, &defaultBranch, &terraformStateKey, &terraformInit, &terraformPlan, &terraformApply, &ansibleRun, &netlabRun, &labppRun, &containerlabRun,
			&awsAccountID, &awsRoleName, &awsRegion, &awsAuthMethod, &artifactsBucket, &isPublic,
			&eveServer, &netlabServer, &legacyWorkspaceID, &giteaOwner, &giteaRepo,
		); err != nil {
			return nil, err
		}
		p := SkyforgeWorkspace{
			ID:                        id,
			Slug:                      slug,
			Name:                      name,
			Description:               description.String,
			CreatedAt:                 createdAt,
			CreatedBy:                 createdBy,
			Blueprint:                 blueprint.String,
			DefaultBranch:             defaultBranch.String,
			TerraformStateKey:         terraformStateKey.String,
			TerraformInitTemplateID:   int(terraformInit.Int64),
			TerraformPlanTemplateID:   int(terraformPlan.Int64),
			TerraformApplyTemplateID:  int(terraformApply.Int64),
			AnsibleRunTemplateID:      int(ansibleRun.Int64),
			NetlabRunTemplateID:       int(netlabRun.Int64),
			LabppRunTemplateID:        int(labppRun.Int64),
			ContainerlabRunTemplateID: int(containerlabRun.Int64),
			AWSAccountID:              awsAccountID.String,
			AWSRoleName:               awsRoleName.String,
			AWSRegion:                 awsRegion.String,
			AWSAuthMethod:             awsAuthMethod.String,
			ArtifactsBucket:           artifactsBucket.String,
			IsPublic:                  isPublic,
			EveServer:                 eveServer.String,
			NetlabServer:              netlabServer.String,
			LegacyWorkspaceID:         legacyWorkspaceID,
			GiteaOwner:                giteaOwner,
			GiteaRepo:                 giteaRepo,
		}
		workspaces = append(workspaces, p)
		workspaceByID[id] = &workspaces[len(workspaces)-1]
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	memberRows, err := s.db.Query(`SELECT workspace_id, username, role FROM sf_workspace_members ORDER BY workspace_id, username`)
	if err != nil {
		return nil, err
	}
	defer memberRows.Close()
	for memberRows.Next() {
		var workspaceID, username, role string
		if err := memberRows.Scan(&workspaceID, &username, &role); err != nil {
			return nil, err
		}
		p := workspaceByID[workspaceID]
		if p == nil {
			continue
		}
		switch role {
		case "owner":
			p.Owners = append(p.Owners, username)
		case "editor":
			p.Editors = append(p.Editors, username)
		case "viewer":
			p.Viewers = append(p.Viewers, username)
		}
	}
	if err := memberRows.Err(); err != nil {
		return nil, err
	}

	groupRows, err := s.db.Query(`SELECT workspace_id, group_name, role FROM sf_workspace_groups ORDER BY workspace_id, group_name`)
	if err != nil {
		return nil, err
	}
	defer groupRows.Close()
	for groupRows.Next() {
		var workspaceID, groupName, role string
		if err := groupRows.Scan(&workspaceID, &groupName, &role); err != nil {
			return nil, err
		}
		p := workspaceByID[workspaceID]
		if p == nil {
			continue
		}
		switch role {
		case "owner":
			p.OwnerGroups = append(p.OwnerGroups, groupName)
		case "editor":
			p.EditorGroups = append(p.EditorGroups, groupName)
		case "viewer":
			p.ViewerGroups = append(p.ViewerGroups, groupName)
		}
	}
	if err := groupRows.Err(); err != nil {
		return nil, err
	}
	return workspaces, nil
}

func (s *pgWorkspacesStore) save(workspaces []SkyforgeWorkspace) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`DELETE FROM sf_workspace_members`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sf_workspace_groups`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sf_workspaces`); err != nil {
		return err
	}

	ensureUser := func(username string) error {
		username = strings.ToLower(strings.TrimSpace(username))
		if username == "" || !isValidUsername(username) {
			return nil
		}
		_, err := tx.Exec(`INSERT INTO sf_users (username) VALUES ($1) ON CONFLICT (username) DO NOTHING`, username)
		return err
	}

	for _, p := range workspaces {
		if err := ensureUser(p.CreatedBy); err != nil {
			return err
		}
		for _, u := range append(append([]string{}, p.Owners...), append(p.Editors, p.Viewers...)...) {
			if err := ensureUser(u); err != nil {
				return err
			}
		}
	}

	for _, p := range workspaces {
		id := strings.TrimSpace(p.ID)
		if id == "" {
			return fmt.Errorf("workspace id is required")
		}
		slug := strings.TrimSpace(p.Slug)
		if slug == "" {
			slug = slugify(p.Name)
		}
		createdBy := strings.ToLower(strings.TrimSpace(p.CreatedBy))
		if createdBy == "" {
			return fmt.Errorf("workspace createdBy is required")
		}
		if _, err := tx.Exec(`INSERT INTO sf_workspaces (
		  id, slug, name, description, created_at, created_by,
		  blueprint, default_branch, terraform_state_key, terraform_init_template_id, terraform_plan_template_id, terraform_apply_template_id, ansible_run_template_id, netlab_run_template_id, labpp_run_template_id, containerlab_run_template_id,
		  aws_account_id, aws_role_name, aws_region, aws_auth_method, artifacts_bucket, is_public,
		  eve_server, netlab_server, legacy_workspace_id, gitea_owner, gitea_repo, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,now())`,
			id, slug, strings.TrimSpace(p.Name), nullIfEmpty(strings.TrimSpace(p.Description)), p.CreatedAt.UTC(), createdBy,
			nullIfEmpty(strings.TrimSpace(p.Blueprint)), nullIfEmpty(strings.TrimSpace(p.DefaultBranch)),
			nullIfEmpty(strings.TrimSpace(p.TerraformStateKey)), p.TerraformInitTemplateID, p.TerraformPlanTemplateID, p.TerraformApplyTemplateID, p.AnsibleRunTemplateID, p.NetlabRunTemplateID, p.LabppRunTemplateID, p.ContainerlabRunTemplateID,
			nullIfEmpty(strings.TrimSpace(p.AWSAccountID)), nullIfEmpty(strings.TrimSpace(p.AWSRoleName)), nullIfEmpty(strings.TrimSpace(p.AWSRegion)),
			nullIfEmpty(strings.TrimSpace(p.AWSAuthMethod)), nullIfEmpty(strings.TrimSpace(p.ArtifactsBucket)), p.IsPublic,
			nullIfEmpty(strings.TrimSpace(p.EveServer)), nullIfEmpty(strings.TrimSpace(p.NetlabServer)),
			p.LegacyWorkspaceID, strings.TrimSpace(p.GiteaOwner), strings.TrimSpace(p.GiteaRepo),
		); err != nil {
			return err
		}

		owners := normalizeUsernameList(p.Owners)
		ownerGroups := normalizeGroupList(p.OwnerGroups)
		editors := normalizeUsernameList(p.Editors)
		editorGroups := normalizeGroupList(p.EditorGroups)
		viewers := normalizeUsernameList(p.Viewers)
		viewerGroups := normalizeGroupList(p.ViewerGroups)
		if len(owners) == 0 && createdBy != "" {
			owners = []string{createdBy}
		}

		insertMember := func(username, role string) error {
			username = strings.ToLower(strings.TrimSpace(username))
			if username == "" || !isValidUsername(username) {
				return nil
			}
			_, err := tx.Exec(`INSERT INTO sf_workspace_members (workspace_id, username, role) VALUES ($1,$2,$3)`, id, username, role)
			return err
		}
		for _, u := range owners {
			if err := insertMember(u, "owner"); err != nil {
				return err
			}
		}
		for _, u := range editors {
			if err := insertMember(u, "editor"); err != nil {
				return err
			}
		}
		for _, u := range viewers {
			if err := insertMember(u, "viewer"); err != nil {
				return err
			}
		}

		insertGroup := func(groupName, role string) error {
			groupName = strings.TrimSpace(groupName)
			if groupName == "" || len(groupName) > 512 {
				return nil
			}
			_, err := tx.Exec(`INSERT INTO sf_workspace_groups (workspace_id, group_name, role) VALUES ($1,$2,$3)`, id, groupName, role)
			return err
		}
		for _, g := range ownerGroups {
			if err := insertGroup(g, "owner"); err != nil {
				return err
			}
		}
		for _, g := range editorGroups {
			if err := insertGroup(g, "editor"); err != nil {
				return err
			}
		}
		for _, g := range viewerGroups {
			if err := insertGroup(g, "viewer"); err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func readFileSecret(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func openSkyforgeDB(cfg Config) (*sql.DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	explicitDBConfigured := strings.TrimSpace(cfg.DBHost) != "" &&
		strings.TrimSpace(cfg.DBName) != "" &&
		strings.TrimSpace(cfg.DBUser) != ""
	if explicitDBConfigured {
		return openSkyforgeExplicitDB(cfg)
	}
	if db, err := openSkyforgeEncoreDB(ctx); err == nil {
		return db, nil
	}
	return nil, fmt.Errorf("missing SKYFORGE_DB_HOST/NAME/USER")
}

func openSkyforgeExplicitDB(cfg Config) (*sql.DB, error) {
	pass := strings.TrimSpace(cfg.DBPassword)
	if pass == "" && strings.TrimSpace(cfg.DBPasswordFile) != "" {
		fromFile, err := readFileSecret(cfg.DBPasswordFile)
		if err != nil {
			return nil, err
		}
		pass = fromFile
	}
	if pass == "" {
		return nil, fmt.Errorf("missing SKYFORGE_DB_PASSWORD or SKYFORGE_DB_PASSWORD_FILE")
	}
	sslmode := strings.TrimSpace(cfg.DBSSLMode)
	if sslmode == "" {
		sslmode = "disable"
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		url.PathEscape(cfg.DBUser),
		url.PathEscape(pass),
		cfg.DBHost,
		cfg.DBPort,
		url.PathEscape(cfg.DBName),
		url.QueryEscape(sslmode),
	)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)
	return db, nil
}

func isPostgresStateEmpty(ctx context.Context, db *sql.DB) (bool, error) {
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sf_workspaces`).Scan(&count); err != nil {
		return false, err
	}
	return count == 0, nil
}

func renameIfExists(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	return os.Rename(path, fmt.Sprintf("%s.migrated.%s", path, ts))
}

func migrateFileStateToPostgres(cfg Config, pgWorkspaces *pgWorkspacesStore, pgUsers *pgUsersStore, pgAWS *pgAWSStore) error {
	fileWorkspaces := newFileWorkspacesStore(cfg.Workspaces.DataDir)
	if _, err := os.Stat(fileWorkspaces.path); errors.Is(err, os.ErrNotExist) {
		legacyPath := filepath.Join(cfg.Workspaces.DataDir, "projects.json")
		if _, legacyErr := os.Stat(legacyPath); legacyErr == nil {
			fileWorkspaces.path = legacyPath
		}
	}
	fileUsers := newFileUsersStore(cfg.Workspaces.DataDir)
	fileAWS := newFileAWSStore(cfg.Workspaces.DataDir, newSecretBox(cfg.SessionSecret))

	workspaces, err := fileWorkspaces.load()
	if err != nil {
		return err
	}
	users, err := fileUsers.load()
	if err != nil {
		return err
	}
	awsRecords, err := fileAWS.loadAll()
	if err != nil {
		return err
	}

	seenUsers := map[string]struct{}{}
	addUser := func(u string) {
		u = strings.ToLower(strings.TrimSpace(u))
		if !isValidUsername(u) {
			return
		}
		seenUsers[u] = struct{}{}
	}
	for _, u := range users {
		addUser(u)
	}
	for username := range awsRecords {
		addUser(username)
	}
	for _, p := range workspaces {
		addUser(p.CreatedBy)
		for _, u := range append(append([]string{}, p.Owners...), append(p.Editors, p.Viewers...)...) {
			addUser(u)
		}
	}

	for u := range seenUsers {
		if err := pgUsers.upsert(u); err != nil {
			return err
		}
	}
	if err := pgWorkspaces.save(workspaces); err != nil {
		return err
	}
	for username, rec := range awsRecords {
		if err := pgAWS.put(username, rec); err != nil {
			return err
		}
	}

	if err := renameIfExists(filepath.Join(cfg.Workspaces.DataDir, "projects.json")); err != nil {
		return err
	}
	if err := renameIfExists(filepath.Join(cfg.Workspaces.DataDir, "users.json")); err != nil {
		return err
	}
	if err := renameIfExists(filepath.Join(cfg.Workspaces.DataDir, "aws_sso.json")); err != nil {
		return err
	}
	return nil
}

func slugify(input string) string {
	s := strings.ToLower(strings.TrimSpace(input))
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, " ", "-")
	var b strings.Builder
	b.Grow(len(s))
	lastDash := false
	for _, r := range s {
		isAlnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if isAlnum {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if r == '-' {
			if !lastDash {
				b.WriteRune('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "workspace"
	}
	return out
}

func parseUserList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, "\n", ",")
	raw = strings.ReplaceAll(raw, "\t", ",")
	raw = strings.ReplaceAll(raw, " ", ",")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key := strings.ToLower(part)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, part)
	}
	return out
}

func isAdminUser(cfg Config, username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	if strings.EqualFold(username, "admin") {
		return true
	}
	for _, u := range cfg.AdminUsers {
		if strings.EqualFold(u, username) {
			return true
		}
	}
	return false
}

func containsUser(list []string, username string) bool {
	for _, u := range list {
		if strings.EqualFold(u, username) {
			return true
		}
	}
	return false
}

func normalizeGroupList(groups []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if len(g) > 512 {
			continue
		}
		key := strings.ToLower(g)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, g)
	}
	return out
}

func containsGroup(list []string, groups []string) bool {
	if len(list) == 0 || len(groups) == 0 {
		return false
	}
	owned := map[string]struct{}{}
	for _, g := range list {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == "" {
			continue
		}
		owned[g] = struct{}{}
	}
	for _, g := range groups {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == "" {
			continue
		}
		if _, ok := owned[g]; ok {
			return true
		}
	}
	return false
}

func normalizeUsernameList(list []string) []string {
	out := make([]string, 0, len(list))
	seen := map[string]bool{}
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !isValidUsername(item) {
			continue
		}
		key := strings.ToLower(item)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func isValidUsername(username string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}
	for _, r := range username {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '@':
		default:
			return false
		}
	}
	return true
}

func workspaceAccessLevel(cfg Config, p SkyforgeWorkspace, username string) string {
	if isAdminUser(cfg, username) {
		return "admin"
	}
	if p.IsPublic {
		return "viewer"
	}
	if containsUser(p.Owners, username) || strings.EqualFold(p.CreatedBy, username) {
		return "owner"
	}
	if containsUser(p.Editors, username) {
		return "editor"
	}
	if containsUser(p.Viewers, username) {
		return "viewer"
	}
	return "none"
}

func workspaceAccessLevelForClaims(cfg Config, p SkyforgeWorkspace, claims *SessionClaims) string {
	if claims == nil {
		return "none"
	}
	if isAdminUser(cfg, claims.Username) {
		return "admin"
	}
	username := strings.TrimSpace(claims.Username)
	if username == "" {
		return "none"
	}
	if p.IsPublic {
		return "viewer"
	}
	if strings.EqualFold(p.CreatedBy, username) || containsUser(p.Owners, username) || containsGroup(p.OwnerGroups, claims.Groups) {
		return "owner"
	}
	if containsUser(p.Editors, username) || containsGroup(p.EditorGroups, claims.Groups) {
		return "editor"
	}
	if containsUser(p.Viewers, username) || containsGroup(p.ViewerGroups, claims.Groups) {
		return "viewer"
	}
	return "none"
}

func syncGroupMembershipForUser(p *SkyforgeWorkspace, claims *SessionClaims) (string, bool) {
	if p == nil || claims == nil {
		return "", false
	}
	username := strings.TrimSpace(claims.Username)
	if username == "" {
		return "", false
	}
	if strings.EqualFold(p.CreatedBy, username) || containsUser(p.Owners, username) || containsUser(p.Editors, username) || containsUser(p.Viewers, username) {
		return "", false
	}
	if containsGroup(p.OwnerGroups, claims.Groups) {
		p.Owners = append(p.Owners, username)
		return "owner", true
	}
	if containsGroup(p.EditorGroups, claims.Groups) {
		p.Editors = append(p.Editors, username)
		return "editor", true
	}
	if containsGroup(p.ViewerGroups, claims.Groups) {
		p.Viewers = append(p.Viewers, username)
		return "viewer", true
	}
	return "", false
}

func findWorkspaceByKey(workspaces []SkyforgeWorkspace, key string) *SkyforgeWorkspace {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	for i := range workspaces {
		if workspaces[i].ID == key || strings.EqualFold(workspaces[i].Slug, key) {
			return &workspaces[i]
		}
	}
	return nil
}

func syncGiteaCollaboratorsForWorkspace(cfg Config, workspace SkyforgeWorkspace) {
	owner := strings.TrimSpace(workspace.GiteaOwner)
	repo := strings.TrimSpace(workspace.GiteaRepo)
	if owner == "" || repo == "" {
		return
	}

	desired := map[string]string{}
	add := func(user, perm string) {
		user = strings.ToLower(strings.TrimSpace(user))
		if !isValidUsername(user) {
			return
		}
		if strings.EqualFold(user, cfg.Workspaces.GiteaUsername) {
			return
		}
		if existing, ok := desired[user]; ok {
			if existing == "admin" || perm == existing {
				return
			}
			if perm == "admin" {
				desired[user] = "admin"
				return
			}
			if existing == "write" && perm == "read" {
				return
			}
			if existing == "read" && perm == "write" {
				desired[user] = "write"
				return
			}
			return
		}
		desired[user] = perm
	}

	add(workspace.CreatedBy, "admin")
	for _, u := range workspace.Owners {
		add(u, "admin")
	}
	for _, u := range workspace.Editors {
		add(u, "write")
	}
	for _, u := range workspace.Viewers {
		add(u, "read")
	}

	for user, perm := range desired {
		if err := ensureGiteaCollaborator(cfg, owner, repo, user, perm); err != nil {
			log.Printf("gitea collaborator add (%s %s/%s): %v", user, owner, repo, err)
		}
	}

	current, err := listGiteaCollaborators(cfg, owner, repo)
	if err != nil {
		log.Printf("gitea collaborators list (%s/%s): %v", owner, repo, err)
		return
	}
	for _, user := range current {
		u := strings.ToLower(strings.TrimSpace(user))
		if u == "" || strings.EqualFold(u, cfg.Workspaces.GiteaUsername) {
			continue
		}
		if _, ok := desired[u]; ok {
			continue
		}
		if err := removeGiteaCollaborator(cfg, owner, repo, u); err != nil {
			log.Printf("gitea collaborator remove (%s %s/%s): %v", u, owner, repo, err)
		}
	}
}

type awsDeviceAuthSession struct {
	Username                string
	Region                  string
	StartURL                string
	ClientID                string
	ClientSecret            string
	DeviceCode              string
	IntervalSeconds         int32
	ExpiresAt               time.Time
	VerificationURIComplete string
	UserCode                string
}

var awsDeviceAuthCache struct {
	mu    sync.Mutex
	items map[string]awsDeviceAuthSession
}

func awsAnonymousConfig(ctx context.Context, region string) (aws.Config, error) {
	return config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
}

func awsSSOClientKey(region string) string {
	return "__client__:" + strings.ToLower(strings.TrimSpace(region))
}

func ensureAWSOIDCClient(ctx context.Context, cfg Config, store awsSSOTokenStore) (string, string, time.Time, error) {
	region := strings.TrimSpace(cfg.AwsSSORegion)
	if region == "" {
		return "", "", time.Time{}, fmt.Errorf("AWS SSO is not configured (missing region)")
	}
	key := awsSSOClientKey(region)
	existing, err := store.get(key)
	if err != nil {
		return "", "", time.Time{}, err
	}
	if existing != nil && existing.ClientID != "" && existing.ClientSecret != "" && time.Now().Add(10*time.Minute).Before(existing.ClientSecretExpiresAt) {
		return existing.ClientID, existing.ClientSecret, existing.ClientSecretExpiresAt, nil
	}

	awsCfg, err := awsAnonymousConfig(ctx, region)
	if err != nil {
		return "", "", time.Time{}, err
	}
	oidcClient := ssooidc.NewFromConfig(awsCfg)
	resp, err := oidcClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("skyforge"),
		ClientType: aws.String("public"),
		Scopes:     []string{"sso:account:access"},
	})
	if err != nil {
		return "", "", time.Time{}, err
	}
	expiresAt := time.Unix(int64(resp.ClientSecretExpiresAt), 0).UTC()
	record := awsSSOTokenRecord{
		StartURL:              strings.TrimSpace(cfg.AwsSSOStartURL),
		Region:                region,
		ClientID:              aws.ToString(resp.ClientId),
		ClientSecret:          aws.ToString(resp.ClientSecret),
		ClientSecretExpiresAt: expiresAt,
	}
	if err := store.put(key, record); err != nil {
		return "", "", time.Time{}, err
	}
	return record.ClientID, record.ClientSecret, record.ClientSecretExpiresAt, nil
}

func startAWSDeviceAuthorization(ctx context.Context, cfg Config, store awsSSOTokenStore, username string) (string, awsDeviceAuthSession, error) {
	startURL := strings.TrimSpace(cfg.AwsSSOStartURL)
	region := strings.TrimSpace(cfg.AwsSSORegion)
	if startURL == "" || region == "" {
		return "", awsDeviceAuthSession{}, fmt.Errorf("AWS SSO is not configured")
	}
	clientID, clientSecret, _, err := ensureAWSOIDCClient(ctx, cfg, store)
	if err != nil {
		return "", awsDeviceAuthSession{}, err
	}
	awsCfg, err := awsAnonymousConfig(ctx, region)
	if err != nil {
		return "", awsDeviceAuthSession{}, err
	}
	oidcClient := ssooidc.NewFromConfig(awsCfg)
	resp, err := oidcClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     aws.String(clientID),
		ClientSecret: aws.String(clientSecret),
		StartUrl:     aws.String(startURL),
	})
	if err != nil {
		return "", awsDeviceAuthSession{}, err
	}

	requestIDBytes := make([]byte, 18)
	if _, err := rand.Read(requestIDBytes); err != nil {
		return "", awsDeviceAuthSession{}, err
	}
	requestID := base64.RawURLEncoding.EncodeToString(requestIDBytes)
	session := awsDeviceAuthSession{
		Username:                username,
		Region:                  region,
		StartURL:                startURL,
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		DeviceCode:              aws.ToString(resp.DeviceCode),
		IntervalSeconds:         resp.Interval,
		ExpiresAt:               time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second).UTC(),
		VerificationURIComplete: aws.ToString(resp.VerificationUriComplete),
		UserCode:                aws.ToString(resp.UserCode),
	}

	awsDeviceAuthCache.mu.Lock()
	if awsDeviceAuthCache.items == nil {
		awsDeviceAuthCache.items = map[string]awsDeviceAuthSession{}
	}
	awsDeviceAuthCache.items[requestID] = session
	awsDeviceAuthCache.mu.Unlock()
	return requestID, session, nil
}

func pollAWSDeviceToken(ctx context.Context, requestID string) (*awsDeviceAuthSession, *ssooidc.CreateTokenOutput, string, error) {
	awsDeviceAuthCache.mu.Lock()
	session, ok := awsDeviceAuthCache.items[requestID]
	awsDeviceAuthCache.mu.Unlock()
	if !ok {
		return nil, nil, "not_found", nil
	}
	if time.Now().After(session.ExpiresAt) {
		return &session, nil, "expired", nil
	}
	awsCfg, err := awsAnonymousConfig(ctx, session.Region)
	if err != nil {
		return &session, nil, "error", err
	}
	oidcClient := ssooidc.NewFromConfig(awsCfg)
	out, err := oidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     aws.String(session.ClientID),
		ClientSecret: aws.String(session.ClientSecret),
		DeviceCode:   aws.String(session.DeviceCode),
		GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
	})
	if err != nil {
		var pending *ssooidcTypes.AuthorizationPendingException
		if errors.As(err, &pending) {
			return &session, nil, "pending", nil
		}
		var slow *ssooidcTypes.SlowDownException
		if errors.As(err, &slow) {
			return &session, nil, "pending", nil
		}
		var denied *ssooidcTypes.AccessDeniedException
		if errors.As(err, &denied) {
			return &session, nil, "denied", nil
		}
		var expired *ssooidcTypes.ExpiredTokenException
		if errors.As(err, &expired) {
			return &session, nil, "expired", nil
		}
		return &session, nil, "error", err
	}
	return &session, out, "ok", nil
}

func refreshAWSAccessToken(ctx context.Context, region, clientID, clientSecret, refreshToken string) (*ssooidc.CreateTokenOutput, error) {
	awsCfg, err := awsAnonymousConfig(ctx, region)
	if err != nil {
		return nil, err
	}
	oidcClient := ssooidc.NewFromConfig(awsCfg)
	return oidcClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     aws.String(clientID),
		ClientSecret: aws.String(clientSecret),
		RefreshToken: aws.String(refreshToken),
		GrantType:    aws.String("refresh_token"),
	})
}

func getAWSRoleCredentials(ctx context.Context, cfg Config, store awsSSOTokenStore, username, accountID, roleName string) (*sso.GetRoleCredentialsOutput, error) {
	accountID = strings.TrimSpace(accountID)
	roleName = strings.TrimSpace(roleName)
	if accountID == "" || roleName == "" {
		return nil, fmt.Errorf("missing aws account id or role name")
	}
	if cfg.AwsSSOStartURL == "" || cfg.AwsSSORegion == "" {
		return nil, fmt.Errorf("AWS SSO is not configured")
	}

	record, err := store.get(username)
	if err != nil {
		return nil, err
	}
	if record == nil || record.RefreshToken == "" {
		return nil, fmt.Errorf("AWS SSO not connected")
	}

	clientID, clientSecret, _, err := ensureAWSOIDCClient(ctx, cfg, store)
	if err != nil {
		return nil, err
	}

	accessToken := record.AccessToken
	if accessToken == "" || time.Now().Add(2*time.Minute).After(record.AccessTokenExpiresAt) {
		refreshed, err := refreshAWSAccessToken(ctx, cfg.AwsSSORegion, clientID, clientSecret, record.RefreshToken)
		if err != nil {
			return nil, err
		}
		record.AccessToken = aws.ToString(refreshed.AccessToken)
		record.AccessTokenExpiresAt = time.Now().Add(time.Duration(refreshed.ExpiresIn) * time.Second).UTC()
		if aws.ToString(refreshed.RefreshToken) != "" {
			record.RefreshToken = aws.ToString(refreshed.RefreshToken)
		}
		record.StartURL = strings.TrimSpace(cfg.AwsSSOStartURL)
		record.Region = strings.TrimSpace(cfg.AwsSSORegion)
		record.ClientID = clientID
		record.ClientSecret = clientSecret
		record.LastAuthenticatedAtUTC = time.Now().UTC()
		if err := store.put(username, *record); err != nil {
			return nil, err
		}
		accessToken = record.AccessToken
	}

	awsCfg, err := awsAnonymousConfig(ctx, cfg.AwsSSORegion)
	if err != nil {
		return nil, err
	}
	ssoClient := sso.NewFromConfig(awsCfg)
	return ssoClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: aws.String(accessToken),
		AccountId:   aws.String(accountID),
		RoleName:    aws.String(roleName),
	})
}

type workspaceSyncReport struct {
	WorkspaceID string   `json:"workspaceId"`
	Slug        string   `json:"slug"`
	Updated     bool     `json:"updated"`
	Steps       []string `json:"steps,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

func workspaceTerraformEnv(cfg Config, workspace SkyforgeWorkspace) map[string]string {
	region := "us-east-1"
	if strings.TrimSpace(workspace.AWSRegion) != "" {
		region = strings.TrimSpace(workspace.AWSRegion)
	}
	env := map[string]string{
		"TF_IN_AUTOMATION":          "true",
		"TF_VAR_scenario":           "regular_cluster",
		"AWS_EC2_METADATA_DISABLED": "true",
		"AWS_REGION":                region,
		"TF_VAR_ssh_key_name":       "REPLACE_ME",
		"TF_VAR_artifacts_bucket":   "REPLACE_ME",
	}
	if cfg.Workspaces.ObjectStorageTerraformAccessKey != "" && cfg.Workspaces.ObjectStorageTerraformSecretKey != "" {
		env["AWS_ACCESS_KEY_ID"] = cfg.Workspaces.ObjectStorageTerraformAccessKey
		env["AWS_SECRET_ACCESS_KEY"] = cfg.Workspaces.ObjectStorageTerraformSecretKey
	}
	return env
}

func syncWorkspaceResources(ctx context.Context, cfg Config, workspace *SkyforgeWorkspace) workspaceSyncReport {
	report := workspaceSyncReport{
		WorkspaceID: workspace.ID,
		Slug:        workspace.Slug,
	}
	addStep := func(msg string) {
		report.Steps = append(report.Steps, msg)
	}
	addErr := func(msg string, err error) {
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("%s: %v", msg, err))
		} else {
			report.Errors = append(report.Errors, msg)
		}
	}

	if strings.TrimSpace(workspace.GiteaOwner) == "" {
		workspace.GiteaOwner = strings.TrimSpace(cfg.Workspaces.GiteaUsername)
		report.Updated = true
		addStep("set gitea owner")
	}
	if strings.TrimSpace(workspace.GiteaRepo) == "" {
		workspace.GiteaRepo = strings.TrimSpace(workspace.Slug)
		report.Updated = true
		addStep("set gitea repo")
	}
	if strings.TrimSpace(workspace.ArtifactsBucket) != storage.StorageBucketName {
		workspace.ArtifactsBucket = storage.StorageBucketName
		report.Updated = true
		addStep("set artifacts bucket")
	}

	if strings.TrimSpace(workspace.GiteaOwner) != "" && strings.TrimSpace(workspace.GiteaRepo) != "" {
		repoPrivate := !workspace.IsPublic
		if err := ensureGiteaRepoFromBlueprint(cfg, workspace.GiteaOwner, workspace.GiteaRepo, workspace.Blueprint, repoPrivate); err != nil {
			addErr("gitea repo ensure", err)
		} else {
			addStep("gitea repo ok")
			if branch, err := getGiteaRepoDefaultBranch(cfg, workspace.GiteaOwner, workspace.GiteaRepo); err != nil {
				addErr("gitea default branch", err)
			} else if strings.TrimSpace(branch) != "" && branch != workspace.DefaultBranch {
				workspace.DefaultBranch = branch
				report.Updated = true
				addStep("updated default branch")
			}
		}
	}

	if strings.TrimSpace(workspace.GiteaOwner) != "" && strings.TrimSpace(workspace.GiteaRepo) != "" {
		syncGiteaCollaboratorsForWorkspace(cfg, *workspace)
		addStep("gitea collaborators synced")
	}

	return report
}

func syncWorkspaces(ctx context.Context, cfg Config, store workspacesStore, db *sql.DB) ([]workspaceSyncReport, error) {
	workspaces, err := store.load()
	if err != nil {
		return nil, err
	}
	reports := make([]workspaceSyncReport, 0, len(workspaces))
	changed := false
	for i := range workspaces {
		workspaceCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		report := syncWorkspaceResources(workspaceCtx, cfg, &workspaces[i])
		cancel()
		if report.Updated {
			changed = true
		}
		reports = append(reports, report)
	}
	if changed {
		if err := store.save(workspaces); err != nil {
			return reports, err
		}
	}
	if db != nil {
		for _, report := range reports {
			if !report.Updated {
				continue
			}
			details := fmt.Sprintf("updated=true errors=%d", len(report.Errors))
			auditCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
			writeAuditEvent(auditCtx, db, "system", true, "", "workspace.sync", report.WorkspaceID, details)
			cancel()
		}
	}
	return reports, nil
}

func runWorkspaceSync(cfg Config, store workspacesStore, db *sql.DB) {
	workspaceSyncBackgroundRuns.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	reports, err := syncWorkspaces(ctx, cfg, store, db)
	if err != nil {
		workspaceSyncFailures.Add(1)
		log.Printf("workspace sync failed: %v", err)
		return
	}
	for _, report := range reports {
		if len(report.Errors) > 0 {
			workspaceSyncErrors.Add(1)
			log.Printf("workspace sync %s errors: %v", report.Slug, report.Errors)
		}
	}
}

type storageObjectSummary struct {
	Key          string `json:"key"`
	Size         int64  `json:"size"`
	LastModified string `json:"lastModified,omitempty"`
	ContentType  string `json:"contentType,omitempty"`
}

// defaultService is set once at startup by initService and is used by raw endpoints
// (SSE/webhooks) and cron jobs which don't have direct access to the Service instance.
var defaultService *Service

func initService() (*Service, error) {
	hydrateSecretEnv(
		"SKYFORGE_SESSION_SECRET",
		"SKYFORGE_OIDC_CLIENT_ID",
		"SKYFORGE_OIDC_CLIENT_SECRET",
		"SKYFORGE_LDAP_URL",
		"SKYFORGE_LDAP_BIND_TEMPLATE",
		"SKYFORGE_LDAP_LOOKUP_BINDDN",
		"SKYFORGE_LDAP_LOOKUP_BINDPASSWORD",
		"SKYFORGE_DB_PASSWORD",
		"SKYFORGE_GITEA_PASSWORD",
		"SKYFORGE_OBJECT_STORAGE_TERRAFORM_ACCESS_KEY",
		"SKYFORGE_OBJECT_STORAGE_TERRAFORM_SECRET_KEY",
		"SKYFORGE_INTERNAL_TOKEN",
	)

	meta := encore.Meta()
	rlog.Info("initializing skyforge service",
		"environment_name", meta.Environment.Name,
		"environment_type", meta.Environment.Type,
		"cloud", meta.Environment.Cloud,
		"app_id", meta.AppID,
	)

	cfg := loadConfig()
	box := newSecretBox(cfg.SessionSecret)
	ldapPasswordBox = box
	var auth *LDAPAuthenticator
	if strings.TrimSpace(cfg.LDAP.URL) != "" && strings.TrimSpace(cfg.LDAP.BindTemplate) != "" {
		auth = NewLDAPAuthenticator(cfg.LDAP, cfg.MaxGroups)
	} else if strings.TrimSpace(cfg.LDAP.URL) != "" || strings.TrimSpace(cfg.LDAP.BindTemplate) != "" {
		log.Printf("LDAP config incomplete; LDAP auth disabled")
	} else {
		log.Printf("LDAP not configured; using local admin only")
	}
	sessionManager := NewSessionManager(cfg.SessionSecret, cfg.SessionCookie, cfg.SessionTTL, cfg.CookieSecure, cfg.CookieDomain)
	oidcClient, err := initOIDCClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("oidc init failed: %w", err)
	}
	var (
		workspaceStore workspacesStore
		awsStore       awsSSOTokenStore
		userStore      usersStore
		db             *sql.DB
	)

	fileWorkspaceStore := newFileWorkspacesStore(cfg.Workspaces.DataDir)
	fileAWSStore := newFileAWSStore(cfg.Workspaces.DataDir, box)
	fileUserStore := newFileUsersStore(cfg.Workspaces.DataDir)

	if strings.EqualFold(strings.TrimSpace(cfg.StateBackend), "postgres") {
		var err error
		db, err = openSkyforgeDB(cfg)
		if err != nil {
			return nil, fmt.Errorf("postgres open failed: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("postgres ping failed: %w", err)
		}

		pgWorkspaces := newPGWorkspacesStore(db)
		pgUsers := newPGUsersStore(db)
		pgAWS := newPGAWSStore(db, box)
		empty, err := isPostgresStateEmpty(ctx, db)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("postgres state check failed: %w", err)
		}
		if empty {
			if err := migrateFileStateToPostgres(cfg, pgWorkspaces, pgUsers, pgAWS); err != nil {
				log.Printf("postgres state migration skipped/failed: %v", err)
			} else {
				log.Printf("postgres state migration complete")
			}
		}

		workspaceStore = pgWorkspaces
		awsStore = pgAWS
		userStore = pgUsers
	} else {
		workspaceStore = fileWorkspaceStore
		awsStore = fileAWSStore
		userStore = fileUserStore
	}

	// Background loops are scheduled externally (e.g. Kubernetes CronJobs) and enqueued for worker execution.

	svc := &Service{
		cfg:            cfg,
		auth:           auth,
		oidc:           oidcClient,
		sessionManager: sessionManager,
		workspaceStore: workspaceStore,
		awsStore:       awsStore,
		userStore:      userStore,
		box:            box,
		db:             db,
	}
	defaultService = svc
	startTaskWorkerHeartbeat(cfg, db)
	return svc, nil
}

// Session + Auth types

type UserProfile struct {
	Authenticated bool     `json:"authenticated"`
	Username      string   `json:"username"`
	DisplayName   string   `json:"displayName"`
	Email         string   `json:"email,omitempty"`
	Groups        []string `json:"groups"`
	IsAdmin       bool     `json:"isAdmin,omitempty"`
	ActorUsername string   `json:"actorUsername,omitempty"`
	Impersonating bool     `json:"impersonating,omitempty"`
}

type SessionResponse = UserProfile

type SessionClaims struct {
	Username         string   `json:"username"`
	DisplayName      string   `json:"displayName"`
	Email            string   `json:"email,omitempty"`
	Groups           []string `json:"groups"`
	ActorUsername    string   `json:"actorUsername,omitempty"`
	ActorDisplayName string   `json:"actorDisplayName,omitempty"`
	ActorEmail       string   `json:"actorEmail,omitempty"`
	ActorGroups      []string `json:"actorGroups,omitempty"`
	jwt.RegisteredClaims
}

type SessionManager struct {
	secret       []byte
	cookieName   string
	ttl          time.Duration
	secureMode   string
	cookieDomain string
}

//encore:service
type Service struct {
	cfg            Config
	auth           *LDAPAuthenticator
	oidc           *OIDCClient
	sessionManager *SessionManager
	workspaceStore workspacesStore
	awsStore       awsSSOTokenStore
	userStore      usersStore
	box            *secretBox
	db             *sql.DB
}

func NewSessionManager(secret, cookie string, ttl time.Duration, secureMode, cookieDomain string) *SessionManager {
	return &SessionManager{
		secret:       []byte(secret),
		cookieName:   cookie,
		ttl:          ttl,
		secureMode:   strings.TrimSpace(strings.ToLower(secureMode)),
		cookieDomain: strings.TrimSpace(cookieDomain),
	}
}

func (sm *SessionManager) Issue(w http.ResponseWriter, r *http.Request, profile *UserProfile) error {
	cookie, err := sm.issueCookie(profile, nil, sm.cookieSecure(r))
	if err != nil {
		return err
	}
	http.SetCookie(w, cookie)
	return nil
}

func (sm *SessionManager) IssueImpersonated(w http.ResponseWriter, r *http.Request, actor *SessionClaims, profile *UserProfile) error {
	cookie, err := sm.issueCookie(profile, actor, sm.cookieSecure(r))
	if err != nil {
		return err
	}
	http.SetCookie(w, cookie)
	return nil
}

func (sm *SessionManager) cookieSecure(r *http.Request) bool {
	switch sm.secureMode {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		if r != nil && r.TLS != nil {
			return true
		}
		if r != nil && sm.cookieSecureFromHeaders(r.Header) {
			return true
		}
		return false
	}
}

func (sm *SessionManager) IssueCookieForHeaders(headers http.Header, profile *UserProfile) (*http.Cookie, error) {
	return sm.issueCookie(profile, nil, sm.cookieSecureFromHeaders(headers))
}

func (sm *SessionManager) IssueImpersonatedCookieForHeaders(headers http.Header, actor *SessionClaims, profile *UserProfile) (*http.Cookie, error) {
	return sm.issueCookie(profile, actor, sm.cookieSecureFromHeaders(headers))
}

func (sm *SessionManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, sm.ClearCookie())
}

func (sm *SessionManager) ClearCookie() *http.Cookie {
	cookie := &http.Cookie{
		Name:     sm.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	if sm.cookieDomain != "" {
		cookie.Domain = sm.cookieDomain
	}
	return cookie
}

func (sm *SessionManager) issueCookie(profile *UserProfile, actor *SessionClaims, secure bool) (*http.Cookie, error) {
	now := time.Now()
	expires := now.Add(sm.ttl)
	claims := SessionClaims{
		Username:    profile.Username,
		DisplayName: profile.DisplayName,
		Email:       profile.Email,
		Groups:      profile.Groups,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
	}
	if actor != nil {
		claims.ActorUsername = strings.TrimSpace(actor.Username)
		claims.ActorDisplayName = strings.TrimSpace(actor.DisplayName)
		claims.ActorEmail = strings.TrimSpace(actor.Email)
		claims.ActorGroups = actor.Groups
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(sm.secret)
	if err != nil {
		return nil, err
	}
	cookie := &http.Cookie{
		Name:     sm.cookieName,
		Value:    signed,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	}
	if sm.cookieDomain != "" {
		cookie.Domain = sm.cookieDomain
	}
	return cookie, nil
}

func (sm *SessionManager) cookieSecureFromHeaders(headers http.Header) bool {
	switch sm.secureMode {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		if headers == nil {
			return false
		}
		xfp := headers.Get("X-Forwarded-Proto")
		return strings.Contains(strings.ToLower(xfp), "https")
	}
}

func (sm *SessionManager) Parse(r *http.Request) (*SessionClaims, error) {
	cookie, err := r.Cookie(sm.cookieName)
	if err != nil {
		return nil, err
	}
	token, err := jwt.ParseWithClaims(cookie.Value, &SessionClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return sm.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*SessionClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid session")
}

func adminUsernameForClaims(claims *SessionClaims) string {
	if claims == nil {
		return ""
	}
	if strings.TrimSpace(claims.ActorUsername) != "" {
		return strings.TrimSpace(claims.ActorUsername)
	}
	return strings.TrimSpace(claims.Username)
}

func isAdminForClaims(cfg Config, claims *SessionClaims) bool {
	return isAdminUser(cfg, adminUsernameForClaims(claims))
}

func isImpersonating(claims *SessionClaims) bool {
	if claims == nil {
		return false
	}
	if strings.TrimSpace(claims.ActorUsername) == "" {
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(claims.ActorUsername), strings.TrimSpace(claims.Username))
}

func auditActor(cfg Config, claims *SessionClaims) (actor string, actorIsAdmin bool, impersonated string) {
	actor = adminUsernameForClaims(claims)
	actorIsAdmin = isAdminUser(cfg, actor)
	if isImpersonating(claims) {
		impersonated = strings.TrimSpace(claims.Username)
	}
	return actor, actorIsAdmin, impersonated
}

type staticHandler struct {
	brandDir        string
	docsDir         string
	platformDataDir string
}

func newStaticHandler(staticRoot, platformDataDir string) *staticHandler {
	root := strings.TrimSpace(staticRoot)
	if root == "" {
		root = "/opt/skyforge/static"
	}
	return &staticHandler{
		brandDir:        filepath.Join(root, "brand"),
		docsDir:         filepath.Join(root, "docs"),
		platformDataDir: strings.TrimSpace(platformDataDir),
	}
}

func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "" {
		path = "/"
	}

	w.Header().Set("Cache-Control", "no-store")

	switch {
	case strings.HasPrefix(path, "/data/"):
		h.serveData(w, r)
		return
	case strings.HasPrefix(path, "/brand/"):
		http.StripPrefix("/brand/", http.FileServer(http.Dir(h.brandDir))).ServeHTTP(w, r)
		return
	default:
		http.NotFound(w, r)
		return
	}
}

func (h *staticHandler) serveData(w http.ResponseWriter, r *http.Request) {
	if h.platformDataDir == "" {
		http.NotFound(w, r)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, "/data/")
	rel = strings.TrimSpace(rel)
	if rel == "" || strings.Contains(rel, "..") || strings.Contains(rel, "\\") {
		http.NotFound(w, r)
		return
	}
	http.StripPrefix("/data/", http.FileServer(http.Dir(h.platformDataDir))).ServeHTTP(w, r)
}

func (sm *SessionManager) Require(handler func(http.ResponseWriter, *http.Request, *SessionClaims)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := sm.Parse(r)
		if err != nil {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		handler(w, r, claims)
	})
}

// LDAP authentication

type LDAPAuthenticator struct {
	cfg       LDAPConfig
	maxGroups int
}

func NewLDAPAuthenticator(cfg LDAPConfig, maxGroups int) *LDAPAuthenticator {
	if maxGroups <= 0 {
		maxGroups = 50
	}
	return &LDAPAuthenticator{cfg: cfg, maxGroups: maxGroups}
}

type AuthFailure struct {
	Status        int
	PublicMessage string
	Err           error
}

func (a *AuthFailure) Error() string {
	if a == nil {
		return ""
	}
	if a.Err != nil {
		return a.Err.Error()
	}
	return a.PublicMessage
}

func (a *AuthFailure) Unwrap() error {
	if a == nil {
		return nil
	}
	return a.Err
}

func (a *LDAPAuthenticator) Authenticate(ctx context.Context, username, password string) (*UserProfile, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, &AuthFailure{Status: http.StatusUnauthorized, PublicMessage: "missing credentials", Err: errors.New("missing credentials")}
	}

	conn, err := dialLDAP(a.cfg)
	if err != nil {
		return nil, classifyLDAPError(err)
	}
	defer conn.Close()

	if err := startTLSSafely(conn, a.cfg); err != nil {
		return nil, classifyLDAPError(err)
	}

	userDN := fmt.Sprintf(a.cfg.BindTemplate, ldap.EscapeDN(username))
	if err := conn.Bind(userDN, password); err != nil {
		return nil, classifyLDAPError(err)
	}

	attrs := []string{a.cfg.DisplayNameAttr, a.cfg.MailAttr, a.cfg.GroupAttr}
	searchReq := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		attrs,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, classifyLDAPError(err)
	}
	if len(sr.Entries) == 0 {
		return nil, &AuthFailure{Status: http.StatusUnauthorized, PublicMessage: "user not found", Err: errors.New("user entry not found")}
	}
	entry := sr.Entries[0]
	display := entry.GetAttributeValue(a.cfg.DisplayNameAttr)
	if display == "" {
		display = username
	}
	email := entry.GetAttributeValue(a.cfg.MailAttr)
	groups := entry.GetAttributeValues(a.cfg.GroupAttr)
	// Normalize group names to simple values when memberOf returns full DN
	for i, g := range groups {
		if strings.Contains(g, ",") {
			parts := strings.SplitN(g, ",", 2)
			if strings.HasPrefix(strings.ToLower(parts[0]), "cn=") {
				groups[i] = strings.TrimPrefix(parts[0], "cn=")
			}
		}
	}

	if len(groups) > 0 {
		seen := make(map[string]struct{}, len(groups))
		unique := make([]string, 0, len(groups))
		for _, g := range groups {
			g = strings.TrimSpace(g)
			if g == "" {
				continue
			}
			if _, ok := seen[g]; ok {
				continue
			}
			seen[g] = struct{}{}
			unique = append(unique, g)
		}
		groups = unique
		if a.maxGroups > 0 && len(groups) > a.maxGroups {
			groups = groups[:a.maxGroups]
		}
	}

	return &UserProfile{
		Authenticated: true,
		Username:      username,
		DisplayName:   display,
		Email:         email,
		Groups:        groups,
	}, nil
}

func lookupLDAPUserProfile(ctx context.Context, cfg LDAPConfig, username string, maxGroups int, bindDN string, bindPassword string) (*UserProfile, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, errors.New("missing username")
	}
	if maxGroups <= 0 {
		maxGroups = 50
	}

	conn, err := dialLDAP(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := startTLSSafely(conn, cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(bindDN) != "" {
		if err := conn.Bind(strings.TrimSpace(bindDN), bindPassword); err != nil {
			return nil, err
		}
	}

	userDN := fmt.Sprintf(cfg.BindTemplate, ldap.EscapeDN(username))
	attrs := []string{cfg.DisplayNameAttr, cfg.MailAttr, cfg.GroupAttr}
	searchReq := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		attrs,
		nil,
	)
	_ = ctx
	sr, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, errors.New("user not found")
	}
	entry := sr.Entries[0]
	display := entry.GetAttributeValue(cfg.DisplayNameAttr)
	if display == "" {
		display = username
	}
	email := entry.GetAttributeValue(cfg.MailAttr)
	groups := entry.GetAttributeValues(cfg.GroupAttr)
	for i, g := range groups {
		if strings.Contains(g, ",") {
			parts := strings.SplitN(g, ",", 2)
			if strings.HasPrefix(strings.ToLower(parts[0]), "cn=") {
				groups[i] = strings.TrimPrefix(parts[0], "cn=")
			}
		}
	}
	if len(groups) > 0 {
		seen := make(map[string]struct{}, len(groups))
		unique := make([]string, 0, len(groups))
		for _, g := range groups {
			g = strings.TrimSpace(g)
			if g == "" {
				continue
			}
			key := strings.ToLower(g)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			unique = append(unique, g)
		}
		groups = unique
		if maxGroups > 0 && len(groups) > maxGroups {
			groups = groups[:maxGroups]
		}
	}
	return &UserProfile{
		Authenticated: true,
		Username:      username,
		DisplayName:   display,
		Email:         email,
		Groups:        groups,
	}, nil
}

func dialLDAP(cfg LDAPConfig) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	opts := []ldap.DialOpt{ldap.DialWithDialer(dialer)}

	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(parsed.Scheme, "ldaps") {
		tlsCfg := &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}
		if host := parsed.Hostname(); host != "" && tlsCfg.ServerName == "" {
			tlsCfg.ServerName = host
		}
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}
	return ldap.DialURL(cfg.URL, opts...)
}

func startTLSSafely(conn *ldap.Conn, cfg LDAPConfig) error {
	if !cfg.UseStartTLS {
		return nil
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return err
	}
	if strings.EqualFold(parsed.Scheme, "ldaps") {
		return nil
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}
	if host := parsed.Hostname(); host != "" && tlsCfg.ServerName == "" {
		tlsCfg.ServerName = host
	}
	return conn.StartTLS(tlsCfg)
}

func classifyLDAPError(err error) error {
	if err == nil {
		return nil
	}
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultInvalidCredentials:
			return &AuthFailure{Status: http.StatusUnauthorized, PublicMessage: "invalid credentials", Err: err}
		case ldap.LDAPResultConfidentialityRequired, ldap.LDAPResultStrongAuthRequired:
			return &AuthFailure{Status: http.StatusBadGateway, PublicMessage: "LDAP requires TLS (StartTLS/LDAPS)", Err: err}
		default:
			if ldapErr.ResultCode == ldap.ErrorNetwork {
				return &AuthFailure{Status: http.StatusBadGateway, PublicMessage: "unable to reach LDAP server", Err: err}
			}
			return &AuthFailure{Status: http.StatusBadGateway, PublicMessage: "LDAP authentication error", Err: err}
		}
	}
	return &AuthFailure{Status: http.StatusBadGateway, PublicMessage: "authentication backend error", Err: err}
}

func checkLDAPConnectivity(ctx context.Context, cfg LDAPConfig) error {
	// Best-effort connectivity check: dial + optional StartTLS handshake; no bind.
	conn, err := dialLDAP(cfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = ctx
	if err := startTLSSafely(conn, cfg); err != nil {
		return err
	}
	return nil
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	msg = strings.ReplaceAll(msg, "\n", " ")
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return msg
}

func extractLabIDFromMetadataPath(stateRoot, path string) string {
	stateRoot = strings.TrimSuffix(stateRoot, "/")
	if stateRoot != "" && strings.HasPrefix(path, stateRoot+"/") {
		rest := strings.TrimPrefix(path, stateRoot+"/")
		parts := strings.Split(rest, "/")
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}
	parts := strings.Split(strings.TrimSuffix(path, "/metadata.json"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func getSetting(ctx context.Context, db *sql.DB, key string) (string, bool, error) {
	if db == nil {
		return "", false, nil
	}
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM sf_settings WHERE key=$1`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return value, true, nil
}

func upsertSetting(ctx context.Context, db *sql.DB, key, value string) error {
	if db == nil {
		return fmt.Errorf("settings store unavailable")
	}
	_, err := db.ExecContext(ctx, `INSERT INTO sf_settings (key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, key, value)
	return err
}

func notificationSettings(ctx context.Context, db *sql.DB, cfg Config) (NotificationSettings, error) {
	interval := cfg.NotificationsInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	settings := NotificationSettings{
		PollingEnabled:    cfg.NotificationsEnabled,
		PollingIntervalMs: interval.Milliseconds(),
	}
	if db == nil {
		return settings, nil
	}
	if value, ok, err := getSetting(ctx, db, "notifications_polling_enabled"); err != nil {
		return settings, err
	} else if ok {
		if parsed, err := strconv.ParseBool(strings.TrimSpace(value)); err == nil {
			settings.PollingEnabled = parsed
		}
	}
	if value, ok, err := getSetting(ctx, db, "notifications_polling_interval"); err != nil {
		return settings, err
	} else if ok {
		if parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil && parsed > 0 {
			settings.PollingIntervalMs = parsed
		}
	}
	return settings, nil
}

func listNotifications(ctx context.Context, db *sql.DB, username string, includeRead bool, limit int) ([]NotificationRecord, error) {
	if db == nil {
		return []NotificationRecord{}, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 25
	}
	query := `SELECT id, username, title, message, type, category, reference_id, priority, is_read, created_at, updated_at
FROM sf_notifications
WHERE username=$1`
	if !includeRead {
		query += " AND is_read=false"
	}
	query += " ORDER BY created_at DESC LIMIT $2"

	rows, err := db.QueryContext(ctx, query, strings.ToLower(strings.TrimSpace(username)), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationRecord{}
	for rows.Next() {
		var rec NotificationRecord
		if err := rows.Scan(
			&rec.ID,
			&rec.Username,
			&rec.Title,
			&rec.Message,
			&rec.Type,
			&rec.Category,
			&rec.ReferenceID,
			&rec.Priority,
			&rec.IsRead,
			&rec.CreatedAt,
			&rec.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func markNotificationRead(ctx context.Context, db *sql.DB, username, id string) error {
	if db == nil {
		return nil
	}
	res, err := db.ExecContext(ctx, `UPDATE sf_notifications SET is_read=true, updated_at=now() WHERE id=$1 AND username=$2`, id, strings.ToLower(strings.TrimSpace(username)))
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func markAllNotificationsRead(ctx context.Context, db *sql.DB, username string) error {
	if db == nil {
		return nil
	}
	_, err := db.ExecContext(ctx, `UPDATE sf_notifications SET is_read=true, updated_at=now() WHERE username=$1 AND is_read=false`, strings.ToLower(strings.TrimSpace(username)))
	return err
}

func deleteNotification(ctx context.Context, db *sql.DB, username, id string) error {
	if db == nil {
		return nil
	}
	res, err := db.ExecContext(ctx, `DELETE FROM sf_notifications WHERE id=$1 AND username=$2`, id, strings.ToLower(strings.TrimSpace(username)))
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func createNotification(ctx context.Context, db *sql.DB, username, title, message, typ, category, referenceID, priority string) (string, error) {
	if db == nil {
		return "", nil
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return "", fmt.Errorf("username is required")
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = "Notification"
	}
	if typ == "" {
		typ = "SYSTEM"
	}
	if priority == "" {
		priority = "low"
	}
	ensureAuditActor(ctx, db, username)
	id := uuid.NewString()
	_, err := db.ExecContext(ctx, `INSERT INTO sf_notifications (
  id, username, title, message, type, category, reference_id, priority
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, username, title, strings.TrimSpace(message), strings.TrimSpace(typ), nullIfEmpty(strings.TrimSpace(category)), nullIfEmpty(strings.TrimSpace(referenceID)), nullIfEmpty(strings.TrimSpace(priority)))
	if err != nil {
		return "", err
	}
	return id, nil
}

func shouldNotifyCloudCredential(key string, ok bool) bool {
	cloudCredentialStatusCache.mu.Lock()
	defer cloudCredentialStatusCache.mu.Unlock()
	if cloudCredentialStatusCache.items == nil {
		cloudCredentialStatusCache.items = map[string]bool{}
	}
	prev, exists := cloudCredentialStatusCache.items[key]
	cloudCredentialStatusCache.items[key] = ok
	if !exists {
		return !ok
	}
	return prev && !ok
}

func workspaceNotificationRecipients(workspace SkyforgeWorkspace) []string {
	recipients := map[string]struct{}{}
	add := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return
		}
		recipients[value] = struct{}{}
	}
	add(workspace.CreatedBy)
	for _, owner := range workspace.Owners {
		add(owner)
	}
	out := make([]string, 0, len(recipients))
	for owner := range recipients {
		out = append(out, owner)
	}
	sort.Strings(out)
	return out
}

func validateAWSStaticCredentials(ctx context.Context, region string, creds *awsStaticCredentials) error {
	region = strings.TrimSpace(region)
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)),
	)
	if err != nil {
		return err
	}
	client := sts.NewFromConfig(cfg)
	_, err = client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	return err
}

func runCloudCredentialChecks(cfg Config, workspaceStore workspacesStore, awsStore awsSSOTokenStore, db *sql.DB) {
	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	now := time.Now().UTC()
	if awsStore != nil {
		if tokens, err := awsStore.loadAll(); err == nil {
			for username, record := range tokens {
				username = strings.ToLower(strings.TrimSpace(username))
				if username == "" {
					continue
				}
				if strings.TrimSpace(record.RefreshToken) == "" {
					continue
				}
				if !record.RefreshTokenExpiresAt.IsZero() && now.After(record.RefreshTokenExpiresAt) {
					if shouldNotifyCloudCredential("aws-sso:"+username, false) {
						_, _ = createNotification(ctx, db, username, "AWS SSO session expired",
							"Your AWS SSO session expired. Re-authenticate in Workspaces → New Workspace → AWS.",
							"warning", "cloud-credentials", "/workspaces/new", "high")
					}
				} else {
					shouldNotifyCloudCredential("aws-sso:"+username, true)
				}
			}
		}
	}

	workspaces, err := workspaceStore.load()
	if err != nil {
		log.Printf("cloud credential check: workspace load failed: %v", err)
		return
	}
	box := newSecretBox(cfg.SessionSecret)
	for _, workspace := range workspaces {
		recipients := workspaceNotificationRecipients(workspace)
		if len(recipients) == 0 {
			continue
		}

		if strings.EqualFold(strings.TrimSpace(workspace.AWSAuthMethod), "static") {
			creds, err := getWorkspaceAWSStaticCredentials(ctx, db, box, workspace.ID)
			key := "aws-static:" + workspace.ID
			if err != nil || creds == nil || creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
				if shouldNotifyCloudCredential(key, false) {
					for _, username := range recipients {
						_, _ = createNotification(ctx, db, username, "AWS static credentials missing",
							fmt.Sprintf("Workspace %s is missing AWS static credentials. Update them in Workspace Settings.", workspace.Name),
							"warning", "cloud-credentials", fmt.Sprintf("/workspaces/%s/settings", workspace.ID), "high")
					}
				}
			} else {
				validateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				validateErr := validateAWSStaticCredentials(validateCtx, workspace.AWSRegion, creds)
				cancel()
				if validateErr != nil {
					if shouldNotifyCloudCredential(key, false) {
						for _, username := range recipients {
							_, _ = createNotification(ctx, db, username, "AWS static credentials invalid",
								fmt.Sprintf("Workspace %s failed AWS static validation. Re-enter credentials in Workspace Settings.", workspace.Name),
								"warning", "cloud-credentials", fmt.Sprintf("/workspaces/%s/settings", workspace.ID), "high")
						}
					}
				} else {
					shouldNotifyCloudCredential(key, true)
				}
			}
		}

		azureCreds, err := getWorkspaceAzureCredentials(ctx, db, box, workspace.ID)
		if azureCreds != nil {
			key := "azure:" + workspace.ID
			if err != nil || azureCreds.ClientID == "" || azureCreds.ClientSecret == "" {
				if shouldNotifyCloudCredential(key, false) {
					for _, username := range recipients {
						_, _ = createNotification(ctx, db, username, "Azure credentials missing",
							fmt.Sprintf("Workspace %s is missing Azure credentials. Re-enter them in Workspace Settings.", workspace.Name),
							"warning", "cloud-credentials", fmt.Sprintf("/workspaces/%s/settings", workspace.ID), "high")
					}
				}
			} else {
				validateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				_, tokenErr := fetchAzureToken(validateCtx, azureCreds.TenantID, azureCreds.ClientID, azureCreds.ClientSecret)
				cancel()
				if tokenErr != nil {
					if shouldNotifyCloudCredential(key, false) {
						for _, username := range recipients {
							_, _ = createNotification(ctx, db, username, "Azure credentials invalid",
								fmt.Sprintf("Workspace %s failed Azure validation. Re-enter credentials in Workspace Settings.", workspace.Name),
								"warning", "cloud-credentials", fmt.Sprintf("/workspaces/%s/settings", workspace.ID), "high")
						}
					}
				} else {
					shouldNotifyCloudCredential(key, true)
				}
			}
		}

		gcpCreds, err := getWorkspaceGCPCredentials(ctx, db, box, workspace.ID)
		if gcpCreds != nil {
			key := "gcp:" + workspace.ID
			if err != nil || gcpCreds.ServiceAccountJSON == "" {
				if shouldNotifyCloudCredential(key, false) {
					for _, username := range recipients {
						_, _ = createNotification(ctx, db, username, "GCP credentials missing",
							fmt.Sprintf("Workspace %s is missing GCP credentials. Re-enter them in Workspace Settings.", workspace.Name),
							"warning", "cloud-credentials", fmt.Sprintf("/workspaces/%s/settings", workspace.ID), "high")
					}
				}
			} else {
				payload, parseErr := parseGCPServiceAccountJSON(gcpCreds.ServiceAccountJSON)
				if parseErr != nil {
					if shouldNotifyCloudCredential(key, false) {
						for _, username := range recipients {
							_, _ = createNotification(ctx, db, username, "GCP credentials invalid",
								fmt.Sprintf("Workspace %s has invalid GCP credentials. Re-upload JSON in Workspace Settings.", workspace.Name),
								"warning", "cloud-credentials", fmt.Sprintf("/workspaces/%s/settings", workspace.ID), "high")
						}
					}
				} else {
					validateCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
					_, tokenErr := fetchGCPAccessToken(validateCtx, payload)
					cancel()
					if tokenErr != nil {
						if shouldNotifyCloudCredential(key, false) {
							for _, username := range recipients {
								_, _ = createNotification(ctx, db, username, "GCP credentials invalid",
									fmt.Sprintf("Workspace %s failed GCP validation. Re-upload JSON in Workspace Settings.", workspace.Name),
									"warning", "cloud-credentials", fmt.Sprintf("/workspaces/%s/settings", workspace.ID), "high")
							}
						}
					} else {
						shouldNotifyCloudCredential(key, true)
					}
				}
			}
		}
	}
}

// helpers

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("writeJSON error: %v", err)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(lrw, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, lrw.status, time.Since(start))
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.status = code
	lrw.ResponseWriter.WriteHeader(code)
}

func listEveLabsScaffold(owner string, cfg LabsConfig) ([]LabSummary, map[string]any) {
	source := map[string]any{
		"provider": "eve-ng",
		"mode":     "scaffold",
	}
	if cfg.PublicURL != "" {
		source["public_url"] = cfg.PublicURL
	}
	if cfg.EveAPIURL != "" {
		source["eve_api_url"] = cfg.EveAPIURL
	}
	now := time.Now().UTC().Format(time.RFC3339)
	all := []LabSummary{
		{ID: "eve-001", Name: "Branch WAN Demo", Owner: "user1", Status: "running", Provider: "eve-ng", UpdatedAt: now},
		{ID: "eve-002", Name: "Campus Core Lab", Owner: "user2", Status: "running", Provider: "eve-ng", UpdatedAt: now},
		{ID: "eve-003", Name: "Automation Sandbox", Owner: "automation", Status: "stopped", Provider: "eve-ng", UpdatedAt: now},
	}

	if owner == "" {
		running := make([]LabSummary, 0, len(all))
		for _, lab := range all {
			if lab.Status == "running" {
				running = append(running, lab)
			}
		}
		return running, source
	}

	filtered := make([]LabSummary, 0, len(all))
	for _, lab := range all {
		if strings.EqualFold(lab.Owner, owner) {
			filtered = append(filtered, lab)
		}
	}
	return filtered, source
}

type EveLabQuery struct {
	Owner        string
	Mode         string // "running" or "all"
	OnlyProvider string // optional filter (e.g. "eve-ng", "netlab")
	EveServer    string // optional server name filter
}

type LabSource struct {
	Provider  string  `json:"provider"`
	Mode      string  `json:"mode"`
	Transport string  `json:"transport,omitempty"`
	Endpoint  string  `json:"endpoint,omitempty"`
	Meta      JSONMap `json:"meta,omitempty"`
}

func listEveLabs(ctx context.Context, cfg Config, query EveLabQuery) ([]LabSummary, map[string]any, error) {
	servers := cfg.EveServers
	if len(servers) == 0 && cfg.Labs.EveAPIURL != "" {
		servers = []EveServerConfig{{
			Name:          "eve-default",
			APIURL:        cfg.Labs.EveAPIURL,
			WebURL:        strings.TrimSuffix(strings.TrimRight(cfg.Labs.EveAPIURL, "/"), "/api"),
			Username:      cfg.Labs.EveUsername,
			Password:      cfg.Labs.EvePassword,
			SkipTLSVerify: cfg.Labs.EveSkipTLSVerify,
			SSHHost: func() string {
				u, _ := url.Parse(cfg.Labs.EveAPIURL)
				if u != nil {
					return u.Hostname()
				}
				return ""
			}(),
			SSHUser:  cfg.Labs.EveSSHUser,
			LabsPath: cfg.Labs.EveLabsPath,
			TmpPath:  cfg.Labs.EveTmpPath,
		}}
	}

	selected := make([]EveServerConfig, 0, len(servers))
	if strings.TrimSpace(query.EveServer) != "" {
		for _, s := range servers {
			if strings.EqualFold(s.Name, query.EveServer) {
				selected = append(selected, s)
			}
		}
	} else {
		selected = servers
	}

	if len(selected) == 0 {
		labs, source := listEveLabsScaffold(query.Owner, cfg.Labs)
		source["mode"] = "scaffold"
		source["error"] = "no eve-ng servers configured"
		return labs, source, fmt.Errorf("no eve-ng servers configured")
	}

	var lastErr error
	for _, s := range selected {
		s = normalizeEveServer(s, cfg.Labs)
		labsCfg := cfg.Labs
		labsCfg.EveAPIURL = s.APIURL
		labsCfg.EveUsername = s.Username
		labsCfg.EvePassword = s.Password
		labsCfg.EveSkipTLSVerify = s.SkipTLSVerify

		var (
			labs   []LabSummary
			source map[string]any
			err    error
		)
		if strings.TrimSpace(labsCfg.EveSSHKeyFile) != "" {
			sshErr := error(nil)
			labs, source, sshErr = listEveLabsViaSSH(ctx, labsCfg, s, query)
			if sshErr == nil {
				err = nil
			} else if strings.TrimSpace(labsCfg.EveUsername) != "" && strings.TrimSpace(labsCfg.EvePassword) != "" {
				labs2, source2, nativeErr := listEveLabsViaNativeAPI(ctx, labsCfg, query)
				if nativeErr == nil {
					labs, source, err = labs2, source2, nil
				} else {
					err = fmt.Errorf("eve-ng ssh failed (%v); native api failed (%v)", sshErr, nativeErr)
				}
			} else {
				err = sshErr
			}
		} else {
			labs, source, err = listEveLabsViaNativeAPI(ctx, labsCfg, query)
		}
		if err == nil {
			source["server"] = s.Name
			return labs, source, nil
		}
		lastErr = err
	}

	fallbackLabs, fallbackSource := listEveLabsScaffold(query.Owner, cfg.Labs)
	fallbackSource["mode"] = "scaffold"
	fallbackSource["error"] = sanitizeError(lastErr)
	return fallbackLabs, fallbackSource, lastErr
}

func listEveLabsViaNativeAPI(ctx context.Context, cfg LabsConfig, query EveLabQuery) ([]LabSummary, map[string]any, error) {
	if cfg.EveUsername == "" || cfg.EvePassword == "" {
		return nil, nil, fmt.Errorf("native eve-ng api requires SKYFORGE_EVE_USERNAME and SKYFORGE_EVE_PASSWORD")
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.EveSkipTLSVerify},
		},
	}
	candidates := candidateEveBaseURLs(cfg.EveAPIURL)

	var lastErr error
	for _, base := range candidates {
		if err := eveLogin(ctx, client, base, cfg.EveUsername, cfg.EvePassword); err != nil {
			lastErr = err
			continue
		}

		labs, endpoint, err := eveListLabs(ctx, client, base, cfg.EveUsername, query)
		if err != nil {
			lastErr = err
			continue
		}
		source := map[string]any{
			"provider":  "eve-ng",
			"mode":      "live",
			"transport": "eve-native",
			"endpoint":  endpoint,
		}
		return labs, source, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("unable to query eve-ng api")
	}
	return nil, nil, lastErr
}

func listEveLabsViaSSH(ctx context.Context, cfg LabsConfig, server EveServerConfig, query EveLabQuery) ([]LabSummary, map[string]any, error) {
	keyFile := strings.TrimSpace(cfg.EveSSHKeyFile)
	if keyFile == "" {
		return nil, nil, fmt.Errorf("missing SKYFORGE_EVE_SSH_KEY_FILE")
	}
	host := strings.TrimSpace(server.SSHHost)
	if host == "" && strings.TrimSpace(server.APIURL) != "" {
		if u, err := url.Parse(strings.TrimSpace(server.APIURL)); err == nil && u != nil {
			host = strings.TrimSpace(u.Hostname())
		}
	}
	if host == "" && strings.TrimSpace(server.WebURL) != "" {
		if u, err := url.Parse(strings.TrimSpace(server.WebURL)); err == nil && u != nil {
			host = strings.TrimSpace(u.Hostname())
		}
	}
	if host == "" {
		return nil, nil, fmt.Errorf("missing eve server sshHost (or apiUrl/webUrl)")
	}
	user := strings.TrimSpace(server.SSHUser)
	if user == "" {
		user = strings.TrimSpace(cfg.EveSSHUser)
	}

	sshCfg := NetlabConfig{SSHHost: host, SSHUser: user, SSHKeyFile: keyFile, StateRoot: "/"}
	client, err := dialSSH(sshCfg)
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	labsPath := strings.TrimSpace(server.LabsPath)
	if labsPath == "" {
		labsPath = strings.TrimSpace(cfg.EveLabsPath)
	}
	tmpPath := strings.TrimSpace(server.TmpPath)
	if tmpPath == "" {
		tmpPath = strings.TrimSpace(cfg.EveTmpPath)
	}

	listLimit := 250
	if raw := strings.TrimSpace(os.Getenv("SKYFORGE_EVE_SSH_LIST_LIMIT")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 2000 {
			listLimit = v
		}
	}

	source := map[string]any{
		"provider":  "eve-ng",
		"mode":      "live",
		"transport": "ssh",
		"endpoint":  "ssh:" + host,
		"meta": map[string]any{
			"ssh_user":  user,
			"labs_path": labsPath,
			"tmp_path":  tmpPath,
		},
	}

	trimLine := func(s string) string { return strings.TrimSpace(strings.TrimRight(s, "\r\n")) }
	lines := func(out string) []string {
		raw := strings.Split(out, "\n")
		res := make([]string, 0, len(raw))
		for _, line := range raw {
			line = trimLine(line)
			if line != "" {
				res = append(res, line)
			}
		}
		return res
	}

	runningSet := map[string]bool{}
	if strings.TrimSpace(tmpPath) != "" {
		cmd := fmt.Sprintf("find %q -type f -name '*.unl' 2>/dev/null | head -n %d", tmpPath, listLimit)
		if out, err := runSSHCommand(client, cmd, 8*time.Second); err == nil {
			for _, p := range lines(out) {
				runningSet[filepath.Base(p)] = true
			}
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)

	if strings.EqualFold(query.Mode, "running") {
		labs := make([]LabSummary, 0, len(runningSet))
		for file := range runningSet {
			if file == "" {
				continue
			}
			labs = append(labs, LabSummary{
				ID:        file,
				Name:      strings.TrimSuffix(file, filepath.Ext(file)),
				Owner:     "",
				Status:    "running",
				Provider:  "eve-ng",
				UpdatedAt: now,
			})
		}
		return labs, source, nil
	}

	owner := strings.TrimSpace(query.Owner)
	if owner == "" {
		return []LabSummary{}, source, nil
	}

	userDir := fmt.Sprintf("%s/skyforge", strings.TrimRight(labsPath, "/"))
	cmd := fmt.Sprintf("find %q -type f -name '*.unl' 2>/dev/null | head -n %d", userDir, listLimit)
	out, err := runSSHCommand(client, cmd, 10*time.Second)
	if err != nil {
		return nil, source, err
	}

	labs := make([]LabSummary, 0, 64)
	for _, p := range lines(out) {
		file := filepath.Base(p)
		name := strings.TrimSuffix(file, filepath.Ext(file))
		status := "unknown"
		if runningSet[file] {
			status = "running"
		} else {
			status = "stopped"
		}
		labs = append(labs, LabSummary{
			ID:        p,
			Name:      name,
			Owner:     owner,
			Status:    status,
			Provider:  "eve-ng",
			UpdatedAt: now,
		})
	}
	return labs, source, nil
}

func eveLabPathForProject(labsPath, owner, slug string) string {
	labsPath = strings.TrimRight(strings.TrimSpace(labsPath), "/")
	slug = strings.TrimSpace(slug)
	if labsPath == "" || slug == "" {
		return ""
	}
	return fmt.Sprintf("%s/skyforge/%s.unl", labsPath, slug)
}

func ensureEveLabViaSSH(ctx context.Context, cfg LabsConfig, server EveServerConfig, owner, slug string) (string, bool, error) {
	keyFile := strings.TrimSpace(cfg.EveSSHKeyFile)
	if keyFile == "" {
		return "", false, fmt.Errorf("missing SKYFORGE_EVE_SSH_KEY_FILE")
	}
	host := strings.TrimSpace(server.SSHHost)
	if host == "" && strings.TrimSpace(server.APIURL) != "" {
		if u, err := url.Parse(strings.TrimSpace(server.APIURL)); err == nil && u != nil {
			host = strings.TrimSpace(u.Hostname())
		}
	}
	if host == "" && strings.TrimSpace(server.WebURL) != "" {
		if u, err := url.Parse(strings.TrimSpace(server.WebURL)); err == nil && u != nil {
			host = strings.TrimSpace(u.Hostname())
		}
	}
	if host == "" {
		return "", false, fmt.Errorf("missing eve server sshHost (or apiUrl/webUrl)")
	}
	user := strings.TrimSpace(server.SSHUser)
	if user == "" {
		user = strings.TrimSpace(cfg.EveSSHUser)
	}
	labsPath := strings.TrimSpace(server.LabsPath)
	if labsPath == "" {
		labsPath = strings.TrimSpace(cfg.EveLabsPath)
	}
	labPath := eveLabPathForProject(labsPath, owner, slug)
	if labPath == "" {
		return "", false, fmt.Errorf("missing labs path")
	}
	sshCfg := NetlabConfig{SSHHost: host, SSHUser: user, SSHKeyFile: keyFile, StateRoot: "/"}
	client, err := dialSSH(sshCfg)
	if err != nil {
		return "", false, err
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	checkCmd := fmt.Sprintf("test -f %q && echo exists || true", labPath)
	out, _ := runSSHCommand(client, checkCmd, 6*time.Second)
	if strings.Contains(out, "exists") {
		return labPath, true, nil
	}

	dir := filepath.Dir(labPath)
	escapedName := strings.ReplaceAll(slug, `"`, `\"`)
	template := fmt.Sprintf(`<lab name="%s" version="1" scripttimeout="0" lock="0"><description></description><nodes></nodes><networks></networks></lab>`, escapedName)
	createCmd := fmt.Sprintf("mkdir -p %q && cat > %q <<'EOF'\n%s\nEOF\nchown %q:%q %q >/dev/null 2>&1 || true\nchmod 0644 %q >/dev/null 2>&1 || true\n",
		dir, labPath, template, owner, owner, labPath, labPath)
	if _, err := runSSHCommand(client, createCmd, 8*time.Second); err != nil {
		return labPath, false, err
	}
	return labPath, false, nil
}

func eveLabExistsViaSSH(ctx context.Context, cfg LabsConfig, server EveServerConfig, owner, slug string) (bool, string, error) {
	keyFile := strings.TrimSpace(cfg.EveSSHKeyFile)
	if keyFile == "" {
		return false, "", fmt.Errorf("missing SKYFORGE_EVE_SSH_KEY_FILE")
	}
	host := strings.TrimSpace(server.SSHHost)
	if host == "" && strings.TrimSpace(server.APIURL) != "" {
		if u, err := url.Parse(strings.TrimSpace(server.APIURL)); err == nil && u != nil {
			host = strings.TrimSpace(u.Hostname())
		}
	}
	if host == "" && strings.TrimSpace(server.WebURL) != "" {
		if u, err := url.Parse(strings.TrimSpace(server.WebURL)); err == nil && u != nil {
			host = strings.TrimSpace(u.Hostname())
		}
	}
	if host == "" {
		return false, "", fmt.Errorf("missing eve server sshHost (or apiUrl/webUrl)")
	}
	user := strings.TrimSpace(server.SSHUser)
	if user == "" {
		user = strings.TrimSpace(cfg.EveSSHUser)
	}
	labsPath := strings.TrimSpace(server.LabsPath)
	if labsPath == "" {
		labsPath = strings.TrimSpace(cfg.EveLabsPath)
	}
	labPath := eveLabPathForProject(labsPath, owner, slug)
	if labPath == "" {
		return false, "", fmt.Errorf("missing labs path")
	}
	sshCfg := NetlabConfig{SSHHost: host, SSHUser: user, SSHKeyFile: keyFile, StateRoot: "/"}
	client, err := dialSSH(sshCfg)
	if err != nil {
		return false, labPath, err
	}
	defer client.Close()
	out, err := runSSHCommand(client, fmt.Sprintf("test -f %q && echo exists || true", labPath), 5*time.Second)
	if err != nil {
		return false, labPath, err
	}
	return strings.Contains(out, "exists"), labPath, nil
}

func candidateEveBaseURLs(raw string) []string {
	base := strings.TrimRight(raw, "/")
	if strings.HasSuffix(base, "/api") {
		root := strings.TrimSuffix(base, "/api")
		return []string{base, root + "/api", root}
	}
	return []string{base, base + "/api"}
}

func eveLogin(ctx context.Context, client *http.Client, base, username, password string) error {
	endpoints := []string{
		strings.TrimRight(base, "/") + "/api/auth/login",
		strings.TrimRight(base, "/") + "/auth/login",
	}
	for _, endpoint := range endpoints {
		if tryEveLoginJSON(ctx, client, endpoint, username, password) {
			return nil
		}
		if tryEveLoginForm(ctx, client, endpoint, username, password) {
			return nil
		}
	}
	return fmt.Errorf("eve-ng login failed")
}

func tryEveLoginJSON(ctx context.Context, client *http.Client, endpoint, username, password string) bool {
	payload := map[string]string{"username": username, "password": password}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	var parsed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err == nil {
		status := strings.ToLower(firstString(parsed, "status", "result"))
		if status == "" {
			return true
		}
		return status == "success" || status == "ok"
	}
	return true
}

func tryEveLoginForm(ctx context.Context, client *http.Client, endpoint, username, password string) bool {
	data := url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

type eveFolderListing struct {
	Code    int    `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Data    struct {
		Folders []struct {
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"folders"`
		Labs []struct {
			File string `json:"file"`
			Path string `json:"path"`
		} `json:"labs"`
	} `json:"data"`
}

func eveGetFolderListing(ctx context.Context, client *http.Client, base, folder string) (*eveFolderListing, string, error) {
	base = strings.TrimRight(base, "/")
	folder = strings.TrimPrefix(strings.TrimSpace(folder), "/")
	endpoint := base + "/api/folders/"
	if folder != "" {
		endpoint = endpoint + url.PathEscape(folder)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, "", fmt.Errorf("eve-ng folders endpoint %s returned %d", endpoint, resp.StatusCode)
	}
	var parsed eveFolderListing
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, "", err
	}
	return &parsed, endpoint, nil
}

func eveLabsFromListing(listing *eveFolderListing, folder string, query EveLabQuery) []LabSummary {
	if listing == nil {
		return []LabSummary{}
	}
	folder = strings.TrimPrefix(strings.TrimSpace(folder), "/")
	prefix := ""
	if folder != "" {
		prefix = folder + "/"
	}

	status := "unknown"
	if strings.EqualFold(folder, "Running") {
		status = "running"
	}

	owner := ""
	if strings.HasPrefix(strings.ToLower(folder), "users/") {
		owner = strings.TrimPrefix(folder, "Users/")
	}
	if strings.TrimSpace(query.Owner) != "" {
		owner = query.Owner
	}

	out := make([]LabSummary, 0, len(listing.Data.Labs))
	now := time.Now().UTC().Format(time.RFC3339)
	for _, lab := range listing.Data.Labs {
		name := strings.TrimSpace(lab.File)
		if name == "" {
			name = strings.TrimSpace(lab.Path)
		}
		if name == "" {
			continue
		}
		id := strings.TrimSpace(lab.Path)
		if id == "" {
			id = prefix + name
		}
		out = append(out, LabSummary{
			ID:        id,
			Name:      prefix + name,
			Owner:     owner,
			Status:    strings.ToLower(status),
			Provider:  "eve-ng",
			UpdatedAt: now,
		})
	}
	return out
}

type eveNodesResponse struct {
	Code    int             `json:"code"`
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func eveEscapeLabPath(labPath string) string {
	labPath = strings.TrimSpace(labPath)
	if labPath == "" {
		return ""
	}
	// EVE expects the lab path to be URL-encoded as a *single* path segment.
	// That means we must encode slashes as %2F, otherwise nested lab paths
	// are interpreted as URL path separators and the API returns 404.
	escaped := url.PathEscape(labPath)
	return strings.ReplaceAll(escaped, "/", "%2F")
}

func eveLabHasRunningNodes(ctx context.Context, client *http.Client, base string, username string, labPath string) (bool, string, error) {
	base = strings.TrimRight(base, "/")
	if strings.HasSuffix(base, "/api") {
		base = strings.TrimSuffix(base, "/api")
	}
	labPath = strings.TrimSpace(labPath)
	if labPath == "" {
		return false, "", fmt.Errorf("empty eve lab path")
	}
	username = strings.TrimSpace(username)

	// EVE installs differ: some want the lab path with a leading '/', some without.
	// Try both encodings to make the status check robust.
	labCandidates := []string{labPath}
	if strings.HasPrefix(labPath, "/") {
		labCandidates = append(labCandidates, strings.TrimPrefix(labPath, "/"))
	}
	seen := map[string]bool{}
	lastEndpoint := ""

	for _, candidate := range labCandidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" || seen[candidate] {
			continue
		}
		seen[candidate] = true

		labPathEscaped := eveEscapeLabPath(candidate)
		if labPathEscaped == "" {
			continue
		}

		if username != "" {
			endpointUser := base + "/api/labs/" + url.PathEscape(username) + "/" + labPathEscaped + "/nodes"
			lastEndpoint = endpointUser
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointUser, nil)
			if err != nil {
				return false, "", err
			}
			req.Header.Set("Accept", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				return false, "", err
			}
			if resp.StatusCode == http.StatusNotFound {
				// Some EVE installs don't include the authenticated username in the URL.
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				return false, endpointUser, fmt.Errorf("eve-ng nodes endpoint %s returned %d", endpointUser, resp.StatusCode)
			} else {
				defer resp.Body.Close()
				return eveNodesHasRunning(endpointUser, resp)
			}
		}

		endpointLegacy := base + "/api/labs/" + labPathEscaped + "/nodes"
		lastEndpoint = endpointLegacy
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointLegacy, nil)
		if err != nil {
			return false, "", err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return false, "", err
		}
		if resp.StatusCode == http.StatusNotFound {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_, _ = io.Copy(io.Discard, resp.Body)
			return false, endpointLegacy, fmt.Errorf("eve-ng nodes endpoint %s returned %d", endpointLegacy, resp.StatusCode)
		}
		return eveNodesHasRunning(endpointLegacy, resp)
	}

	if lastEndpoint == "" {
		lastEndpoint = base + "/api/labs/<labPath>/nodes"
	}
	return false, lastEndpoint, fmt.Errorf("eve-ng nodes endpoint %s returned 404", lastEndpoint)
}

func eveNodesHasRunning(endpoint string, resp *http.Response) (bool, string, error) {
	var parsed eveNodesResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return false, endpoint, err
	}

	raw := bytes.TrimSpace(parsed.Data)
	if len(raw) == 0 || string(raw) == "null" {
		return false, endpoint, nil
	}

	if len(raw) > 0 && raw[0] == '{' {
		var nodes map[string]struct {
			Status int `json:"status"`
		}
		if err := json.Unmarshal(raw, &nodes); err != nil {
			return false, endpoint, err
		}
		for _, node := range nodes {
			if node.Status != 0 {
				return true, endpoint, nil
			}
		}
		return false, endpoint, nil
	}

	if len(raw) > 0 && raw[0] == '[' {
		var nodes []struct {
			Status int `json:"status"`
		}
		if err := json.Unmarshal(raw, &nodes); err != nil {
			return false, endpoint, err
		}
		for _, node := range nodes {
			if node.Status != 0 {
				return true, endpoint, nil
			}
		}
		return false, endpoint, nil
	}

	return false, endpoint, nil
}

func eveListLabs(ctx context.Context, client *http.Client, base string, username string, query EveLabQuery) ([]LabSummary, string, error) {
	// Normalize base to the EVE host root (strip trailing /api if present).
	base = strings.TrimRight(base, "/")
	if strings.HasSuffix(base, "/api") {
		base = strings.TrimSuffix(base, "/api")
	}

	foldersToQuery := []string{}
	if strings.EqualFold(query.Mode, "running") {
		foldersToQuery = []string{"Running"}
	} else if strings.TrimSpace(query.Owner) != "" {
		foldersToQuery = []string{"Users/" + query.Owner}
		if strings.EqualFold(strings.TrimSpace(os.Getenv("SKYFORGE_EVE_USER_ROOT_FALLBACK")), "true") {
			foldersToQuery = append(foldersToQuery, "")
		}
	} else {
		foldersToQuery = []string{""}
	}

	var (
		allLabs    []LabSummary
		lastErr    error
		lastSource string
	)
	for _, folder := range foldersToQuery {
		listing, endpoint, err := eveGetFolderListing(ctx, client, base, folder)
		if err != nil {
			lastErr = err
			continue
		}
		lastSource = endpoint
		allLabs = append(allLabs, eveLabsFromListing(listing, folder, query)...)
	}

	if strings.EqualFold(query.Mode, "running") && len(allLabs) == 0 {
		// EVE installs vary; many do not provide a populated "Running" folder. In that case, we fall back
		// to scanning a limited number of labs from the root and checking node status to infer "running".
		listing, endpoint, err := eveGetFolderListing(ctx, client, base, "")
		if err == nil {
			lastSource = endpoint
			allLabs = eveLabsFromListing(listing, "", query)
		} else if lastErr == nil {
			lastErr = err
		}

		limit := 25
		if skyforgeEncoreCfg.EveRunningScan.Limit > 0 && skyforgeEncoreCfg.EveRunningScan.Limit <= 500 {
			limit = skyforgeEncoreCfg.EveRunningScan.Limit
		}
		if raw := strings.TrimSpace(os.Getenv("SKYFORGE_EVE_RUNNING_SCAN_LIMIT")); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 500 {
				limit = v
			}
		}
		if len(allLabs) > limit {
			allLabs = allLabs[:limit]
		}

		type labResult struct {
			idx     int
			running bool
		}

		workers := 8
		if skyforgeEncoreCfg.EveRunningScan.Workers > 0 && skyforgeEncoreCfg.EveRunningScan.Workers <= 32 {
			workers = skyforgeEncoreCfg.EveRunningScan.Workers
		}
		if raw := strings.TrimSpace(os.Getenv("SKYFORGE_EVE_RUNNING_SCAN_WORKERS")); raw != "" {
			if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 32 {
				workers = v
			}
		}

		budget := 4 * time.Second
		if skyforgeEncoreCfg.EveRunningScan.BudgetSeconds > 0 && skyforgeEncoreCfg.EveRunningScan.BudgetSeconds <= 60 {
			budget = time.Duration(skyforgeEncoreCfg.EveRunningScan.BudgetSeconds) * time.Second
		}
		if raw := strings.TrimSpace(os.Getenv("SKYFORGE_EVE_RUNNING_SCAN_BUDGET")); raw != "" {
			if v, err := time.ParseDuration(raw); err == nil && v > 0 && v <= 60*time.Second {
				budget = v
			}
		}
		scanCtx := ctx
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			scanCtx, cancel = context.WithTimeout(ctx, budget)
			defer cancel()
		}

		jobs := make(chan int)
		results := make(chan labResult)
		var scanErrMu sync.Mutex
		var scanErr error
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for idx := range jobs {
					lab := allLabs[idx]
					perLabTimeout := 3 * time.Second
					if skyforgeEncoreCfg.EveRunningScan.PerLabTimeoutSeconds > 0 && skyforgeEncoreCfg.EveRunningScan.PerLabTimeoutSeconds <= 30 {
						perLabTimeout = time.Duration(skyforgeEncoreCfg.EveRunningScan.PerLabTimeoutSeconds) * time.Second
					}
					perCall, cancel := context.WithTimeout(scanCtx, perLabTimeout)
					running, _, err := eveLabHasRunningNodes(perCall, client, base, username, lab.ID)
					cancel()
					if err != nil {
						scanErrMu.Lock()
						if scanErr == nil {
							scanErr = err
						}
						scanErrMu.Unlock()
					}
					results <- labResult{idx: idx, running: running}
				}
			}()
		}

		go func() {
			for idx := range allLabs {
				select {
				case <-scanCtx.Done():
					close(jobs)
					wg.Wait()
					close(results)
					return
				case jobs <- idx:
				}
			}
			close(jobs)
			wg.Wait()
			close(results)
		}()

		runningSet := make(map[int]bool, len(allLabs))
		for res := range results {
			runningSet[res.idx] = res.running
		}

		runningLabs := make([]LabSummary, 0, len(allLabs))
		for idx, lab := range allLabs {
			if runningSet[idx] {
				lab.Status = "running"
				runningLabs = append(runningLabs, lab)
			}
		}
		allLabs = runningLabs
		if scanErr != nil && lastErr == nil {
			lastErr = scanErr
		}
	}

	if lastErr != nil && len(allLabs) == 0 {
		return nil, "", lastErr
	}
	if lastSource == "" {
		lastSource = strings.TrimRight(base, "/") + "/api/folders/"
	}
	return allLabs, lastSource, nil
}

func decodeJSONArrayOrObject(r io.Reader) (any, error) {
	var decoded any
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}

func parseLabSummaries(raw any, query EveLabQuery) []LabSummary {
	var items []any
	switch v := raw.(type) {
	case []any:
		items = v
	case map[string]any:
		for _, key := range []string{"labs", "items", "result"} {
			if arr, ok := v[key].([]any); ok {
				items = arr
				break
			}
		}
		if len(items) == 0 {
			if data, ok := v["data"].(map[string]any); ok {
				if arr, ok := data["labs"].([]any); ok {
					items = arr
				} else if m, ok := data["labs"].(map[string]any); ok {
					for _, val := range m {
						items = append(items, val)
					}
				} else if m, ok := data["items"].(map[string]any); ok {
					for _, val := range m {
						items = append(items, val)
					}
				} else if arr, ok := data["items"].([]any); ok {
					items = arr
				}
			}
		}
	}

	labs := make([]LabSummary, 0, len(items))
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := firstString(obj, "name", "title", "lab", "path", "filename")
		id := firstString(obj, "id", "lab_id", "uuid", "path", "filename")
		if id == "" {
			id = name
		}
		owner := firstString(obj, "owner", "user", "username", "created_by")
		status := firstString(obj, "status", "state")
		if status == "" {
			if b, ok := obj["running"].(bool); ok {
				if b {
					status = "running"
				} else {
					status = "stopped"
				}
			} else {
				status = "unknown"
			}
		}

		labs = append(labs, LabSummary{
			ID:        id,
			Name:      name,
			Owner:     owner,
			Status:    strings.ToLower(status),
			Provider:  "eve-ng",
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}

	if query.Mode == "running" {
		running := make([]LabSummary, 0, len(labs))
		for _, lab := range labs {
			if lab.Status == "running" {
				running = append(running, lab)
			}
		}
		labs = running
	}

	if query.Owner != "" {
		filtered := make([]LabSummary, 0, len(labs))
		for _, lab := range labs {
			if lab.Owner == "" {
				continue
			}
			if strings.EqualFold(lab.Owner, query.Owner) {
				filtered = append(filtered, lab)
			}
		}
		labs = filtered
	}

	return labs
}

func firstString(obj map[string]any, keys ...string) string {
	for _, key := range keys {
		if raw, ok := obj[key]; ok {
			if val, ok := raw.(string); ok && strings.TrimSpace(val) != "" {
				return strings.TrimSpace(val)
			}
			if val, ok := raw.(json.Number); ok {
				return val.String()
			}
		}
	}
	return ""
}

func parseActorFromMessage(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	lastOpen := strings.LastIndex(message, "(")
	lastClose := strings.LastIndex(message, ")")
	if lastOpen == -1 || lastClose == -1 || lastClose < lastOpen {
		return ""
	}
	if strings.TrimSpace(message[lastClose+1:]) != "" {
		return ""
	}
	candidate := strings.TrimSpace(message[lastOpen+1 : lastClose])
	if candidate == "" {
		return ""
	}
	for _, r := range candidate {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return ""
	}
	return candidate
}

type ProviderQuery struct {
	Owner        string
	Mode         string
	OnlyProvider string
	PublicOnly   bool
	EveServer    string
	NetlabServer string
}

func listLabProviders(ctx context.Context, cfg Config, query ProviderQuery) ([]LabSummary, []LabSource) {
	labs := make([]LabSummary, 0, 64)
	sources := make([]LabSource, 0, 4)
	providers := labProvidersForQuery(cfg, query)
	for _, provider := range providers {
		if query.PublicOnly && provider.publicOnly {
			continue
		}
		items, source, err := provider.list(ctx, cfg, query)
		if err != nil {
			source["error"] = sanitizeError(err)
		}
		launchURL := ""
		if provider.launchURL != nil {
			launchURL = provider.launchURL(cfg)
		}
		items = normalizeLabSummaries(provider.name, launchURL, items)
		if strings.TrimSpace(firstString(source, "provider")) == "" {
			source["provider"] = provider.name
		}
		sources = appendLabSource(sources, source)
		labs = append(labs, items...)
	}
	return labs, sources
}

func listNetlabLabs(ctx context.Context, cfg Config, netlabCfg NetlabConfig, owner string, mode string) ([]LabSummary, map[string]any, error) {
	source := map[string]any{
		"provider":  "netlab",
		"mode":      "live",
		"transport": "ssh",
		"endpoint":  "ssh:" + netlabCfg.SSHHost,
	}

	if netlabCfg.SSHHost == "" || netlabCfg.SSHKeyFile == "" {
		source["mode"] = "disabled"
		return []LabSummary{}, source, fmt.Errorf("netlab runner is not configured")
	}

	client, err := dialSSH(netlabCfg)
	if err != nil {
		return []LabSummary{}, source, err
	}
	defer client.Close()

	limit := 50
	cmd := fmt.Sprintf("find %q -maxdepth 2 -type f -name metadata.json 2>/dev/null | head -n %d", netlabCfg.StateRoot, limit)
	out, err := runSSHCommand(client, cmd, 10*time.Second)
	if err != nil {
		return []LabSummary{}, source, err
	}
	paths := strings.Fields(out)

	labs := make([]LabSummary, 0, len(paths))
	now := time.Now().UTC().Format(time.RFC3339)
	for _, p := range paths {
		content, err := runSSHCommand(client, fmt.Sprintf("cat %q", p), 10*time.Second)
		if err != nil {
			continue
		}
		var meta map[string]any
		if err := json.Unmarshal([]byte(content), &meta); err != nil {
			continue
		}
		labID := extractLabIDFromMetadataPath(netlabCfg.StateRoot, p)
		name := firstString(meta, "name", "lab", "title", "scenario")
		if name == "" {
			name = labID
		}
		labOwner := firstString(meta, "owner", "user", "username", "created_by")
		status := strings.ToLower(firstString(meta, "status", "state"))
		if status == "" {
			status = "running"
		}
		labs = append(labs, LabSummary{
			ID:        "netlab:" + labID,
			Name:      name,
			Owner:     labOwner,
			Status:    status,
			Provider:  "netlab",
			UpdatedAt: firstString(meta, "updated_at", "updatedAt", "timestamp"),
		})
		if labs[len(labs)-1].UpdatedAt == "" {
			labs[len(labs)-1].UpdatedAt = now
		}
	}

	if owner != "" {
		filtered := make([]LabSummary, 0, len(labs))
		for _, lab := range labs {
			if lab.Owner == "" {
				continue
			}
			if strings.EqualFold(lab.Owner, owner) {
				filtered = append(filtered, lab)
			}
		}
		labs = filtered
	}

	if mode == "running" {
		running := make([]LabSummary, 0, len(labs))
		for _, lab := range labs {
			if lab.Status == "running" {
				running = append(running, lab)
			}
		}
		labs = running
	}

	return labs, source, nil
}

func parseSkyforgeMarkers(output []map[string]any) (map[string]string, map[string]string) {
	labs := map[string]string{}
	artifacts := map[string]string{}
	for _, row := range output {
		out, _ := row["output"].(string)
		if out == "" {
			continue
		}
		line := strings.TrimSpace(out)
		if strings.Contains(line, "SKYFORGE_OUTPUT ") {
			parts := strings.SplitN(line, "SKYFORGE_OUTPUT ", 2)
			if len(parts) == 2 {
				kv := strings.TrimSpace(parts[1])
				key, val, ok := strings.Cut(kv, "=")
				if ok {
					key = strings.TrimSpace(key)
					val = strings.TrimSpace(val)
					if key != "" && val != "" {
						labs[key] = val
					}
				}
			}
		}
		if strings.Contains(line, "SKYFORGE_ARTIFACT ") {
			parts := strings.SplitN(line, "SKYFORGE_ARTIFACT ", 2)
			if len(parts) == 2 {
				kv := strings.TrimSpace(parts[1])
				key, val, ok := strings.Cut(kv, "=")
				if ok {
					key = strings.TrimSpace(key)
					val = strings.TrimSpace(val)
					if key != "" && val != "" {
						artifacts[key] = val
					}
				}
			}
		}
	}
	return labs, artifacts
}

func firstNumber(obj map[string]any, keys ...string) float64 {
	for _, key := range keys {
		if raw, ok := obj[key]; ok {
			switch v := raw.(type) {
			case float64:
				return v
			case int:
				return float64(v)
			case int64:
				return float64(v)
			case json.Number:
				if f, err := v.Float64(); err == nil {
					return f
				}
			}
		}
	}
	return 0
}
