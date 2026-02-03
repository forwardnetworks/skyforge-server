package skyforgecore

import "time"

// Config holds Skyforge runtime configuration.
//
// This package is a non-service library so it can be shared by both the API service
// and the worker service without creating a Go-package dependency on the skyforge
// service package implementation.
type Config struct {
	ListenAddr                string
	SessionSecret             string
	SessionTTL                time.Duration
	SessionCookie             string
	CookieSecure              string
	CookieDomain              string
	InternalToken             string
	StaticRoot                string
	MaxGroups                 int
	AdminUsers                []string
	AdminUsername             string
	AdminPassword             string
	E2EAdminEnabled           bool
	E2EAdminToken             string
	UI                        UIConfig
	PublicURL                 string
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
	NetboxInternalBaseURL     string
	NautobotBaseURL           string
	NautobotInternalBaseURL   string
	YaadeBaseURL              string
	YaadeInternalBaseURL      string
	Netlab                    NetlabConfig
	OIDC                      OIDCConfig
	LDAP                      LDAPConfig
	LDAPLookupBindDN          string
	LDAPLookupBindPassword    string
	Workspaces                WorkspacesConfig
	TerraformBinaryPath       string
	TerraformVersion          string
	TerraformURL              string
	YaadeAdminUsername        string
	YaadeAdminPassword        string
	ContainerlabAPIPath       string
	ContainerlabJWTSecret     string
	ContainerlabSkipTLSVerify bool
	// NetlabC9sGeneratorMode controls how netlab-c9s artifacts are generated:
	// - "remote": use a BYOS netlab API server
	// - "k8s": run a netlab generator Job in-cluster
	NetlabC9sGeneratorMode                   string
	NetlabGeneratorImage                     string
	NetlabGeneratorPullPolicy                string
	NetlabApplierImage                       string
	NetlabApplierPullPolicy                  string
	PKICACert                                string
	PKICAKey                                 string
	PKIDefaultDays                           int
	SSHCAKey                                 string
	SSHCADefaultDays                         int
	DNSURL                                   string
	DNSAdminUsername                         string
	DNSUserZoneSuffix                        string
	AIEnabled                                bool
	GeminiEnabled                            bool
	GeminiClientID                           string
	GeminiClientSecret                       string
	GeminiRedirectURL                        string
	GeminiProjectID                          string
	GeminiLocation                           string
	GeminiModel                              string
	GeminiFallbackModel                      string
	TaskWorkerEnabled                        bool
	ImagePullSecretName                      string
	ImagePullSecretNamespace                 string
	ForwardCollectorImage                    string
	ForwardCollectorPullPolicy               string
	ForwardCollectorImagePullSecretName      string
	ForwardCollectorImagePullSecretNamespace string
	// ForwardCollectorHeapSizeGB sets COLLECTOR_HEAP_SIZE for the in-cluster
	// collector container. When 0, the image default is used.
	ForwardCollectorHeapSizeGB int
	Forward                    ForwardConfig
	Features                   FeaturesConfig
}

type ForwardConfig struct {
	SNMPPlaceholderEnabled bool
	SNMPCommunity          string
}

type FeaturesConfig struct {
	GiteaEnabled     bool `json:"giteaEnabled"`
	MinioEnabled     bool `json:"minioEnabled"`
	DexEnabled       bool `json:"dexEnabled"`
	CoderEnabled     bool `json:"coderEnabled"`
	YaadeEnabled     bool `json:"yaadeEnabled"`
	SwaggerUIEnabled bool `json:"swaggerUIEnabled"`
	ForwardEnabled   bool `json:"forwardEnabled"`
	NetboxEnabled    bool `json:"netboxEnabled"`
	NautobotEnabled  bool `json:"nautobotEnabled"`
	DNSEnabled       bool `json:"dnsEnabled"`
}

type OIDCConfig struct {
	IssuerURL string
	// DiscoveryURL optionally overrides where Skyforge fetches the OIDC discovery document.
	// This is useful when the issuer URL is only reachable via an external ingress hostname,
	// but the service itself is reachable in-cluster (e.g. Dex at http://dex:5556/dex).
	//
	// When set, Skyforge uses go-oidc's InsecureIssuerURLContext to allow the discovery
	// document to specify the external issuer while being fetched from the internal URL.
	DiscoveryURL string
	ClientID     string
	ClientSecret string
	RedirectURL  string
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

type WorkspacesConfig struct {
	DataDir                string
	GiteaAPIURL            string
	GiteaUsername          string
	GiteaPassword          string
	GiteaRepoPrivate       bool
	DeleteMode             string
	ObjectStorageEndpoint  string
	ObjectStorageUseSSL    bool
	ObjectStorageAccessKey string
	ObjectStorageSecretKey string
}

// SkyforgeWorkspace is the user-facing workspace object stored in Postgres and
// returned by the API.
type SkyforgeWorkspace struct {
	ID                         string                 `json:"id"`
	Slug                       string                 `json:"slug"`
	Name                       string                 `json:"name"`
	Description                string                 `json:"description,omitempty"`
	CreatedAt                  time.Time              `json:"createdAt"`
	CreatedBy                  string                 `json:"createdBy"`
	IsPublic                   bool                   `json:"isPublic"`
	Owners                     []string               `json:"owners,omitempty"`
	OwnerGroups                []string               `json:"ownerGroups,omitempty"`
	Editors                    []string               `json:"editors,omitempty"`
	EditorGroups               []string               `json:"editorGroups,omitempty"`
	Viewers                    []string               `json:"viewers,omitempty"`
	ViewerGroups               []string               `json:"viewerGroups,omitempty"`
	Blueprint                  string                 `json:"blueprint,omitempty"`
	DefaultBranch              string                 `json:"defaultBranch,omitempty"`
	AllowExternalTemplateRepos bool                   `json:"allowExternalTemplateRepos,omitempty"`
	AllowCustomEveServers      bool                   `json:"allowCustomEveServers,omitempty"`
	AllowCustomNetlabServers   bool                   `json:"allowCustomNetlabServers,omitempty"`
	ExternalTemplateRepos      []ExternalTemplateRepo `json:"externalTemplateRepos,omitempty"`
	TerraformStateKey          string                 `json:"terraformStateKey,omitempty"`
	TerraformInitTemplateID    int                    `json:"terraformInitTemplateId,omitempty"`
	TerraformPlanTemplateID    int                    `json:"terraformPlanTemplateId,omitempty"`
	TerraformApplyTemplateID   int                    `json:"terraformApplyTemplateId,omitempty"`
	AnsibleRunTemplateID       int                    `json:"ansibleRunTemplateId,omitempty"`
	NetlabRunTemplateID        int                    `json:"netlabRunTemplateId,omitempty"`
	EveNgRunTemplateID         int                    `json:"eveNgRunTemplateId,omitempty"`
	ContainerlabRunTemplateID  int                    `json:"containerlabRunTemplateId,omitempty"`
	AWSAccountID               string                 `json:"awsAccountId,omitempty"`
	AWSRoleName                string                 `json:"awsRoleName,omitempty"`
	AWSRegion                  string                 `json:"awsRegion,omitempty"`
	AWSAuthMethod              string                 `json:"awsAuthMethod,omitempty"`
	ArtifactsBucket            string                 `json:"artifactsBucket,omitempty"`
	EveServer                  string                 `json:"eveServer,omitempty"`
	NetlabServer               string                 `json:"netlabServer,omitempty"`
	GiteaOwner                 string                 `json:"giteaOwner"`
	GiteaRepo                  string                 `json:"giteaRepo"`
}

type ExternalTemplateRepo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Repo          string `json:"repo"` // gitea owner/repo
	DefaultBranch string `json:"defaultBranch,omitempty"`
}

type Secrets struct {
	SessionSecret          string
	AdminPassword          string
	E2EAdminToken          string
	OIDCClientID           string
	OIDCClientSecret       string
	LDAPURL                string
	LDAPBindTemplate       string
	LDAPLookupBindDN       string
	LDAPLookupBindPassword string
	DBPassword             string
	GiteaPassword          string
	ObjectStorageAccessKey string
	ObjectStorageSecretKey string
	InternalToken          string
	ContainerlabJWTSecret  string
	PKICACert              string
	PKICAKey               string
	SSHCAKey               string
	YaadeAdminPassword     string
	GeminiClientSecret     string
}
