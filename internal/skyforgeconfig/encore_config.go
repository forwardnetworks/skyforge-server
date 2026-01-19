package skyforgeconfig

type NetlabDefaultsConfig struct {
	SSHHost    string
	SSHUser    string
	SSHKeyFile string
	StateRoot  string
}

type IntegrationDefaultsConfig struct {
	GiteaBaseURL            string
	NetboxBaseURL           string
	NetboxInternalBaseURL   string
	NautobotBaseURL         string
	NautobotInternalBaseURL string
	YaadeBaseURL            string
	YaadeInternalBaseURL    string
}

type OIDCDefaultsConfig struct {
	IssuerURL    string
	DiscoveryURL string
	RedirectURL  string
}

type LDAPDefaultsConfig struct {
	BaseDN          string
	DisplayNameAttr string
	MailAttr        string
	GroupAttr       string
	UseStartTLS     bool
	SkipTLSVerify   bool
}

type DNSDefaultsConfig struct {
	URL            string
	AdminUsername  string
	UserZoneSuffix string
}

type ContainerlabDefaultsConfig struct {
	APIPath       string
	SkipTLSVerify bool
}

type NetlabGeneratorDefaultsConfig struct {
	C9sGeneratorMode  string
	GeneratorImage    string
	PullPolicy        string
	AnsibleImage      string
	AnsiblePullPolicy string
}

type KubernetesDefaultsConfig struct {
	ImagePullSecretName      string
	ImagePullSecretNamespace string
}

type UIDefaultsConfig struct {
	ProductName      string
	ProductSubtitle  string
	LogoURL          string
	LogoAlt          string
	HeaderBackground string
	SupportText      string
	SupportURL       string
	ThemeDefault     string
}

type WorkspacesDefaultsConfig struct {
	DataDir          string
	GiteaAPIURL      string
	GiteaUsername    string
	GiteaRepoPrivate bool
	DeleteMode       string
}

type ObjectStorageDefaultsConfig struct {
	Endpoint string
	UseSSL   bool
}

type TerraformDefaultsConfig struct {
	BinaryPath string
	Version    string
	URL        string
}

type ForwardDefaultsConfig struct {
	SNMPPlaceholderEnabled bool
	SNMPCommunity          string
}

type EncoreConfig struct {
	TaskWorkerEnabled    bool
	DisableEncoreCache   bool
	NotificationsEnabled bool

	StaticRoot string

	AdminUsers      string
	AdminUsername   string
	CorpEmailDomain string

	PublicURL string

	ListenAddr    string
	SessionCookie string
	SessionTTL    string
	CookieSecure  string
	CookieDomain  string
	MaxGroups     int

	PKIDefaultDays   int
	SSHCADefaultDays int

	NotificationsIntervalSeconds int
	CloudCheckIntervalMinutes    int

	AwsSSOStartURL     string
	AwsSSORegion       string
	AwsSSOAccountID    string
	AwsSSORoleName     string
	YaadeAdminUsername string

	Netlab          NetlabDefaultsConfig
	Integrations    IntegrationDefaultsConfig
	UI              UIDefaultsConfig
	OIDC            OIDCDefaultsConfig
	LDAP            LDAPDefaultsConfig
	DNS             DNSDefaultsConfig
	Containerlab    ContainerlabDefaultsConfig
	Workspaces      WorkspacesDefaultsConfig
	ObjectStorage   ObjectStorageDefaultsConfig
	Terraform       TerraformDefaultsConfig
	Forward         ForwardDefaultsConfig
	NetlabGenerator NetlabGeneratorDefaultsConfig
	Kubernetes      KubernetesDefaultsConfig
}
