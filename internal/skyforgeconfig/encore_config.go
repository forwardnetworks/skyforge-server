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

type GeminiDefaultsConfig struct {
	Enabled     bool
	ClientID    string
	RedirectURL string
	ProjectID   string
	Location    string
	Model       string
}

type AIDefaultsConfig struct {
	Enabled bool
}

type ContainerlabDefaultsConfig struct {
	APIPath       string
	SkipTLSVerify bool
}

type NetlabGeneratorDefaultsConfig struct {
	C9sGeneratorMode string
	GeneratorImage   string
	PullPolicy       string
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

type ForwardCollectorDefaultsConfig struct {
	// Image is the container image used for the in-cluster Forward collector.
	//
	// When empty, Skyforge will not attempt to deploy a collector Pod and the UI
	// will show the collector as "not configured".
	Image string
	// PullPolicy controls Kubernetes image pull behavior (e.g. Always, IfNotPresent).
	PullPolicy string
	// ImagePullSecretName is an optional registry secret name used to pull the image.
	// When empty, Skyforge falls back to Kubernetes.ImagePullSecretName.
	ImagePullSecretName string
	// ImagePullSecretNamespace is the namespace where ImagePullSecretName lives.
	// When empty, Skyforge falls back to Kubernetes.ImagePullSecretNamespace.
	ImagePullSecretNamespace string
	// HeapSizeGB sets COLLECTOR_HEAP_SIZE (in gigabytes) for the collector.
	// When 0, the collector image default is used.
	HeapSizeGB int
}

type FeaturesDefaultsConfig struct {
	GiteaEnabled     bool
	MinioEnabled     bool
	DexEnabled       bool
	CoderEnabled     bool
	YaadeEnabled     bool
	SwaggerUIEnabled bool
	ForwardEnabled   bool
	NetboxEnabled    bool
	NautobotEnabled  bool
	DNSEnabled       bool
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

	Netlab           NetlabDefaultsConfig
	Integrations     IntegrationDefaultsConfig
	UI               UIDefaultsConfig
	OIDC             OIDCDefaultsConfig
	LDAP             LDAPDefaultsConfig
	DNS              DNSDefaultsConfig
	Gemini           GeminiDefaultsConfig
	AI               AIDefaultsConfig
	Containerlab     ContainerlabDefaultsConfig
	Workspaces       WorkspacesDefaultsConfig
	ObjectStorage    ObjectStorageDefaultsConfig
	Terraform        TerraformDefaultsConfig
	Forward          ForwardDefaultsConfig
	ForwardCollector ForwardCollectorDefaultsConfig
	Features         FeaturesDefaultsConfig
	NetlabGenerator  NetlabGeneratorDefaultsConfig
	Kubernetes       KubernetesDefaultsConfig
}

type WorkerConfig struct {
	TaskWorkerEnabled bool

	Netlab           NetlabDefaultsConfig
	Workspaces       WorkspacesDefaultsConfig
	ObjectStorage    ObjectStorageDefaultsConfig
	Terraform        TerraformDefaultsConfig
	Forward          ForwardDefaultsConfig
	ForwardCollector ForwardCollectorDefaultsConfig
	Features         FeaturesDefaultsConfig
	NetlabGenerator  NetlabGeneratorDefaultsConfig
	Kubernetes       KubernetesDefaultsConfig
}
