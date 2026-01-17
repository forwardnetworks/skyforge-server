package skyforgeconfig

type EveRunningScanConfig struct {
	Limit                int
	Workers              int
	BudgetSeconds        int
	PerLabTimeoutSeconds int
}

type NetlabDefaultsConfig struct {
	SSHHost    string
	SSHUser    string
	SSHKeyFile string
	StateRoot  string
}

type LabppDefaultsConfig struct {
	RunnerImage       string
	RunnerPullPolicy  string
	RunnerPVCName     string
	ConfigDirBase     string
	ConfigVersion     string
	NetboxURL         string
	NetboxMgmtSubnet  string
	S3Region          string
	S3BucketName      string
	S3Endpoint        string
	S3DisableSSL      bool
	S3DisableChecksum bool
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

type LabsDefaultsConfig struct {
	EveSSHUser   string
	EveSSHTunnel bool
	EveLabsPath  string
	EveTmpPath   string
}

type DNSDefaultsConfig struct {
	URL string
}

type ContainerlabDefaultsConfig struct {
	APIPath string
}

type EncoreConfig struct {
	TaskWorkerEnabled bool

	NotificationsIntervalSeconds int
	CloudCheckIntervalMinutes    int
	EveUserRootFallback          bool

	EveRunningScan EveRunningScanConfig
	Netlab         NetlabDefaultsConfig
	Labpp          LabppDefaultsConfig
	Integrations   IntegrationDefaultsConfig
	Labs           LabsDefaultsConfig
	DNS            DNSDefaultsConfig
	Containerlab   ContainerlabDefaultsConfig
}
