package skyforge

import "encore.dev/config"

type encoreEveRunningScanConfig struct {
	Limit                int
	Workers              int
	BudgetSeconds        int
	PerLabTimeoutSeconds int
}

type encoreNetlabDefaultsConfig struct {
	SSHHost    string
	SSHUser    string
	SSHKeyFile string
	StateRoot  string
}

type encoreLabppDefaultsConfig struct {
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

type encoreIntegrationDefaultsConfig struct {
	GiteaBaseURL            string
	NetboxBaseURL           string
	NetboxInternalBaseURL   string
	NautobotBaseURL         string
	NautobotInternalBaseURL string
	YaadeBaseURL            string
	YaadeInternalBaseURL    string
}

type encoreLabsDefaultsConfig struct {
	EveSSHUser   string
	EveSSHTunnel bool
	EveLabsPath  string
	EveTmpPath   string
}

type encoreDNSDefaultsConfig struct {
	URL string
}

type encoreContainerlabDefaultsConfig struct {
	APIPath string
}

type encoreSkyforgeConfig struct {
	TaskWorkerEnabled bool

	NotificationsIntervalSeconds int
	CloudCheckIntervalMinutes    int

	EveRunningScan encoreEveRunningScanConfig
	Netlab         encoreNetlabDefaultsConfig
	Labpp          encoreLabppDefaultsConfig
	Integrations   encoreIntegrationDefaultsConfig
	Labs           encoreLabsDefaultsConfig
	DNS            encoreDNSDefaultsConfig
	Containerlab   encoreContainerlabDefaultsConfig
}

var skyforgeEncoreCfg = config.Load[encoreSkyforgeConfig]()
