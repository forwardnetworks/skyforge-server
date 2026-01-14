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

type encoreSkyforgeConfig struct {
	TaskWorkerEnabled bool

	NotificationsIntervalSeconds int
	CloudCheckIntervalMinutes    int

	EveRunningScan encoreEveRunningScanConfig
	Netlab         encoreNetlabDefaultsConfig
	Labpp          encoreLabppDefaultsConfig
}

var skyforgeEncoreCfg = config.Load[encoreSkyforgeConfig]()
