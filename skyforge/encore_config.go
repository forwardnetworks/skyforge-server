package skyforge

import "encore.dev/config"

type encoreEveRunningScanConfig struct {
	Limit                int
	Workers              int
	BudgetSeconds        int
	PerLabTimeoutSeconds int
}

type encoreSkyforgeConfig struct {
	TaskWorkerEnabled bool

	NotificationsIntervalSeconds int
	CloudCheckIntervalMinutes    int

	EveRunningScan encoreEveRunningScanConfig
}

var skyforgeEncoreCfg = config.Load[encoreSkyforgeConfig]()
