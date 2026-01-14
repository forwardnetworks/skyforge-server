package skyforge

import "encore.dev/config"

type encoreSkyforgeConfig struct {
	TaskWorkerEnabled bool `json:"taskWorkerEnabled"`

	NotificationsIntervalSeconds int `json:"notificationsIntervalSeconds"`
	CloudCheckIntervalMinutes    int `json:"cloudCheckIntervalMinutes"`

	EveRunningScan struct {
		Limit                int `json:"limit"`
		Workers              int `json:"workers"`
		BudgetSeconds        int `json:"budgetSeconds"`
		PerLabTimeoutSeconds int `json:"perLabTimeoutSeconds"`
	} `json:"eveRunningScan"`
}

var skyforgeEncoreCfg = config.Load[encoreSkyforgeConfig]()
