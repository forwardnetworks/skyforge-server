// Skyforge service configuration (Encore).
//
// These defaults can be overridden at deploy time using ENCORE_RUNTIME_CONFIG.
// We keep environment-variable parsing as a compatibility layer for now.

TaskWorkerEnabled: false

// Default polling interval for notifications (server-side).
NotificationsIntervalSeconds: 30

// Default interval for cloud credential checks (AWS/Azure/GCP).
CloudCheckIntervalMinutes: 30

// Limits and time budget for the public "running labs" endpoint when scanning EVE-NG.
EveRunningScan: {
	Limit:                25
	Workers:              8
	BudgetSeconds:        4
	PerLabTimeoutSeconds: 3
}
