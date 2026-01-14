// Skyforge service configuration (Encore).
//
// These defaults can be overridden at deploy time using ENCORE_RUNTIME_CONFIG.
// We keep environment-variable parsing as a compatibility layer for now.

taskWorkerEnabled: false

// Default polling interval for notifications (server-side).
notificationsIntervalSeconds: 30

// Default interval for cloud credential checks (AWS/Azure/GCP).
cloudCheckIntervalMinutes: 30

// Limits and time budget for the public "running labs" endpoint when scanning EVE-NG.
eveRunningScan: {
	limit:                25
	workers:              8
	budgetSeconds:        4
	perLabTimeoutSeconds: 3
}

