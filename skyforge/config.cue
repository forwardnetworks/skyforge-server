// Skyforge service configuration (Encore).
//
// These defaults can be overridden at deploy time using ENCORE_CFG_SKYFORGE.
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

// Netlab defaults (legacy env vars can override).
Netlab: {
	SSHHost:    ""
	SSHUser:    ""
	SSHKeyFile: ""
	StateRoot:  "/var/lib/skyforge/netlab"
}

// LabPP defaults (legacy env vars can override). Secrets still come from env/secrets.
Labpp: {
	RunnerImage:        ""
	RunnerPullPolicy:   "IfNotPresent"
	RunnerPVCName:      "skyforge-server-data"
	ConfigDirBase:      "/var/lib/skyforge/labpp/configs"
	ConfigVersion:      "1.0"
	NetboxURL:          ""
	NetboxMgmtSubnet:   ""
	S3Region:           ""
	S3BucketName:       ""
	S3Endpoint:         ""
	S3DisableSSL:       true
	S3DisableChecksum:  false
}

// General service defaults (non-secret). These can be overridden at deploy time
// with env vars or ENCORE_CFG_SKYFORGE.
Integrations: {
	GiteaBaseURL:   ""
	NetboxBaseURL:  ""
	NautobotBaseURL:""
	YaadeBaseURL:   ""
}

Labs: {
	EveSSHUser:       ""
	EveSSHTunnel:     true
	EveLabsPath:      "/opt/unetlab/labs"
	EveTmpPath:       "/opt/unetlab/tmp"
}

DNS: {
	URL: "http://technitium-dns:5380"
}

Containerlab: {
	APIPath: "/containerlab"
}
