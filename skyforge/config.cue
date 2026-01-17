// Skyforge service configuration (Encore).
//
// These defaults can be overridden at deploy time using ENCORE_CFG_SKYFORGE.

TaskWorkerEnabled: true

// Default polling interval for notifications (server-side).
NotificationsIntervalSeconds: 30

// Default interval for cloud credential checks (AWS/Azure/GCP).
CloudCheckIntervalMinutes: 30

// When querying EVE labs for a specific owner, optionally fall back to scanning the root folder.
// This is useful for EVE installs that don't follow the `Users/<owner>` folder convention.
EveUserRootFallback: false

// Limits and time budget for the public "running labs" endpoint when scanning EVE-NG.
EveRunningScan: {
	Limit:                25
	Workers:              8
	BudgetSeconds:        4
	PerLabTimeoutSeconds: 3
}

// Netlab defaults.
Netlab: {
	SSHHost:    ""
	SSHUser:    ""
	SSHKeyFile: ""
	StateRoot:  "/var/lib/skyforge/netlab"
}

// LabPP defaults. Secrets still come from env/secrets.
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
	NetboxInternalBaseURL: ""
	NautobotBaseURL:""
	NautobotInternalBaseURL: ""
	YaadeBaseURL:   ""
	YaadeInternalBaseURL: ""
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

// Netlab-on-C9s (netlab-c9s) defaults.
// These are non-secret toggles; the generator/ansible images should be set in Helm values (ENCORE_CFG_SKYFORGE).
NetlabGenerator: {
	// "remote" (default): use BYOS netlab API server for `netlab create` + `netlab clab-tarball`.
	// "k8s": run a netlab generator Job in-cluster (scaffolding; not fully implemented yet).
	C9sGeneratorMode: "k8s"

	GeneratorImage:    ""
	PullPolicy:        "IfNotPresent"
	AnsibleImage:      ""
	AnsiblePullPolicy: "IfNotPresent"
}
