// Worker service configuration (Encore).
//
// These defaults can be overridden at deploy time using ENCORE_CFG_WORKER.

// Enable worker-side cron and task processing by default.
TaskWorkerEnabled: true
// Enable DB-backed fallback polling of queued tasks (in case Pub/Sub is delayed/unavailable).
TaskWorkerPollEnabled: true
// Only start tasks directly via the poller when they've been queued for at least this long.
TaskWorkerPollMinQueuedSeconds: 60
// Per tick, attempt to start up to this many queued tasks.
TaskWorkerPollMaxTasksPerTick: 10
// Cap poller-started tasks concurrently (separate from Pub/Sub subscription concurrency).
TaskWorkerPollMaxConcurrency: 4

// Netlab defaults.
Netlab: {
	SSHHost:    ""
	SSHUser:    ""
	SSHKeyFile: ""
	StateRoot:  "/var/lib/skyforge/netlab"
}

Scopes: {
	DataDir: "/var/lib/skyforge"
	GiteaAPIURL: ""
	GiteaUsername: "skyforge"
	GiteaRepoPrivate: true
	DeleteMode: "live"
}

ObjectStorage: {
	Endpoint: "minio:9000"
	UseSSL: false
}

Terraform: {
	BinaryPath: ""
	Version: ""
	URL: ""
}

Forward: {
	SNMPPlaceholderEnabled: true
}

ForwardCollector: {
	Image: ""
	PullPolicy: "IfNotPresent"
	ImagePullSecretName: ""
	ImagePullSecretNamespace: ""
	HeapSizeGB: 0
}

Features: {
	GiteaEnabled: true
	MinioEnabled: true
	DexEnabled: true
	CoderEnabled: true
	YaadeEnabled: true
	SwaggerUIEnabled: true
	ForwardEnabled: true
	NetboxEnabled: false
	NautobotEnabled: false
	DNSEnabled: false
	ElasticEnabled: false
}

Elastic: {
	URL: ""
	IndexPrefix: "skyforge"
	IndexingMode: "instance"
	ToolsAutosleepEnabled: false
	ToolsAutosleepIdleMinutes: 30
}

Kubernetes: {
	ImagePullSecretName: "ghcr-pull"
	ImagePullSecretNamespace: "skyforge"
}

// Netlab-on-C9s (netlab-c9s) defaults.
NetlabGenerator: {
	C9sGeneratorMode: "k8s"
	// Default to the public generator image so netlab validation works out-of-the-box
	// in local/dev setups even if ENCORE_CFG_WORKER isn't wired up yet.
	GeneratorImage:   "ghcr.io/forwardnetworks/skyforge-netlab-generator:20260127-b8947318"
	PullPolicy:       "IfNotPresent"
	ApplierImage:     "ghcr.io/forwardnetworks/skyforge-netlab-applier:latest"
	ApplierPullPolicy: "IfNotPresent"
	// Prefer static defaults in /etc/netlab/defaults.yml over platform-injected --set.
	C9sDefaultSetOverrides: []
}
