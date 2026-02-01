// Worker service configuration (Encore).
//
// These defaults can be overridden at deploy time using ENCORE_CFG_WORKER.

// Enable worker-side cron and task processing by default.
TaskWorkerEnabled: true

// Netlab defaults.
Netlab: {
	SSHHost:    ""
	SSHUser:    ""
	SSHKeyFile: ""
	StateRoot:  "/var/lib/skyforge/netlab"
}

Workspaces: {
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
	SNMPCommunity: "public"
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
	GeneratorImage:   "ghcr.io/forwardnetworks/skyforge-netlab-generator:latest"
	PullPolicy:       "IfNotPresent"
}
