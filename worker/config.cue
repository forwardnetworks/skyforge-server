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
	MultusNetworks: *[] | [...string]
}

Kubernetes: {
	ImagePullSecretName: "ghcr-pull"
	ImagePullSecretNamespace: "skyforge"
}

// Netlab-on-C9s (netlab-c9s) defaults.
NetlabGenerator: {
	C9sGeneratorMode: "k8s"
	GeneratorImage:   ""
	PullPolicy:       "IfNotPresent"
}