// Skyforge service configuration (Encore).
//
// These defaults can be overridden at deploy time using ENCORE_CFG_SKYFORGE.

TaskWorkerEnabled: true
DisableEncoreCache: false
NotificationsEnabled: true
StaticRoot: "/opt/skyforge/static"
AdminUsers: ""
AdminUsername: "skyforge"
E2EAdminEnabled: true
CorpEmailDomain: ""
ListenAddr: ":8085"
SessionCookie: "skyforge_session"
SessionTTL: "8h"
CookieSecure: "auto"
CookieDomain: ""
MaxGroups: 50
PKIDefaultDays: 365
SSHCADefaultDays: 30

// Default polling interval for notifications (server-side).
NotificationsIntervalSeconds: 30

// Default interval for cloud credential checks (AWS/Azure/GCP).
CloudCheckIntervalMinutes: 30

AwsSSOStartURL: ""
AwsSSORegion: "us-east-1"
AwsSSOAccountID: ""
AwsSSORoleName: ""
YaadeAdminUsername: "admin"

// Netlab defaults.
Netlab: {
	SSHHost:    ""
	SSHUser:    ""
	SSHKeyFile: ""
	StateRoot:  "/var/lib/skyforge/netlab"
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

UI: {
	ProductName: "Skyforge"
	ProductSubtitle: "Automation Hub"
	LogoURL: ""
	LogoAlt: "Skyforge"
	HeaderBackground: ""
	SupportText: "Need access? Contact your platform admin."
	SupportURL: ""
	ThemeDefault: ""
}

PublicURL: ""

	DNS: {
		URL: "http://technitium-dns:5380"
		AdminUsername: "admin"
		UserZoneSuffix: "skyforge"
	}

	MCP: {
		// Enables Skyforge-hosted MCP endpoints (HTTP JSON-RPC).
		Enabled: true
		ForwardAllowWrites: false
	}

	OIDC: {
		IssuerURL: ""
		DiscoveryURL: ""
	RedirectURL: ""
}

LDAP: {
	BaseDN: ""
	DisplayNameAttr: ""
	MailAttr: ""
	GroupAttr: ""
	UseStartTLS: false
	SkipTLSVerify: false
}

Containerlab: {
	APIPath: "/containerlab"
	SkipTLSVerify: false
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
	// When enabled, Skyforge creates a placeholder SNMP credential in Forward for each
	// deployment network so that enabling SNMP collection later doesn't require manual setup.
	SNMPPlaceholderEnabled: true
}

ForwardCollector: {
	// Image is the container image used for the in-cluster Forward collector.
	//
	// Keep this empty by default so clusters that haven't published the collector
	// image don't end up with broken ImagePullBackOff pods.
	Image: ""
	PullPolicy: "IfNotPresent"
	ImagePullSecretName: ""
	ImagePullSecretNamespace: ""
	// HeapSizeGB sets COLLECTOR_HEAP_SIZE (in gigabytes) for the collector.
	// When 0, the collector image default is used.
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
	// When empty, Skyforge uses a provider default when ElasticEnabled=true.
	// For in-cluster (Helm): http://elasticsearch:9200
	URL: ""
	IndexPrefix: "skyforge"
	// IndexingMode controls how indices are named:
	// - "instance": shared indices (default)
	// - "per_user": separate indices per user
	IndexingMode: "instance"
	// ToolsAutosleepEnabled enables autosleep for Elastic tooling (kibana, etc).
	ToolsAutosleepEnabled: false
	// ToolsAutosleepIdleMinutes is the idle timeout before autosleep scales to 0.
	ToolsAutosleepIdleMinutes: 30
}

Kubernetes: {
	// ImagePullSecretName is the name of a docker registry secret that allows
	// pulling images (e.g. from GHCR). When set, Skyforge can mirror it into
	// per-workspace namespaces used by clabernetes/netlab-c9s.
	ImagePullSecretName: "ghcr-pull"
	// ImagePullSecretNamespace is the namespace where ImagePullSecretName exists.
	ImagePullSecretNamespace: "skyforge"
}

// Netlab-on-C9s (netlab-c9s) defaults.
// These are non-secret toggles; the generator/ansible images should be set in Helm values (ENCORE_CFG_SKYFORGE).
NetlabGenerator: {
	// "remote" (default): use BYOS netlab API server for `netlab create` + `netlab clab-tarball`.
	// "k8s": run a netlab generator Job in-cluster (scaffolding; not fully implemented yet).
	C9sGeneratorMode: "k8s"

	// Default to the public generator image so netlab validation works out-of-the-box
	// in local/dev setups even if ENCORE_CFG_SKYFORGE isn't wired up yet.
	GeneratorImage:    "ghcr.io/forwardnetworks/skyforge-netlab-generator:20260127-b8947318"
	PullPolicy:        "IfNotPresent"
	ApplierImage:      "ghcr.io/forwardnetworks/skyforge-netlab-applier:latest"
	ApplierPullPolicy: "IfNotPresent"
	// Prefer static defaults in /etc/netlab/defaults.yml over platform-injected --set.
	C9sDefaultSetOverrides: []
}
