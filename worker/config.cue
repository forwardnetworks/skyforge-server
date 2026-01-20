// Worker service configuration (Encore).
//
// These defaults can be overridden at deploy time using ENCORE_CFG_WORKER.

// Enable worker-side cron and task processing by default.
TaskWorkerEnabled: true
DisableEncoreCache: false
NotificationsEnabled: true
StaticRoot: "/opt/skyforge/static"
AdminUsers: ""
AdminUsername: "skyforge"
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

// General service defaults (non-secret).
Integrations: {
	GiteaBaseURL:           ""
	NetboxBaseURL:          ""
	NetboxInternalBaseURL:  ""
	NautobotBaseURL:        ""
	NautobotInternalBaseURL:""
	YaadeBaseURL:           ""
	YaadeInternalBaseURL:   ""
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
