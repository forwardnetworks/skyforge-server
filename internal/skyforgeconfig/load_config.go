package skyforgeconfig

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"encore.app/internal/skyforgecore"
)

func parseUserList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, "\n", ",")
	raw = strings.ReplaceAll(raw, ";", ",")
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key := strings.ToLower(p)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func loadEncoreConfigOverrideFromEnv() (EncoreConfig, bool) {
	raw := strings.TrimSpace(os.Getenv("ENCORE_CFG_SKYFORGE"))
	if raw == "" {
		return EncoreConfig{}, false
	}

	// `config.Load` should handle runtime config, but in some environments the injected
	// loader may not pick up `ENCORE_CFG_SKYFORGE`. Treat this env var as a source of
	// truth when present so Helm-provided typed config stays effective.
	var cfg EncoreConfig
	if strings.HasPrefix(raw, "{") {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			log.Printf("invalid ENCORE_CFG_SKYFORGE JSON: %v", err)
			return EncoreConfig{}, false
		}
		return cfg, true
	}

	// Helm stores the JSON as base64url without padding (Encore's legacy format).
	// Accept both padded and unpadded.
	enc := raw
	if m := len(enc) % 4; m != 0 {
		enc += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.URLEncoding.DecodeString(enc)
	if err != nil {
		log.Printf("invalid ENCORE_CFG_SKYFORGE base64url: %v", err)
		return EncoreConfig{}, false
	}
	if err := json.Unmarshal(decoded, &cfg); err != nil {
		log.Printf("invalid ENCORE_CFG_SKYFORGE decoded JSON: %v", err)
		return EncoreConfig{}, false
	}
	return cfg, true
}

// LoadConfig loads Skyforge runtime configuration from env, Encore config, and secrets.
//
// The Encore-managed config values must be passed in from a service package,
// since config.Load cannot be called from a non-service library.
func LoadConfig(enc EncoreConfig, sec skyforgecore.Secrets) skyforgecore.Config {
	if override, ok := loadEncoreConfigOverrideFromEnv(); ok {
		enc = override
	}

	sessionTTL := 8 * time.Hour
	if raw := strings.TrimSpace(enc.SessionTTL); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			sessionTTL = parsed
		} else {
			log.Printf("invalid SessionTTL (%s), defaulting to %s", raw, sessionTTL)
		}
	}

	maxGroups := 50
	if enc.MaxGroups > 0 && enc.MaxGroups <= 500 {
		maxGroups = enc.MaxGroups
	}

	adminUsers := parseUserList(enc.AdminUsers)
	adminUsername := strings.TrimSpace(enc.AdminUsername)
	adminPassword := strings.TrimSpace(sec.AdminPassword)
	e2eAdminEnabled := enc.E2EAdminEnabled
	e2eAdminToken := strings.TrimSpace(sec.E2EAdminToken)
	corpEmailDomain := strings.TrimSpace(enc.CorpEmailDomain)
	if adminUsername == "" {
		adminUsername = "skyforge"
	}

	giteaBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.GiteaBaseURL), "/")
	netboxBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.NetboxBaseURL), "/")
	nautobotBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.NautobotBaseURL), "/")
	yaadeBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.YaadeBaseURL), "/")
	netboxInternalBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.NetboxInternalBaseURL), "/")
	nautobotInternalBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.NautobotInternalBaseURL), "/")
	yaadeInternalBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.YaadeInternalBaseURL), "/")

	elasticURL := strings.TrimRight(strings.TrimSpace(enc.Elastic.URL), "/")
	elasticIndexPrefix := strings.TrimSpace(enc.Elastic.IndexPrefix)
	if elasticURL == "" && enc.Features.ElasticEnabled {
		elasticURL = "http://elasticsearch:9200"
	}
	if elasticIndexPrefix == "" {
		elasticIndexPrefix = "skyforge"
	}

	publicURL := strings.TrimRight(strings.TrimSpace(enc.PublicURL), "/")

	oidcIssuerURL := strings.TrimSpace(enc.OIDC.IssuerURL)
	oidcDiscoveryURL := strings.TrimSpace(enc.OIDC.DiscoveryURL)
	oidcClientID := strings.TrimSpace(sec.OIDCClientID)
	oidcClientSecret := strings.TrimSpace(sec.OIDCClientSecret)
	oidcRedirectURL := strings.TrimSpace(enc.OIDC.RedirectURL)

	// NOTE: Skyforge uses an Encore-managed Postgres database resource.
	// Legacy env-based DB connection settings have been removed.

	ldapURL := strings.TrimSpace(sec.LDAPURL)
	ldapBindTemplate := strings.TrimSpace(sec.LDAPBindTemplate)
	ldapCfg := skyforgecore.LDAPConfig{
		URL:             ldapURL,
		BindTemplate:    ldapBindTemplate,
		BaseDN:          strings.TrimSpace(enc.LDAP.BaseDN),
		DisplayNameAttr: strings.TrimSpace(enc.LDAP.DisplayNameAttr),
		MailAttr:        strings.TrimSpace(enc.LDAP.MailAttr),
		GroupAttr:       strings.TrimSpace(enc.LDAP.GroupAttr),
		UseStartTLS:     enc.LDAP.UseStartTLS,
		SkipTLSVerify:   enc.LDAP.SkipTLSVerify,
	}
	ldapLookupBindDN := strings.TrimSpace(sec.LDAPLookupBindDN)
	ldapLookupBindPassword := sec.LDAPLookupBindPassword

	netlabCfg := skyforgecore.NetlabConfig{
		SSHHost:    strings.TrimSpace(enc.Netlab.SSHHost),
		SSHUser:    strings.TrimSpace(enc.Netlab.SSHUser),
		SSHKeyFile: strings.TrimSpace(enc.Netlab.SSHKeyFile),
		StateRoot:  strings.TrimSpace(enc.Netlab.StateRoot),
	}

	dnsURL := strings.TrimRight(strings.TrimSpace(enc.DNS.URL), "/")
	dnsAdminUsername := strings.TrimSpace(enc.DNS.AdminUsername)
	dnsUserZoneSuffix := strings.TrimSpace(enc.DNS.UserZoneSuffix)
	if dnsAdminUsername == "" {
		dnsAdminUsername = "admin"
	}
	if dnsUserZoneSuffix == "" {
		dnsUserZoneSuffix = "skyforge"
	}
	dnsUserZoneSuffix = strings.TrimPrefix(dnsUserZoneSuffix, ".")

	taskWorkerEnabled := enc.TaskWorkerEnabled

	aiEnabled := enc.AI.Enabled

	geminiEnabled := enc.Gemini.Enabled
	geminiClientID := strings.TrimSpace(enc.Gemini.ClientID)
	geminiRedirectURL := strings.TrimSpace(enc.Gemini.RedirectURL)
	if geminiRedirectURL == "" && strings.TrimSpace(enc.PublicURL) != "" {
		geminiRedirectURL = strings.TrimRight(strings.TrimSpace(enc.PublicURL), "/") + "/api/user/integrations/gemini/callback"
	}
	geminiProjectID := strings.TrimSpace(enc.Gemini.ProjectID)
	geminiLocation := strings.TrimSpace(enc.Gemini.Location)
	if geminiLocation == "" {
		geminiLocation = "us-central1"
	}
	geminiModel := strings.TrimSpace(enc.Gemini.Model)
	geminiFallbackModel := strings.TrimSpace(enc.Gemini.FallbackModel)
	if geminiModel == "" {
		geminiModel = "gemini-3.0-pro"
	}
	if geminiFallbackModel == "" {
		geminiFallbackModel = "gemini-3.0-flash"
	}

	imagePullSecretName := strings.TrimSpace(enc.Kubernetes.ImagePullSecretName)
	imagePullSecretNamespace := strings.TrimSpace(enc.Kubernetes.ImagePullSecretNamespace)
	if imagePullSecretName == "" {
		imagePullSecretName = "ghcr-pull"
	}
	if imagePullSecretNamespace == "" {
		imagePullSecretNamespace = "skyforge"
	}

	forwardCollectorImage := strings.TrimSpace(enc.ForwardCollector.Image)
	forwardCollectorPullPolicy := strings.TrimSpace(enc.ForwardCollector.PullPolicy)
	if forwardCollectorPullPolicy == "" {
		forwardCollectorPullPolicy = "IfNotPresent"
	}
	forwardCollectorPullSecretName := strings.TrimSpace(enc.ForwardCollector.ImagePullSecretName)
	forwardCollectorPullSecretNamespace := strings.TrimSpace(enc.ForwardCollector.ImagePullSecretNamespace)
	if forwardCollectorPullSecretName == "" {
		forwardCollectorPullSecretName = imagePullSecretName
	}
	if forwardCollectorPullSecretNamespace == "" {
		forwardCollectorPullSecretNamespace = imagePullSecretNamespace
	}
	forwardCollectorHeapSizeGB := enc.ForwardCollector.HeapSizeGB

	netlabC9sGeneratorMode := strings.ToLower(strings.TrimSpace(enc.NetlabGenerator.C9sGeneratorMode))
	if netlabC9sGeneratorMode == "" {
		// Default to in-cluster generation for netlab-c9s so it works out of the box without
		// requiring a BYOS netlab server selection.
		netlabC9sGeneratorMode = "k8s"
	}
	netlabGeneratorImage := strings.TrimSpace(enc.NetlabGenerator.GeneratorImage)
	netlabGeneratorPullPolicy := strings.TrimSpace(enc.NetlabGenerator.PullPolicy)
	netlabApplierImage := strings.TrimSpace(enc.NetlabGenerator.ApplierImage)
	netlabApplierPullPolicy := strings.TrimSpace(enc.NetlabGenerator.ApplierPullPolicy)

	featuresCfg := skyforgecore.FeaturesConfig{
		GiteaEnabled:     enc.Features.GiteaEnabled,
		MinioEnabled:     enc.Features.MinioEnabled,
		DexEnabled:       enc.Features.DexEnabled,
		CoderEnabled:     enc.Features.CoderEnabled,
		YaadeEnabled:     enc.Features.YaadeEnabled,
		SwaggerUIEnabled: enc.Features.SwaggerUIEnabled,
		ForwardEnabled:   enc.Features.ForwardEnabled,
		NetboxEnabled:    enc.Features.NetboxEnabled,
		NautobotEnabled:  enc.Features.NautobotEnabled,
		DNSEnabled:       enc.Features.DNSEnabled,
		ElasticEnabled:   enc.Features.ElasticEnabled,
	}
	// "Forward Networks integrations" umbrella: keep Forward-specific integrations/tools
	// (e.g. Forward Collector, ServiceNow demo, Elastic indexing) behind a single switch.
	//
	// NOTE: AI is intentionally not gated by this flag.
	if !featuresCfg.ForwardEnabled {
		featuresCfg.ElasticEnabled = false
	}

	// For the common "in-cluster Elastic" case, allow the feature flag to
	// implicitly enable the default service name.
	if elasticURL == "" && featuresCfg.ElasticEnabled {
		elasticURL = "http://elasticsearch:9200"
	}
	elasticCfg := skyforgecore.ElasticConfig{
		URL:         elasticURL,
		IndexPrefix: elasticIndexPrefix,
	}

	uiCfg := skyforgecore.UIConfig{
		ProductName:      strings.TrimSpace(enc.UI.ProductName),
		ProductSubtitle:  strings.TrimSpace(enc.UI.ProductSubtitle),
		LogoURL:          strings.TrimSpace(enc.UI.LogoURL),
		LogoAlt:          strings.TrimSpace(enc.UI.LogoAlt),
		HeaderBackground: strings.TrimSpace(enc.UI.HeaderBackground),
		SupportText:      strings.TrimSpace(enc.UI.SupportText),
		SupportURL:       strings.TrimSpace(enc.UI.SupportURL),
		ThemeDefault:     strings.TrimSpace(enc.UI.ThemeDefault),
		OIDCEnabled:      strings.TrimSpace(oidcIssuerURL) != "" && strings.TrimSpace(oidcClientID) != "" && strings.TrimSpace(oidcClientSecret) != "" && strings.TrimSpace(oidcRedirectURL) != "",
		OIDCLoginURL:     "/api/oidc/login",
	}
	if uiCfg.ProductName == "" {
		uiCfg.ProductName = "Skyforge"
	}
	if uiCfg.ProductSubtitle == "" {
		uiCfg.ProductSubtitle = "Automation Hub"
	}
	if uiCfg.LogoAlt == "" {
		uiCfg.LogoAlt = uiCfg.ProductName
	}
	if uiCfg.SupportText == "" {
		uiCfg.SupportText = "Need access? Contact your platform admin."
	}

	notificationsEnabled := enc.NotificationsEnabled
	notificationsInterval := 30 * time.Second
	if enc.NotificationsIntervalSeconds > 0 && enc.NotificationsIntervalSeconds <= 3600 {
		notificationsInterval = time.Duration(enc.NotificationsIntervalSeconds) * time.Second
	}
	cloudCredentialChecks := 30 * time.Minute
	if enc.CloudCheckIntervalMinutes > 0 && enc.CloudCheckIntervalMinutes <= 24*60 {
		cloudCredentialChecks = time.Duration(enc.CloudCheckIntervalMinutes) * time.Minute
	}

	workspacesCfg := skyforgecore.WorkspacesConfig{
		DataDir:                strings.TrimSpace(enc.Workspaces.DataDir),
		GiteaAPIURL:            strings.TrimRight(strings.TrimSpace(enc.Workspaces.GiteaAPIURL), "/"),
		GiteaUsername:          strings.TrimSpace(enc.Workspaces.GiteaUsername),
		GiteaPassword:          strings.TrimSpace(sec.GiteaPassword),
		GiteaRepoPrivate:       enc.Workspaces.GiteaRepoPrivate,
		DeleteMode:             strings.TrimSpace(enc.Workspaces.DeleteMode),
		ObjectStorageEndpoint:  strings.TrimRight(strings.TrimSpace(enc.ObjectStorage.Endpoint), "/"),
		ObjectStorageUseSSL:    enc.ObjectStorage.UseSSL,
		ObjectStorageAccessKey: strings.TrimSpace(sec.ObjectStorageAccessKey),
		ObjectStorageSecretKey: strings.TrimSpace(sec.ObjectStorageSecretKey),
	}
	if strings.TrimSpace(workspacesCfg.DataDir) == "" {
		workspacesCfg.DataDir = "/var/lib/skyforge"
	}
	// Back-compat + robustness: allow the older SKYFORGE_* env vars (injected by Helm configmaps)
	// to fill gaps if ENCORE_CFG is missing or partially configured.
	if strings.TrimSpace(workspacesCfg.GiteaAPIURL) == "" {
		if v := strings.TrimRight(strings.TrimSpace(os.Getenv("SKYFORGE_GITEA_API_URL")), "/"); v != "" {
			workspacesCfg.GiteaAPIURL = v
		} else if giteaBaseURL != "" {
			workspacesCfg.GiteaAPIURL = giteaBaseURL + "/api/v1"
		}
	}
	if strings.TrimSpace(workspacesCfg.GiteaUsername) == "" {
		if v := strings.TrimSpace(os.Getenv("SKYFORGE_GITEA_USERNAME")); v != "" {
			workspacesCfg.GiteaUsername = v
		} else {
			workspacesCfg.GiteaUsername = "skyforge"
		}
	}
	if strings.TrimSpace(workspacesCfg.GiteaPassword) == "" {
		if v := strings.TrimSpace(os.Getenv("SKYFORGE_GITEA_PASSWORD")); v != "" {
			workspacesCfg.GiteaPassword = v
		}
	}
	if strings.TrimSpace(workspacesCfg.DeleteMode) == "" {
		workspacesCfg.DeleteMode = "live"
	}
	if strings.TrimSpace(workspacesCfg.ObjectStorageEndpoint) == "" {
		workspacesCfg.ObjectStorageEndpoint = "minio:9000"
	}

	terraformBinaryPath := strings.TrimSpace(enc.Terraform.BinaryPath)
	terraformVersion := strings.TrimSpace(enc.Terraform.Version)
	terraformURL := strings.TrimSpace(enc.Terraform.URL)

	return skyforgecore.Config{
		ListenAddr: func() string {
			if v := strings.TrimSpace(enc.ListenAddr); v != "" {
				return v
			}
			return ":8085"
		}(),
		SessionSecret: sec.SessionSecret,
		SessionTTL:    sessionTTL,
		PublicURL:     publicURL,
		SessionCookie: func() string {
			if v := strings.TrimSpace(enc.SessionCookie); v != "" {
				return v
			}
			return "skyforge_session"
		}(),
		CookieSecure: func() string {
			if v := strings.TrimSpace(enc.CookieSecure); v != "" {
				return v
			}
			return "auto"
		}(),
		CookieDomain:  strings.TrimSpace(enc.CookieDomain),
		InternalToken: strings.TrimSpace(sec.InternalToken),
		StaticRoot: func() string {
			if v := strings.TrimSpace(enc.StaticRoot); v != "" {
				return v
			}
			return "/opt/skyforge/static"
		}(),
		MaxGroups:               maxGroups,
		AdminUsers:              adminUsers,
		AdminUsername:           adminUsername,
		AdminPassword:           adminPassword,
		E2EAdminEnabled:         e2eAdminEnabled,
		E2EAdminToken:           e2eAdminToken,
		UI:                      uiCfg,
		NotificationsEnabled:    notificationsEnabled,
		NotificationsInterval:   notificationsInterval,
		CloudCredentialChecks:   cloudCredentialChecks,
		CorpEmailDomain:         corpEmailDomain,
		AwsSSOAccountID:         strings.TrimSpace(enc.AwsSSOAccountID),
		AwsSSORoleName:          strings.TrimSpace(enc.AwsSSORoleName),
		AwsSSOStartURL:          strings.TrimSpace(enc.AwsSSOStartURL),
		AwsSSORegion:            strings.TrimSpace(enc.AwsSSORegion),
		GiteaBaseURL:            giteaBaseURL,
		NetboxBaseURL:           netboxBaseURL,
		NetboxInternalBaseURL:   netboxInternalBaseURL,
		NautobotBaseURL:         nautobotBaseURL,
		NautobotInternalBaseURL: nautobotInternalBaseURL,
		YaadeBaseURL:            yaadeBaseURL,
		YaadeInternalBaseURL:    yaadeInternalBaseURL,
		ElasticURL:              elasticURL,
		ElasticIndexPrefix:      elasticIndexPrefix,
		OIDC: skyforgecore.OIDCConfig{
			IssuerURL:    oidcIssuerURL,
			DiscoveryURL: oidcDiscoveryURL,
			ClientID:     oidcClientID,
			ClientSecret: oidcClientSecret,
			RedirectURL:  oidcRedirectURL,
		},
		Netlab:                    netlabCfg,
		LDAP:                      ldapCfg,
		LDAPLookupBindDN:          ldapLookupBindDN,
		LDAPLookupBindPassword:    ldapLookupBindPassword,
		Workspaces:                workspacesCfg,
		TerraformBinaryPath:       terraformBinaryPath,
		TerraformVersion:          terraformVersion,
		TerraformURL:              terraformURL,
		YaadeAdminUsername:        strings.TrimSpace(enc.YaadeAdminUsername),
		YaadeAdminPassword:        strings.TrimSpace(sec.YaadeAdminPassword),
		ContainerlabAPIPath:       strings.TrimSpace(enc.Containerlab.APIPath),
		ContainerlabJWTSecret:     strings.TrimSpace(sec.ContainerlabJWTSecret),
		ContainerlabSkipTLSVerify: enc.Containerlab.SkipTLSVerify,
		Forward: skyforgecore.ForwardConfig{
			SNMPPlaceholderEnabled: enc.Forward.SNMPPlaceholderEnabled,
			SNMPCommunity:          strings.TrimSpace(enc.Forward.SNMPCommunity),
		},
		PKICACert: strings.TrimSpace(sec.PKICACert),
		PKICAKey:  strings.TrimSpace(sec.PKICAKey),
		SSHCAKey:  strings.TrimSpace(sec.SSHCAKey),
		PKIDefaultDays: func() int {
			if enc.PKIDefaultDays > 0 {
				return enc.PKIDefaultDays
			}
			return 365
		}(),
		SSHCADefaultDays: func() int {
			if enc.SSHCADefaultDays > 0 {
				return enc.SSHCADefaultDays
			}
			return 30
		}(),
		DNSURL:                                   dnsURL,
		DNSAdminUsername:                         dnsAdminUsername,
		DNSUserZoneSuffix:                        dnsUserZoneSuffix,
		AIEnabled:                                aiEnabled,
		GeminiEnabled:                            geminiEnabled,
		GeminiClientID:                           geminiClientID,
		GeminiClientSecret:                       strings.TrimSpace(sec.GeminiClientSecret),
		GeminiRedirectURL:                        geminiRedirectURL,
		GeminiProjectID:                          geminiProjectID,
		GeminiLocation:                           geminiLocation,
		GeminiModel:                              geminiModel,
		GeminiFallbackModel:                      geminiFallbackModel,
		TaskWorkerEnabled:                        taskWorkerEnabled,
		ImagePullSecretName:                      imagePullSecretName,
		ImagePullSecretNamespace:                 imagePullSecretNamespace,
		ForwardCollectorImage:                    forwardCollectorImage,
		ForwardCollectorPullPolicy:               forwardCollectorPullPolicy,
		ForwardCollectorImagePullSecretName:      forwardCollectorPullSecretName,
		ForwardCollectorImagePullSecretNamespace: forwardCollectorPullSecretNamespace,
		ForwardCollectorHeapSizeGB:               forwardCollectorHeapSizeGB,
		NetlabC9sGeneratorMode:                   netlabC9sGeneratorMode,
		NetlabGeneratorImage:                     netlabGeneratorImage,
		NetlabGeneratorPullPolicy:                netlabGeneratorPullPolicy,
		NetlabApplierImage:                       netlabApplierImage,
		NetlabApplierPullPolicy:                  netlabApplierPullPolicy,
		Features:                                 featuresCfg,
		Elastic:                                  elasticCfg,
	}
}

// LoadWorkerConfig loads a subset of configuration required for the worker service.
func LoadWorkerConfig(enc WorkerConfig, sec skyforgecore.Secrets) skyforgecore.Config {
	netlabCfg := skyforgecore.NetlabConfig{
		SSHHost:    strings.TrimSpace(enc.Netlab.SSHHost),
		SSHUser:    strings.TrimSpace(enc.Netlab.SSHUser),
		SSHKeyFile: strings.TrimSpace(enc.Netlab.SSHKeyFile),
		StateRoot:  strings.TrimSpace(enc.Netlab.StateRoot),
	}

	workspacesCfg := skyforgecore.WorkspacesConfig{
		DataDir:                strings.TrimSpace(enc.Workspaces.DataDir),
		GiteaAPIURL:            strings.TrimRight(strings.TrimSpace(enc.Workspaces.GiteaAPIURL), "/"),
		GiteaUsername:          strings.TrimSpace(enc.Workspaces.GiteaUsername),
		GiteaPassword:          strings.TrimSpace(sec.GiteaPassword),
		GiteaRepoPrivate:       enc.Workspaces.GiteaRepoPrivate,
		DeleteMode:             strings.TrimSpace(enc.Workspaces.DeleteMode),
		ObjectStorageEndpoint:  strings.TrimRight(strings.TrimSpace(enc.ObjectStorage.Endpoint), "/"),
		ObjectStorageUseSSL:    enc.ObjectStorage.UseSSL,
		ObjectStorageAccessKey: strings.TrimSpace(sec.ObjectStorageAccessKey),
		ObjectStorageSecretKey: strings.TrimSpace(sec.ObjectStorageSecretKey),
	}
	if strings.TrimSpace(workspacesCfg.DataDir) == "" {
		workspacesCfg.DataDir = "/var/lib/skyforge"
	}
	// Back-compat + robustness: allow the SKYFORGE_* env vars (injected by Helm configmaps)
	// to fill gaps if ENCORE_CFG is missing or partially configured.
	if strings.TrimSpace(workspacesCfg.GiteaAPIURL) == "" {
		if v := strings.TrimRight(strings.TrimSpace(os.Getenv("SKYFORGE_GITEA_API_URL")), "/"); v != "" {
			workspacesCfg.GiteaAPIURL = v
		} else if base := strings.TrimRight(strings.TrimSpace(os.Getenv("SKYFORGE_GITEA_URL")), "/"); base != "" {
			workspacesCfg.GiteaAPIURL = base + "/api/v1"
		}
	}
	if strings.TrimSpace(workspacesCfg.GiteaUsername) == "" {
		if v := strings.TrimSpace(os.Getenv("SKYFORGE_GITEA_USERNAME")); v != "" {
			workspacesCfg.GiteaUsername = v
		} else {
			workspacesCfg.GiteaUsername = "skyforge"
		}
	}
	if strings.TrimSpace(workspacesCfg.GiteaPassword) == "" {
		if v := strings.TrimSpace(os.Getenv("SKYFORGE_GITEA_PASSWORD")); v != "" {
			workspacesCfg.GiteaPassword = v
		}
	}
	if strings.TrimSpace(workspacesCfg.DeleteMode) == "" {
		workspacesCfg.DeleteMode = "live"
	}
	if strings.TrimSpace(workspacesCfg.ObjectStorageEndpoint) == "" {
		workspacesCfg.ObjectStorageEndpoint = "minio:9000"
	}

	terraformBinaryPath := strings.TrimSpace(enc.Terraform.BinaryPath)
	terraformVersion := strings.TrimSpace(enc.Terraform.Version)
	terraformURL := strings.TrimSpace(enc.Terraform.URL)

	imagePullSecretName := strings.TrimSpace(enc.Kubernetes.ImagePullSecretName)
	imagePullSecretNamespace := strings.TrimSpace(enc.Kubernetes.ImagePullSecretNamespace)
	if imagePullSecretName == "" {
		imagePullSecretName = "ghcr-pull"
	}
	if imagePullSecretNamespace == "" {
		imagePullSecretNamespace = "skyforge"
	}

	forwardCollectorImage := strings.TrimSpace(enc.ForwardCollector.Image)
	forwardCollectorPullPolicy := strings.TrimSpace(enc.ForwardCollector.PullPolicy)
	if forwardCollectorPullPolicy == "" {
		forwardCollectorPullPolicy = "IfNotPresent"
	}
	forwardCollectorPullSecretName := strings.TrimSpace(enc.ForwardCollector.ImagePullSecretName)
	forwardCollectorPullSecretNamespace := strings.TrimSpace(enc.ForwardCollector.ImagePullSecretNamespace)
	if forwardCollectorPullSecretName == "" {
		forwardCollectorPullSecretName = imagePullSecretName
	}
	if forwardCollectorPullSecretNamespace == "" {
		forwardCollectorPullSecretNamespace = imagePullSecretNamespace
	}
	forwardCollectorHeapSizeGB := enc.ForwardCollector.HeapSizeGB

	netlabC9sGeneratorMode := strings.ToLower(strings.TrimSpace(enc.NetlabGenerator.C9sGeneratorMode))
	if netlabC9sGeneratorMode == "" {
		netlabC9sGeneratorMode = "k8s"
	}
	netlabGeneratorImage := strings.TrimSpace(enc.NetlabGenerator.GeneratorImage)
	netlabGeneratorPullPolicy := strings.TrimSpace(enc.NetlabGenerator.PullPolicy)
	netlabApplierImage := strings.TrimSpace(enc.NetlabGenerator.ApplierImage)
	netlabApplierPullPolicy := strings.TrimSpace(enc.NetlabGenerator.ApplierPullPolicy)

	featuresCfg := skyforgecore.FeaturesConfig{
		GiteaEnabled:     enc.Features.GiteaEnabled,
		MinioEnabled:     enc.Features.MinioEnabled,
		DexEnabled:       enc.Features.DexEnabled,
		CoderEnabled:     enc.Features.CoderEnabled,
		YaadeEnabled:     enc.Features.YaadeEnabled,
		SwaggerUIEnabled: enc.Features.SwaggerUIEnabled,
		ForwardEnabled:   enc.Features.ForwardEnabled,
		NetboxEnabled:    enc.Features.NetboxEnabled,
		NautobotEnabled:  enc.Features.NautobotEnabled,
		DNSEnabled:       enc.Features.DNSEnabled,
		ElasticEnabled:   enc.Features.ElasticEnabled,
	}
	// "Forward Networks integrations" umbrella: keep Forward-specific integrations/tools
	// (e.g. Forward Collector, ServiceNow demo, Elastic indexing) behind a single switch.
	//
	// NOTE: AI is intentionally not gated by this flag.
	if !featuresCfg.ForwardEnabled {
		featuresCfg.ElasticEnabled = false
	}

	elasticURL := strings.TrimRight(strings.TrimSpace(enc.Elastic.URL), "/")
	elasticIndexPrefix := strings.TrimSpace(enc.Elastic.IndexPrefix)
	if elasticIndexPrefix == "" {
		elasticIndexPrefix = "skyforge"
	}
	if elasticURL == "" && featuresCfg.ElasticEnabled {
		elasticURL = "http://elasticsearch:9200"
	}
	elasticCfg := skyforgecore.ElasticConfig{
		URL:         elasticURL,
		IndexPrefix: elasticIndexPrefix,
	}

	// Note: Worker does not need OIDC, LDAP, DNS, UI, or admin users.
	// However it *does* need SessionSecret to decrypt any encrypted credentials
	// stored in Postgres (Forward creds, cloud creds, etc.).
	return skyforgecore.Config{
		TaskWorkerEnabled:                        enc.TaskWorkerEnabled,
		SessionSecret:                            sec.SessionSecret,
		Netlab:                                   netlabCfg,
		Workspaces:                               workspacesCfg,
		TerraformBinaryPath:                      terraformBinaryPath,
		TerraformVersion:                         terraformVersion,
		TerraformURL:                             terraformURL,
		ImagePullSecretName:                      imagePullSecretName,
		ImagePullSecretNamespace:                 imagePullSecretNamespace,
		ForwardCollectorImage:                    forwardCollectorImage,
		ForwardCollectorPullPolicy:               forwardCollectorPullPolicy,
		ForwardCollectorImagePullSecretName:      forwardCollectorPullSecretName,
		ForwardCollectorImagePullSecretNamespace: forwardCollectorPullSecretNamespace,
		ForwardCollectorHeapSizeGB:               forwardCollectorHeapSizeGB,
		NetlabC9sGeneratorMode:                   netlabC9sGeneratorMode,
		NetlabGeneratorImage:                     netlabGeneratorImage,
		NetlabGeneratorPullPolicy:                netlabGeneratorPullPolicy,
		NetlabApplierImage:                       netlabApplierImage,
		NetlabApplierPullPolicy:                  netlabApplierPullPolicy,
		ElasticURL:                               elasticURL,
		ElasticIndexPrefix:                       elasticIndexPrefix,
		Forward: skyforgecore.ForwardConfig{
			SNMPPlaceholderEnabled: enc.Forward.SNMPPlaceholderEnabled,
			SNMPCommunity:          strings.TrimSpace(enc.Forward.SNMPCommunity),
		},
		PKICACert: strings.TrimSpace(sec.PKICACert),
		PKICAKey:  strings.TrimSpace(sec.PKICAKey),
		SSHCAKey:  strings.TrimSpace(sec.SSHCAKey),
		Features:  featuresCfg,
		Elastic:   elasticCfg,
	}
}
