package skyforgeconfig

import (
	"log"
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

// LoadConfig loads Skyforge runtime configuration from env, Encore config, and secrets.
//
// The Encore-managed config values must be passed in from a service package,
// since config.Load cannot be called from a non-service library.
func LoadConfig(enc EncoreConfig, sec skyforgecore.Secrets) skyforgecore.Config {
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

	imagePullSecretName := strings.TrimSpace(enc.Kubernetes.ImagePullSecretName)
	imagePullSecretNamespace := strings.TrimSpace(enc.Kubernetes.ImagePullSecretNamespace)
	if imagePullSecretName == "" {
		imagePullSecretName = "ghcr-pull"
	}
	if imagePullSecretNamespace == "" {
		imagePullSecretNamespace = "skyforge"
	}

	netlabC9sGeneratorMode := strings.ToLower(strings.TrimSpace(enc.NetlabGenerator.C9sGeneratorMode))
	if netlabC9sGeneratorMode == "" {
		// Default to in-cluster generation for netlab-c9s so it works out of the box without
		// requiring a BYOS netlab server selection.
		netlabC9sGeneratorMode = "k8s"
	}
	netlabGeneratorImage := strings.TrimSpace(enc.NetlabGenerator.GeneratorImage)
	netlabGeneratorPullPolicy := strings.TrimSpace(enc.NetlabGenerator.PullPolicy)

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
		OIDCLoginURL:     "/api/skyforge/api/oidc/login",
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
	if strings.TrimSpace(workspacesCfg.GiteaUsername) == "" {
		workspacesCfg.GiteaUsername = "skyforge"
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
		WorkspaceSyncSeconds:    0,
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
		DNSURL:                    dnsURL,
		DNSAdminUsername:          dnsAdminUsername,
		DNSUserZoneSuffix:         dnsUserZoneSuffix,
		TaskWorkerEnabled:         taskWorkerEnabled,
		ImagePullSecretName:       imagePullSecretName,
		ImagePullSecretNamespace:  imagePullSecretNamespace,
		NetlabC9sGeneratorMode:    netlabC9sGeneratorMode,
		NetlabGeneratorImage:      netlabGeneratorImage,
		NetlabGeneratorPullPolicy: netlabGeneratorPullPolicy,
	}
}
