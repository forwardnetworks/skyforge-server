package skyforgeconfig

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"encore.app/internal/skyforgecore"
)

func getenv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func inferEmailDomain(explicit string) string {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		return explicit
	}
	raw := strings.TrimSpace(os.Getenv("SKYFORGE_HOSTNAME"))
	if raw == "" {
		return ""
	}
	raw = strings.Split(raw, ",")[0]
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "*.")
	if idx := strings.Index(raw, "."); idx != -1 && idx+1 < len(raw) {
		return raw[idx+1:]
	}
	return ""
}

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

func parseEveServers(raw string) ([]skyforgecore.EveServerConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var decoded any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}

	switch v := decoded.(type) {
	case []any:
		payload, _ := json.Marshal(v)
		var servers []skyforgecore.EveServerConfig
		if err := json.Unmarshal(payload, &servers); err != nil {
			return nil, err
		}
		return servers, nil
	case map[string]any:
		if serversRaw, ok := v["servers"]; ok {
			payload, _ := json.Marshal(serversRaw)
			var servers []skyforgecore.EveServerConfig
			if err := json.Unmarshal(payload, &servers); err != nil {
				return nil, err
			}
			return servers, nil
		}
		return nil, fmt.Errorf("invalid eve servers json (expected array or {\"servers\": [...]})")
	default:
		return nil, fmt.Errorf("invalid eve servers json (expected array or object)")
	}
}

func parseNetlabServers(raw string) ([]skyforgecore.NetlabServerConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var decoded any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}

	switch v := decoded.(type) {
	case []any:
		payload, _ := json.Marshal(v)
		var rawServers []map[string]any
		if err := json.Unmarshal(payload, &rawServers); err != nil {
			return nil, err
		}
		servers := make([]skyforgecore.NetlabServerConfig, 0, len(rawServers))
		for _, entry := range rawServers {
			b, _ := json.Marshal(entry)
			var s skyforgecore.NetlabServerConfig
			if err := json.Unmarshal(b, &s); err != nil {
				return nil, err
			}
			if _, ok := entry["apiInsecure"]; !ok {
				s.APIInsecure = true
			}
			servers = append(servers, s)
		}
		return servers, nil
	case map[string]any:
		if serversRaw, ok := v["servers"]; ok {
			payload, _ := json.Marshal(serversRaw)
			var rawServers []map[string]any
			if err := json.Unmarshal(payload, &rawServers); err != nil {
				return nil, err
			}
			servers := make([]skyforgecore.NetlabServerConfig, 0, len(rawServers))
			for _, entry := range rawServers {
				b, _ := json.Marshal(entry)
				var s skyforgecore.NetlabServerConfig
				if err := json.Unmarshal(b, &s); err != nil {
					return nil, err
				}
				if _, ok := entry["apiInsecure"]; !ok {
					s.APIInsecure = true
				}
				servers = append(servers, s)
			}
			return servers, nil
		}
		return nil, fmt.Errorf("invalid netlab servers json (expected array or {\"servers\": [...]})")
	default:
		return nil, fmt.Errorf("invalid netlab servers json (expected array or object)")
	}
}

func normalizeEveServer(s skyforgecore.EveServerConfig, fallback skyforgecore.LabsConfig) skyforgecore.EveServerConfig {
	s.Name = strings.TrimSpace(s.Name)
	s.APIURL = strings.TrimRight(strings.TrimSpace(s.APIURL), "/")
	s.WebURL = strings.TrimRight(strings.TrimSpace(s.WebURL), "/")
	s.Username = strings.TrimSpace(s.Username)
	s.Password = strings.TrimSpace(s.Password)
	s.SSHHost = strings.TrimSpace(s.SSHHost)
	s.SSHUser = strings.TrimSpace(s.SSHUser)
	s.LabsPath = strings.TrimSpace(s.LabsPath)
	s.TmpPath = strings.TrimSpace(s.TmpPath)

	if s.Username == "" {
		s.Username = strings.TrimSpace(fallback.EveUsername)
	}
	if s.Password == "" {
		s.Password = strings.TrimSpace(fallback.EvePassword)
	}
	if !s.SkipTLSVerify && fallback.EveSkipTLSVerify {
		s.SkipTLSVerify = true
	}
	if s.APIURL == "" && strings.TrimSpace(fallback.EveAPIURL) != "" {
		s.APIURL = strings.TrimRight(strings.TrimSpace(fallback.EveAPIURL), "/")
	}
	if s.WebURL == "" && strings.TrimSpace(fallback.PublicURL) != "" {
		s.WebURL = strings.TrimRight(strings.TrimSpace(fallback.PublicURL), "/")
	}

	if s.WebURL == "" && s.APIURL != "" {
		web := s.APIURL
		if before, ok := strings.CutSuffix(web, "/api"); ok {
			web = before
		}
		s.WebURL = strings.TrimRight(web, "/")
	}
	if s.SSHHost == "" && s.APIURL != "" {
		if u, err := url.Parse(s.APIURL); err == nil && u != nil {
			s.SSHHost = strings.TrimSpace(u.Hostname())
		}
	}
	if s.SSHHost == "" && s.WebURL != "" {
		if u, err := url.Parse(s.WebURL); err == nil && u != nil {
			s.SSHHost = strings.TrimSpace(u.Hostname())
		}
	}
	if s.SSHUser == "" {
		s.SSHUser = strings.TrimSpace(fallback.EveSSHUser)
	}
	if s.LabsPath == "" {
		s.LabsPath = strings.TrimSpace(fallback.EveLabsPath)
	}
	if s.TmpPath == "" {
		s.TmpPath = strings.TrimSpace(fallback.EveTmpPath)
	}
	return s
}

func normalizeNetlabServer(s skyforgecore.NetlabServerConfig, fallback skyforgecore.NetlabConfig) skyforgecore.NetlabServerConfig {
	s.Name = strings.TrimSpace(s.Name)
	s.SSHHost = strings.TrimSpace(s.SSHHost)
	s.SSHUser = strings.TrimSpace(s.SSHUser)
	s.SSHKeyFile = strings.TrimSpace(s.SSHKeyFile)
	s.StateRoot = strings.TrimSpace(s.StateRoot)
	s.APIURL = strings.TrimRight(strings.TrimSpace(s.APIURL), "/")
	s.ContainerlabAPIURL = strings.TrimRight(strings.TrimSpace(s.ContainerlabAPIURL), "/")

	if s.SSHUser == "" {
		s.SSHUser = strings.TrimSpace(fallback.SSHUser)
	}
	if s.SSHKeyFile == "" {
		s.SSHKeyFile = strings.TrimSpace(fallback.SSHKeyFile)
	}
	if s.StateRoot == "" {
		s.StateRoot = strings.TrimSpace(fallback.StateRoot)
	}
	if s.APIURL == "" && s.SSHHost != "" {
		s.APIURL = strings.TrimRight(fmt.Sprintf("https://%s/netlab", s.SSHHost), "/")
	}
	if s.Name == "" {
		if s.SSHHost != "" {
			s.Name = s.SSHHost
		} else {
			s.Name = "netlab-default"
		}
	}
	return s
}

// LoadConfig loads Skyforge runtime configuration from env, Encore config, and secrets.
//
// The Encore-managed config values must be passed in from a service package,
// since config.Load cannot be called from a non-service library.
func LoadConfig(enc EncoreConfig, sec skyforgecore.Secrets) skyforgecore.Config {
	sessionTTL := 8 * time.Hour
	if raw := getenv("SKYFORGE_SESSION_TTL", "8h"); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			sessionTTL = parsed
		} else {
			log.Printf("invalid SKYFORGE_SESSION_TTL (%s), defaulting to %s", raw, sessionTTL)
		}
	}

	maxGroups := 50
	if raw := getenv("SKYFORGE_MAX_GROUPS", "50"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 500 {
			maxGroups = v
		}
	}

	adminUsers := parseUserList(getenv("SKYFORGE_ADMIN_USERS", ""))
	adminUsername := strings.TrimSpace(getenv("SKYFORGE_ADMIN_USERNAME", "skyforge"))
	adminPassword := strings.TrimSpace(sec.AdminPassword)
	corpEmailDomain := inferEmailDomain(getenv("SKYFORGE_CORP_EMAIL_DOMAIN", ""))

	giteaBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.GiteaBaseURL), "/")
	netboxBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.NetboxBaseURL), "/")
	nautobotBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.NautobotBaseURL), "/")
	yaadeBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.YaadeBaseURL), "/")
	netboxInternalBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.NetboxInternalBaseURL), "/")
	nautobotInternalBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.NautobotInternalBaseURL), "/")
	yaadeInternalBaseURL := strings.TrimRight(strings.TrimSpace(enc.Integrations.YaadeInternalBaseURL), "/")

	oidcIssuerURL := strings.TrimSpace(getenv("SKYFORGE_OIDC_ISSUER_URL", ""))
	oidcDiscoveryURL := strings.TrimSpace(getenv("SKYFORGE_OIDC_DISCOVERY_URL", ""))
	oidcClientID := strings.TrimSpace(sec.OIDCClientID)
	oidcClientSecret := strings.TrimSpace(sec.OIDCClientSecret)
	oidcRedirectURL := strings.TrimSpace(getenv("SKYFORGE_OIDC_REDIRECT_URL", ""))

	// NOTE: Skyforge uses an Encore-managed Postgres database resource.
	// Legacy env-based DB connection settings have been removed.

	ldapURL := strings.TrimSpace(sec.LDAPURL)
	ldapBindTemplate := strings.TrimSpace(sec.LDAPBindTemplate)
	ldapCfg := skyforgecore.LDAPConfig{
		URL:             ldapURL,
		BindTemplate:    ldapBindTemplate,
		BaseDN:          getenv("SKYFORGE_LDAP_BASEDN", ""),
		DisplayNameAttr: getenv("SKYFORGE_LDAP_DISPLAY_ATTR", ""),
		MailAttr:        getenv("SKYFORGE_LDAP_MAIL_ATTR", ""),
		GroupAttr:       getenv("SKYFORGE_LDAP_GROUP_ATTR", ""),
		UseStartTLS:     getenv("SKYFORGE_LDAP_STARTTLS", "false") == "true",
		SkipTLSVerify:   getenv("SKYFORGE_LDAP_SKIP_TLS_VERIFY", "false") == "true",
	}
	ldapLookupBindDN := strings.TrimSpace(sec.LDAPLookupBindDN)
	ldapLookupBindPassword := sec.LDAPLookupBindPassword

	netlabCfg := skyforgecore.NetlabConfig{
		SSHHost:    strings.TrimSpace(enc.Netlab.SSHHost),
		SSHUser:    strings.TrimSpace(enc.Netlab.SSHUser),
		SSHKeyFile: strings.TrimSpace(enc.Netlab.SSHKeyFile),
		StateRoot:  strings.TrimSpace(enc.Netlab.StateRoot),
	}
	labsCfg := skyforgecore.LabsConfig{
		PublicURL:        strings.TrimRight(strings.TrimSpace(getenv("SKYFORGE_LABS_PUBLIC_URL", "")), "/"),
		EveAPIURL:        strings.TrimRight(strings.TrimSpace(getenv("SKYFORGE_EVE_API_URL", "")), "/"),
		EveUsername:      strings.TrimSpace(getenv("SKYFORGE_EVE_USERNAME", "")),
		EvePassword:      strings.TrimSpace(getenv("SKYFORGE_EVE_PASSWORD", "")),
		EveSkipTLSVerify: getenv("SKYFORGE_EVE_SKIP_TLS_VERIFY", "false") == "true",
		EveSSHKeyFile:    strings.TrimSpace(getenv("SKYFORGE_EVE_SSH_KEY_FILE", "")),
		EveSSHUser:       strings.TrimSpace(enc.Labs.EveSSHUser),
		EveSSHTunnel:     enc.Labs.EveSSHTunnel,
		EveLabsPath:      strings.TrimSpace(enc.Labs.EveLabsPath),
		EveTmpPath:       strings.TrimSpace(enc.Labs.EveTmpPath),
	}

	dnsURL := strings.TrimRight(strings.TrimSpace(enc.DNS.URL), "/")
	dnsAdminUsername := strings.TrimSpace(getenv("SKYFORGE_DNS_ADMIN_USERNAME", "admin"))
	dnsUserZoneSuffix := strings.TrimSpace(getenv("SKYFORGE_DNS_USER_ZONE_SUFFIX", "skyforge"))
	dnsUserZoneSuffix = strings.TrimPrefix(dnsUserZoneSuffix, ".")

	taskWorkerEnabled := enc.TaskWorkerEnabled
	netlabC9sGeneratorMode := strings.ToLower(strings.TrimSpace(enc.NetlabGenerator.C9sGeneratorMode))
	if override := strings.ToLower(strings.TrimSpace(getenv("SKYFORGE_NETLAB_C9S_GENERATOR_MODE", ""))); override != "" {
		netlabC9sGeneratorMode = override
	}
	if netlabC9sGeneratorMode == "" {
		// Default to in-cluster generation for netlab-c9s so it works out of the box without
		// requiring a BYOS netlab server selection.
		netlabC9sGeneratorMode = "k8s"
	}
	netlabGeneratorImage := strings.TrimSpace(enc.NetlabGenerator.GeneratorImage)
	if override := strings.TrimSpace(getenv("SKYFORGE_NETLAB_GENERATOR_IMAGE", "")); override != "" {
		netlabGeneratorImage = override
	}
	netlabGeneratorPullPolicy := strings.TrimSpace(enc.NetlabGenerator.PullPolicy)
	if override := strings.TrimSpace(getenv("SKYFORGE_NETLAB_GENERATOR_PULL_POLICY", "")); override != "" {
		netlabGeneratorPullPolicy = override
	}
	ansibleRunnerImage := strings.TrimSpace(enc.NetlabGenerator.AnsibleImage)
	if override := strings.TrimSpace(getenv("SKYFORGE_ANSIBLE_RUNNER_IMAGE", "")); override != "" {
		ansibleRunnerImage = override
	}
	ansibleRunnerPullPolicy := strings.TrimSpace(enc.NetlabGenerator.AnsiblePullPolicy)
	if override := strings.TrimSpace(getenv("SKYFORGE_ANSIBLE_RUNNER_PULL_POLICY", "")); override != "" {
		ansibleRunnerPullPolicy = override
	}

	eveServersRaw := strings.TrimSpace(os.Getenv("SKYFORGE_EVE_SERVERS_JSON"))
	if eveServersRaw == "" {
		eveServersRaw = strings.TrimSpace(readSecretFromFileEnv("SKYFORGE_EVE_SERVERS_FILE"))
	}
	eveServers, err := parseEveServers(eveServersRaw)
	if err != nil {
		log.Printf("invalid EVE servers config: %v", err)
	}
	filteredEveServers := make([]skyforgecore.EveServerConfig, 0, len(eveServers))
	for _, s := range eveServers {
		s = normalizeEveServer(s, labsCfg)
		if s.Name == "" || (s.APIURL == "" && s.WebURL == "" && s.SSHHost == "") {
			continue
		}
		filteredEveServers = append(filteredEveServers, s)
	}

	netlabServersRaw := strings.TrimSpace(os.Getenv("SKYFORGE_NETLAB_SERVERS_JSON"))
	if netlabServersRaw == "" {
		netlabServersRaw = strings.TrimSpace(readSecretFromFileEnv("SKYFORGE_NETLAB_SERVERS_FILE"))
	}
	netlabServers, err := parseNetlabServers(netlabServersRaw)
	if err != nil {
		log.Printf("invalid Netlab servers config: %v", err)
	}
	filteredNetlabServers := make([]skyforgecore.NetlabServerConfig, 0, len(netlabServers))
	for _, s := range netlabServers {
		s = normalizeNetlabServer(s, netlabCfg)
		if s.SSHHost == "" || s.SSHKeyFile == "" {
			continue
		}
		filteredNetlabServers = append(filteredNetlabServers, s)
	}

	uiCfg := skyforgecore.UIConfig{
		ProductName:      strings.TrimSpace(getenv("SKYFORGE_UI_PRODUCT_NAME", "Skyforge")),
		ProductSubtitle:  strings.TrimSpace(getenv("SKYFORGE_UI_PRODUCT_SUBTITLE", "Automation Hub")),
		LogoURL:          strings.TrimSpace(getenv("SKYFORGE_UI_LOGO_URL", "")),
		LogoAlt:          strings.TrimSpace(getenv("SKYFORGE_UI_LOGO_ALT", "Skyforge")),
		HeaderBackground: strings.TrimSpace(getenv("SKYFORGE_UI_HEADER_BG_URL", "")),
		SupportText:      strings.TrimSpace(getenv("SKYFORGE_UI_SUPPORT_TEXT", "Need access? Contact your platform admin.")),
		SupportURL:       strings.TrimSpace(getenv("SKYFORGE_UI_SUPPORT_URL", "")),
		ThemeDefault:     strings.TrimSpace(getenv("SKYFORGE_UI_THEME_DEFAULT", "")),
		OIDCEnabled:      strings.TrimSpace(oidcIssuerURL) != "" && strings.TrimSpace(oidcClientID) != "" && strings.TrimSpace(oidcClientSecret) != "" && strings.TrimSpace(oidcRedirectURL) != "",
		OIDCLoginURL:     "/api/skyforge/api/oidc/login",
	}

	notificationsEnabled := getenv("SKYFORGE_NOTIFICATIONS_ENABLED", "true") == "true"
	notificationsInterval := 30 * time.Second
	if enc.NotificationsIntervalSeconds > 0 && enc.NotificationsIntervalSeconds <= 3600 {
		notificationsInterval = time.Duration(enc.NotificationsIntervalSeconds) * time.Second
	}
	cloudCredentialChecks := 30 * time.Minute
	if enc.CloudCheckIntervalMinutes > 0 && enc.CloudCheckIntervalMinutes <= 24*60 {
		cloudCredentialChecks = time.Duration(enc.CloudCheckIntervalMinutes) * time.Minute
	}

	workspacesCfg := skyforgecore.WorkspacesConfig{
		DataDir:                         getenv("SKYFORGE_WORKSPACES_DATA_DIR", "/var/lib/skyforge"),
		GiteaAPIURL:                     strings.TrimRight(getenv("SKYFORGE_GITEA_API_URL", ""), "/"),
		GiteaUsername:                   getenv("SKYFORGE_GITEA_USERNAME", getenv("GITEA_ADMIN_USER", "skyforge")),
		GiteaPassword:                   strings.TrimSpace(sec.GiteaPassword),
		GiteaRepoPrivate:                getenv("SKYFORGE_GITEA_REPO_PRIVATE", "false") == "true",
		DeleteMode:                      strings.TrimSpace(getenv("SKYFORGE_WORKSPACE_DELETE_MODE", "live")),
		ObjectStorageEndpoint:           strings.TrimRight(getenv("SKYFORGE_OBJECT_STORAGE_ENDPOINT", "minio:9000"), "/"),
		ObjectStorageUseSSL:             getenv("SKYFORGE_OBJECT_STORAGE_USE_SSL", "false") == "true",
		ObjectStorageTerraformAccessKey: strings.TrimSpace(sec.ObjectStorageTerraformAccessKey),
		ObjectStorageTerraformSecretKey: strings.TrimSpace(sec.ObjectStorageTerraformSecretKey),
	}

	return skyforgecore.Config{
		ListenAddr:              getenv("SKYFORGE_LISTEN_ADDR", ":8085"),
		SessionSecret:           sec.SessionSecret,
		SessionTTL:              sessionTTL,
		SessionCookie:           getenv("SKYFORGE_SESSION_COOKIE", "skyforge_session"),
		CookieSecure:            getenv("SKYFORGE_COOKIE_SECURE", "auto"),
		CookieDomain:            strings.TrimSpace(getenv("SKYFORGE_COOKIE_DOMAIN", "")),
		InternalToken:           strings.TrimSpace(sec.InternalToken),
		StaticRoot:              strings.TrimSpace(getenv("SKYFORGE_STATIC_ROOT", "/opt/skyforge/static")),
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
		AwsSSOAccountID:         strings.TrimSpace(getenv("SKYFORGE_AWS_SSO_ACCOUNT_ID", "")),
		AwsSSORoleName:          strings.TrimSpace(getenv("SKYFORGE_AWS_SSO_ROLE_NAME", "")),
		AwsSSOStartURL:          strings.TrimSpace(getenv("SKYFORGE_AWS_SSO_START_URL", "")),
		AwsSSORegion:            strings.TrimSpace(getenv("SKYFORGE_AWS_SSO_REGION", "")),
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
		NetlabServers:             filteredNetlabServers,
		Labs:                      labsCfg,
		LDAP:                      ldapCfg,
		LDAPLookupBindDN:          ldapLookupBindDN,
		LDAPLookupBindPassword:    ldapLookupBindPassword,
		Workspaces:                workspacesCfg,
		EveServers:                filteredEveServers,
		LabppRunnerImage:          strings.TrimSpace(enc.Labpp.RunnerImage),
		LabppRunnerPullPolicy:     strings.TrimSpace(enc.Labpp.RunnerPullPolicy),
		LabppRunnerPVCName:        strings.TrimSpace(enc.Labpp.RunnerPVCName),
		LabppConfigDirBase:        strings.TrimSpace(enc.Labpp.ConfigDirBase),
		LabppConfigVersion:        strings.TrimSpace(enc.Labpp.ConfigVersion),
		LabppNetboxURL:            strings.TrimSpace(enc.Labpp.NetboxURL),
		LabppNetboxUsername:       strings.TrimSpace(sec.LabppNetboxUsername),
		LabppNetboxPassword:       strings.TrimSpace(sec.LabppNetboxPassword),
		LabppNetboxToken:          strings.TrimSpace(sec.LabppNetboxToken),
		LabppNetboxMgmtSubnet:     strings.TrimSpace(enc.Labpp.NetboxMgmtSubnet),
		LabppS3AccessKey:          strings.TrimSpace(sec.LabppS3AccessKey),
		LabppS3SecretKey:          strings.TrimSpace(sec.LabppS3SecretKey),
		LabppS3Region:             strings.TrimSpace(enc.Labpp.S3Region),
		LabppS3BucketName:         strings.TrimSpace(enc.Labpp.S3BucketName),
		LabppS3Endpoint:           strings.TrimSpace(enc.Labpp.S3Endpoint),
		LabppS3DisableSSL:         enc.Labpp.S3DisableSSL,
		LabppS3DisableChecksum:    enc.Labpp.S3DisableChecksum,
		YaadeAdminUsername:        strings.TrimSpace(getenv("SKYFORGE_YAADE_ADMIN_USERNAME", "admin")),
		YaadeAdminPassword:        strings.TrimSpace(sec.YaadeAdminPassword),
		ContainerlabAPIPath:       strings.TrimSpace(enc.Containerlab.APIPath),
		ContainerlabJWTSecret:     strings.TrimSpace(sec.ContainerlabJWTSecret),
		ContainerlabSkipTLSVerify: getenv("SKYFORGE_CONTAINERLAB_SKIP_TLS_VERIFY", "false") == "true",
		PKICACert:                 strings.TrimSpace(sec.PKICACert),
		PKICAKey:                  strings.TrimSpace(sec.PKICAKey),
		SSHCAKey:                  strings.TrimSpace(sec.SSHCAKey),
		PKIDefaultDays: func() int {
			v := 365
			if raw := strings.TrimSpace(getenv("SKYFORGE_PKI_DEFAULT_DAYS", "")); raw != "" {
				if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
					v = parsed
				}
			}
			return v
		}(),
		SSHCADefaultDays: func() int {
			v := 30
			if raw := strings.TrimSpace(getenv("SKYFORGE_SSH_DEFAULT_DAYS", "")); raw != "" {
				if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
					v = parsed
				}
			}
			return v
		}(),
		DNSURL:                    dnsURL,
		DNSAdminUsername:          dnsAdminUsername,
		DNSUserZoneSuffix:         dnsUserZoneSuffix,
		TaskWorkerEnabled:         taskWorkerEnabled,
		NetlabC9sGeneratorMode:    netlabC9sGeneratorMode,
		NetlabGeneratorImage:      netlabGeneratorImage,
		NetlabGeneratorPullPolicy: netlabGeneratorPullPolicy,
		AnsibleRunnerImage:        ansibleRunnerImage,
		AnsibleRunnerPullPolicy:   ansibleRunnerPullPolicy,
	}
}

func readSecretFromFileEnv(key string) string {
	path := strings.TrimSpace(os.Getenv(key))
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
