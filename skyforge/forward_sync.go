package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	_ "embed"
)

const (
	forwardNetworkIDKey        = "forwardNetworkId"
	forwardNetworkNameKey      = "forwardNetworkName"
	forwardCliCredentialIDKey  = "forwardCliCredentialId"
	forwardCliCredentialMap    = "forwardCliCredentialIdsByDevice"
	forwardSnmpCredentialIDKey = "forwardSnmpCredentialId"
	forwardJumpServerIDKey     = "forwardJumpServerId"
	forwardEndpointProfileID   = "forwardEndpointProfileId"
)

const (
	defaultNetlabDeviceUsername = "admin"
	defaultNetlabDevicePassword = "admin"
)

//go:embed netlab_device_defaults.json
var netlabDeviceDefaultsJSON []byte

type netlabDeviceCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type netlabDeviceCredentialSet struct {
	Device      string                   `json:"device,omitempty"`
	ImagePrefix string                   `json:"image_prefix,omitempty"`
	Credentials []netlabDeviceCredential `json:"credentials"`
}

type netlabDeviceDefaults struct {
	Source    string                      `json:"source"`
	Generated string                      `json:"generated_at"`
	Sets      []netlabDeviceCredentialSet `json:"sets"`
	Fallback  []netlabDeviceCredential    `json:"fallback"`
}

var netlabDefaults = loadNetlabDeviceDefaults()

func (s *Service) forwardDeviceTypes(ctx context.Context) map[string]string {
	out := map[string]string{
		"linux": "linux_os_ssh",
		"eos":   "arista_eos_ssh",
		// Netlab device keys for Cisco IOL/IOS images. Do not rely on auto-detection.
		"iol":    "cisco_ios_ssh",
		"ios":    "cisco_ios_ssh",
		"ios_xe": "cisco_ios_ssh",
		"ios-xe": "cisco_ios_ssh",
		"iosxe":  "cisco_ios_ssh",
	}
	if s == nil || s.db == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT device_key, forward_type FROM sf_forward_device_types`)
	if err != nil {
		// During rollout, migrations may not have run yet. Fall back to built-ins.
		if strings.Contains(strings.ToLower(err.Error()), "does not exist") {
			return out
		}
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var deviceKey string
		var forwardType string
		if scanErr := rows.Scan(&deviceKey, &forwardType); scanErr != nil {
			continue
		}
		deviceKey = strings.ToLower(strings.TrimSpace(deviceKey))
		forwardType = strings.TrimSpace(forwardType)
		if deviceKey == "" || forwardType == "" {
			continue
		}
		out[deviceKey] = forwardType
	}
	return out
}

func loadNetlabDeviceDefaults() netlabDeviceDefaults {
	var catalog netlabDeviceDefaults
	if len(netlabDeviceDefaultsJSON) == 0 {
		return catalog
	}
	if err := json.Unmarshal(netlabDeviceDefaultsJSON, &catalog); err != nil {
		log.Printf("netlab defaults: failed to parse catalog: %v", err)
		return netlabDeviceDefaults{}
	}
	return catalog
}

func netlabCredentialForDevice(device, image string) (netlabDeviceCredential, bool) {
	device = strings.ToLower(strings.TrimSpace(device))
	image = strings.ToLower(strings.TrimSpace(image))
	if device == "" && image == "" {
		return netlabDeviceCredential{}, false
	}
	isValid := func(cred netlabDeviceCredential) bool {
		return strings.TrimSpace(cred.Username) != "" && strings.TrimSpace(cred.Password) != ""
	}
	for _, set := range netlabDefaults.Sets {
		if set.Device != "" && strings.EqualFold(set.Device, device) {
			for _, cred := range set.Credentials {
				if isValid(cred) {
					return cred, true
				}
			}
		}
	}
	for _, set := range netlabDefaults.Sets {
		if set.ImagePrefix != "" && strings.HasPrefix(image, strings.ToLower(set.ImagePrefix)) {
			for _, cred := range set.Credentials {
				if isValid(cred) {
					return cred, true
				}
			}
		}
	}
	for _, cred := range netlabDefaults.Fallback {
		if isValid(cred) {
			return cred, true
		}
	}
	if defaultNetlabDeviceUsername != "" && defaultNetlabDevicePassword != "" {
		return netlabDeviceCredential{
			Username: defaultNetlabDeviceUsername,
			Password: defaultNetlabDevicePassword,
		}, true
	}
	return netlabDeviceCredential{}, false
}

type netlabStatusDevice struct {
	Node     string
	Device   string
	Image    string
	MgmtIPv4 string
	Provider string
	Status   string
}

func parseNetlabStatusOutput(logText string) []netlabStatusDevice {
	if strings.TrimSpace(logText) == "" {
		return nil
	}
	rows := []netlabStatusDevice{}
	cleaned := stripANSICodes(logText)
	lines := strings.SplitSeq(cleaned, "\n")
	for line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "│") {
			continue
		}
		if strings.HasPrefix(trimmed, "│ node") || strings.Contains(trimmed, "node │ device") {
			continue
		}
		parts := strings.Split(line, "│")
		if len(parts) < 3 {
			continue
		}
		cols := make([]string, 0, len(parts))
		for _, part := range parts[1 : len(parts)-1] {
			cols = append(cols, strings.TrimSpace(part))
		}
		if len(cols) < 4 {
			continue
		}
		row := netlabStatusDevice{
			Node:     cols[0],
			Device:   cols[1],
			Image:    cols[2],
			MgmtIPv4: cols[3],
		}
		if len(cols) >= 6 {
			row.Provider = cols[5]
		}
		if len(cols) >= 8 {
			row.Status = cols[7]
		}
		if strings.TrimSpace(row.Node) == "" || row.Node == "—" {
			continue
		}
		rows = append(rows, row)
	}
	return rows
}

func stripANSICodes(value string) string {
	if value == "" {
		return value
	}
	var b strings.Builder
	b.Grow(len(value))
	inEscape := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if inEscape {
			// ANSI escape sequences end in a letter.
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				inEscape = false
			}
			continue
		}
		if ch == 0x1b {
			inEscape = true
			continue
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func (s *Service) forwardConfigForWorkspace(ctx context.Context, workspaceID string) (*forwardCredentials, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getWorkspaceForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), workspaceID)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	if strings.TrimSpace(rec.BaseURL) == "" {
		rec.BaseURL = defaultForwardBaseURL
	}
	if strings.TrimSpace(rec.Username) == "" || strings.TrimSpace(rec.Password) == "" {
		return nil, nil
	}
	return rec, nil
}

func (s *Service) forwardConfigForUser(ctx context.Context, username string) (*forwardCredentials, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getUserForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), username)
	if err != nil || rec == nil {
		return nil, err
	}

	if strings.TrimSpace(rec.BaseURL) == "" {
		rec.BaseURL = defaultForwardBaseURL
	}
	if strings.TrimSpace(rec.ForwardUsername) == "" || strings.TrimSpace(rec.ForwardPassword) == "" {
		return nil, nil
	}

	collectorUser := strings.TrimSpace(rec.CollectorUsername)
	if collectorUser == "" && strings.TrimSpace(rec.AuthorizationKey) != "" {
		if before, _, ok := strings.Cut(rec.AuthorizationKey, ":"); ok {
			collectorUser = strings.TrimSpace(before)
		}
	}

	return &forwardCredentials{
		BaseURL:       rec.BaseURL,
		SkipTLSVerify: rec.SkipTLSVerify,
		Username:      rec.ForwardUsername,
		Password:      rec.ForwardPassword,
		CollectorUser: collectorUser,
	}, nil
}

func (s *Service) ensureForwardNetworkForDeployment(ctx context.Context, pc *workspaceContext, dep *WorkspaceDeployment) (map[string]any, error) {
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	forwardCfg, err := s.forwardConfigForUser(ctx, pc.claims.Username)
	if err != nil || forwardCfg == nil {
		return cfgAny, err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return cfgAny, err
	}

	getString := func(key string) string {
		raw, ok := cfgAny[key]
		if !ok {
			return ""
		}
		if v, ok := raw.(string); ok {
			return strings.TrimSpace(v)
		}
		return strings.TrimSpace(fmt.Sprintf("%v", raw))
	}

	networkName := getString(forwardNetworkNameKey)
	credentialName := ""
	if networkName != "" {
		credentialName = networkName
	}
	networkID := getString(forwardNetworkIDKey)
	changed := false
	if networkID == "" {
		// Prefer a stable, human-readable Forward network name:
		//   <deploymentName>-<username>
		// with a timestamp fallback only when we hit a name collision.
		baseName := fmt.Sprintf("%s-%s", dep.Name, strings.TrimSpace(pc.claims.Username))
		network, err := forwardCreateNetworkWithRetry(ctx, client, baseName)
		if err != nil {
			return cfgAny, err
		}
		networkID = network.ID
		cfgAny[forwardNetworkIDKey] = networkID
		cfgAny[forwardNetworkNameKey] = strings.TrimSpace(network.Name)
		credentialName = strings.TrimSpace(network.Name)
		changed = true
	}

	collectorUser := strings.TrimSpace(getString("forwardCollectorUsername"))
	if collectorUser == "" {
		collectorUser = strings.TrimSpace(forwardCfg.CollectorUser)
	}
	if collectorUser != "" {
		status, err := forwardGetCollectorStatus(ctx, client, networkID)
		if err != nil && strings.Contains(err.Error(), "not found") {
			baseName := fmt.Sprintf("%s-%s", dep.Name, strings.TrimSpace(pc.claims.Username))
			network, createErr := forwardCreateNetworkWithRetry(ctx, client, baseName)
			if createErr != nil {
				return cfgAny, createErr
			}
			networkID = network.ID
			cfgAny[forwardNetworkIDKey] = networkID
			cfgAny[forwardNetworkNameKey] = strings.TrimSpace(network.Name)
			changed = true
			status, err = forwardGetCollectorStatus(ctx, client, networkID)
		}
		if err != nil {
			return cfgAny, err
		}
		if status != nil && !status.IsSet {
			if err := forwardSetCollector(ctx, client, networkID, collectorUser); err != nil {
				return cfgAny, err
			}
		}
	}

	cliCredentialID := getString(forwardCliCredentialIDKey)
	deviceUsername := strings.TrimSpace(forwardCfg.DeviceUsername)
	devicePassword := strings.TrimSpace(forwardCfg.DevicePassword)
	if deviceUsername == "" && devicePassword == "" && dep.Type == "netlab" {
		deviceUsername = defaultNetlabDeviceUsername
		devicePassword = defaultNetlabDevicePassword
	}
	// For Netlab deployments, we prefer per-device credentials (created during sync based on the
	// discovered device types) over a single default credential. Keep the legacy default credential
	// behavior for other deployment types.
	if cliCredentialID == "" && deviceUsername != "" && devicePassword != "" && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(dep.Type)), "netlab") {
		cred, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialName, deviceUsername, devicePassword)
		if err != nil {
			if strings.Contains(err.Error(), "No collector configured") {
				log.Printf("forward cli credential skipped: %v", err)
			} else {
				return cfgAny, err
			}
		} else {
			cliCredentialID = cred.ID
			cfgAny[forwardCliCredentialIDKey] = cliCredentialID
			changed = true
		}
	}

	snmpCredentialID := getString(forwardSnmpCredentialIDKey)
	if snmpCredentialID == "" && s.cfg.Forward.SNMPPlaceholderEnabled {
		community := strings.TrimSpace(s.cfg.Forward.SNMPCommunity)
		if community != "" {
			cred, err := forwardCreateSnmpCredential(ctx, client, networkID, credentialName, community)
			if err != nil {
				if strings.Contains(err.Error(), "No collector configured") ||
					strings.Contains(strings.ToLower(err.Error()), "not found") {
					log.Printf("forward snmp credential skipped: %v", err)
				} else {
					return cfgAny, err
				}
			} else {
				snmpCredentialID = cred.ID
				cfgAny[forwardSnmpCredentialIDKey] = snmpCredentialID
				changed = true
			}
		}
	}

	jumpServerID := getString(forwardJumpServerIDKey)
	jumpHost := strings.TrimSpace(forwardCfg.JumpHost)
	jumpKey := strings.TrimSpace(forwardCfg.JumpPrivateKey)
	jumpUser := strings.TrimSpace(forwardCfg.JumpUsername)
	jumpCert := strings.TrimSpace(forwardCfg.JumpCert)
	useUserJump := strings.TrimSpace(forwardCfg.JumpPrivateKey) != "" || strings.TrimSpace(forwardCfg.JumpCert) != ""
	if dep.Type == "netlab" && useUserJump {
		if userName := strings.TrimSpace(pc.claims.Username); userName != "" {
			jumpUser = userName
		}
	}
	if jumpUser == "" {
		jumpUser = strings.TrimSpace(pc.claims.Username)
	}
	if jumpServerID == "" && jumpHost != "" && jumpKey != "" && jumpUser != "" {
		jump, err := forwardCreateJumpServer(ctx, client, networkID, jumpHost, jumpUser, jumpKey, jumpCert)
		if err != nil {
			if strings.Contains(err.Error(), "No collector configured") {
				log.Printf("forward jump server skipped: %v", err)
			} else {
				return cfgAny, err
			}
		} else {
			jumpServerID = jump.ID
			cfgAny[forwardJumpServerIDKey] = jumpServerID
			changed = true
		}
	}

	if changed {
		if err := s.updateDeploymentConfig(ctx, pc.workspace.ID, dep.ID, cfgAny); err != nil {
			return cfgAny, err
		}
	}
	return cfgAny, nil
}

func forwardCreateNetworkWithRetry(ctx context.Context, client *forwardClient, baseName string) (*forwardNetwork, error) {
	name := strings.TrimSpace(baseName)
	name = strings.TrimSpace(strings.ReplaceAll(name, "@", "-"))
	name = strings.TrimSpace(strings.ReplaceAll(name, " ", "-"))
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	name = strings.Trim(name, "-")
	if name == "" {
		name = "deployment"
	}
	if len(name) > 80 {
		name = strings.TrimRight(name[:80], "-")
	}

	for attempt := 0; attempt < 4; attempt++ {
		tryName := name
		if attempt > 0 {
			suffix := time.Now().UTC().Format("1504")
			if attempt > 1 {
				suffix = fmt.Sprintf("%s-%02d", suffix, attempt-1)
			}
			tryName = fmt.Sprintf("%s-%s", name, suffix)
			if len(tryName) > 80 {
				tryName = strings.TrimRight(tryName[:80], "-")
			}
		}
		network, err := forwardCreateNetwork(ctx, client, tryName)
		if err == nil {
			return network, nil
		}
		// Only retry on name collisions.
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "already used") && !strings.Contains(msg, "already exists") && !strings.Contains(msg, "duplicate") {
			return nil, err
		}
	}
	return nil, fmt.Errorf("forward network name collision after retries")
}

func isForwardNameCollision(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "duplicate") ||
		strings.Contains(msg, "name is already") ||
		strings.Contains(msg, "name exists")
}

func isForwardJumpServerMissing(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "jump server") && strings.Contains(msg, "not found")
}

func (s *Service) syncForwardNetlabDevices(ctx context.Context, taskID int, pc *workspaceContext, dep *WorkspaceDeployment, logText string) (int, error) {
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	cfgAny, err := s.ensureForwardNetworkForDeployment(ctx, pc, dep)
	if err != nil {
		return 0, err
	}

	forwardCfg, err := s.forwardConfigForUser(ctx, pc.claims.Username)
	if err != nil || forwardCfg == nil {
		// Workspace isn't configured for Forward; treat as a best-effort no-op.
		if s != nil && s.db != nil && taskID > 0 {
			_ = appendTaskEvent(context.Background(), s.db, taskID, "forward.devices.upload.skipped", map[string]any{
				"source": "netlab",
				"reason": "forward_not_configured",
			})
		}
		return 0, err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return 0, err
	}

	getString := func(key string) string {
		raw, ok := cfgAny[key]
		if !ok {
			return ""
		}
		if v, ok := raw.(string); ok {
			return strings.TrimSpace(v)
		}
		return strings.TrimSpace(fmt.Sprintf("%v", raw))
	}

	networkID := getString(forwardNetworkIDKey)
	if networkID == "" {
		if s != nil && s.db != nil && taskID > 0 {
			_ = appendTaskEvent(context.Background(), s.db, taskID, "forward.devices.upload.skipped", map[string]any{
				"source": "netlab",
				"reason": "network_id_missing",
			})
		}
		return 0, nil
	}
	if s != nil && s.db != nil && taskID > 0 {
		_ = appendTaskEvent(context.Background(), s.db, taskID, "forward.devices.upload.started", map[string]any{
			"source":    "netlab",
			"networkId": networkID,
		})
	}
	deploymentName := strings.TrimSpace(dep.Name)
	credentialBase := deploymentName
	if credentialBase == "" {
		credentialBase = strings.TrimSpace(getString(forwardNetworkNameKey))
	}
	jumpServerID := getString(forwardJumpServerIDKey)
	defaultCliCredentialID := getString(forwardCliCredentialIDKey)
	snmpCredentialID := getString(forwardSnmpCredentialIDKey)
	forwardTypes := s.forwardDeviceTypes(ctx)
	credentialIDsByDevice := map[string]string{}
	if raw, ok := cfgAny[forwardCliCredentialMap]; ok {
		if parsed, ok := raw.(map[string]any); ok {
			for key, value := range parsed {
				if id, ok := value.(string); ok && strings.TrimSpace(id) != "" {
					credentialIDsByDevice[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(id)
				}
			}
		}
	}
	endpointProfileID := getString(forwardEndpointProfileID)
	linuxEndpoints := []forwardEndpoint{}
	seenLinux := false

	sanitizeCredentialComponent := func(value string) string {
		value = strings.ToLower(strings.TrimSpace(value))
		value = strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z':
				return r
			case r >= '0' && r <= '9':
				return r
			case r == '-' || r == '_' || r == '.':
				return r
			default:
				return '-'
			}
		}, value)
		value = strings.Trim(value, "-")
		for strings.Contains(value, "--") {
			value = strings.ReplaceAll(value, "--", "-")
		}
		if value == "" {
			return "deployment"
		}
		return value
	}
	credentialNameForDevice := func(deviceKey string) string {
		base := sanitizeCredentialComponent(credentialBase)
		device := sanitizeCredentialComponent(deviceKey)
		if device == "" {
			device = "default"
		}
		name := fmt.Sprintf("%s-%s", base, device)
		if len(name) > 80 {
			name = name[:80]
			name = strings.TrimRight(name, "-")
		}
		return name
	}

	devices := []forwardClassicDevice{}
	seen := map[string]bool{}
	changed := false
	for _, row := range parseNetlabStatusOutput(logText) {
		name := strings.TrimSpace(row.Node)
		deviceKey := strings.ToLower(strings.TrimSpace(row.Device))
		switch deviceKey {
		case "host":
			deviceKey = "linux"
		case "cisco_iol", "iol", "ios_xe", "ios-xe", "iosxe":
			deviceKey = "ios"
		}
		if deviceKey == "linux" {
			seenLinux = true
		}
		cred, ok := netlabCredentialForDevice(row.Device, row.Image)
		if !ok && defaultCliCredentialID == "" {
			continue
		}

		cliCredentialID := ""
		if deviceKey != "" {
			cliCredentialID = credentialIDsByDevice[deviceKey]
		}
		// Prefer per-device credentials over the legacy default credential.
		if cliCredentialID == "" && strings.TrimSpace(cred.Username) != "" && strings.TrimSpace(cred.Password) != "" {
			created, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialNameForDevice(deviceKey), cred.Username, cred.Password)
			if err != nil {
				if strings.Contains(err.Error(), "No collector configured") {
					log.Printf("forward cli credential skipped: %v", err)
				} else {
					return 0, err
				}
			} else {
				cliCredentialID = created.ID
				if deviceKey != "" {
					credentialIDsByDevice[deviceKey] = cliCredentialID
					changed = true
				}
			}
		}
		if cliCredentialID == "" {
			cliCredentialID = defaultCliCredentialID
		}

		// Create-only runs can produce device type/image data without management IPs yet.
		// Still create (and persist) the per-device credentials so the subsequent `up`
		// can reuse them without needing a default credential.
		mgmt := strings.TrimSpace(row.MgmtIPv4)
		if mgmt == "" || mgmt == "—" {
			continue
		}
		key := strings.ToLower(mgmt)
		if seen[key] {
			continue
		}
		seen[key] = true
		if name == "" {
			name = mgmt
		}
		if deviceKey == "linux" {
			endpoint := forwardEndpoint{
				Type:          "CLI",
				Name:          name,
				Host:          mgmt,
				Protocol:      "SSH",
				CredentialID:  cliCredentialID,
				ProfileID:     endpointProfileID,
				JumpServerID:  jumpServerID,
				Collect:       true,
				LargeRTT:      false,
				FullCollect:   false,
				Note:          "",
				Port:          22,
			}
			linuxEndpoints = append(linuxEndpoints, endpoint)
			continue
		}
		forwardType := ""
		if deviceKey != "" {
			forwardType = forwardTypes[deviceKey]
		}
		// Netlab sometimes reports Cisco IOL images under different keys; always force IOS SSH.
		if forwardType == "" {
			imageLower := strings.ToLower(strings.TrimSpace(row.Image))
			if deviceKey == "ios" || strings.Contains(imageLower, "cisco_iol") {
				forwardType = "cisco_ios_ssh"
			}
		}
		devices = append(devices, forwardClassicDevice{
			Name:                     name,
			Type:                     forwardType,
			Host:                     mgmt,
			Port:                     22,
			CliCredentialID:          cliCredentialID,
			SnmpCredentialID:         snmpCredentialID,
			JumpServerID:             jumpServerID,
			CollectBgpAdvertisements: true,
			BgpTableType:             "BOTH",
			BgpPeerType:              "BOTH",
			EnableSnmpCollection:     true,
		})
	}

	if len(devices) == 0 {
		if s != nil && s.db != nil && taskID > 0 {
			_ = appendTaskEvent(context.Background(), s.db, taskID, "forward.devices.upload.skipped", map[string]any{
				"source":    "netlab",
				"networkId": networkID,
				"reason":    "no_devices",
			})
		}
		return 0, nil
	}
	if seenLinux {
		if endpointProfileID == "" {
			profileID, err := forwardEnsureEndpointProfile(ctx, client, "Linux")
			if err != nil {
				return 0, err
			}
			endpointProfileID = profileID
			cfgAny[forwardEndpointProfileID] = endpointProfileID
			changed = true
		}
		for i := range linuxEndpoints {
			linuxEndpoints[i].ProfileID = endpointProfileID
		}
		if len(linuxEndpoints) > 0 {
			if err := forwardPutEndpoints(ctx, client, networkID, linuxEndpoints); err != nil {
				if s != nil && s.db != nil && taskID > 0 {
					_ = appendTaskEvent(context.Background(), s.db, taskID, "forward.endpoints.upload.failed", map[string]any{
						"source":    "netlab",
						"networkId": networkID,
						"error":     strings.TrimSpace(err.Error()),
					})
				}
				return 0, err
			}
		}
	}
	if err := forwardPutClassicDevices(ctx, client, networkID, devices); err != nil {
		if isForwardJumpServerMissing(err) && jumpServerID != "" {
			cfgAny[forwardJumpServerIDKey] = ""
			refreshed, refreshErr := s.ensureForwardNetworkForDeployment(ctx, pc, dep)
			if refreshErr != nil {
				return 0, refreshErr
			}
			cfgAny = refreshed
			jumpServerID = getString(forwardJumpServerIDKey)
			for i := range devices {
				devices[i].JumpServerID = jumpServerID
			}
			if retryErr := forwardPutClassicDevices(ctx, client, networkID, devices); retryErr != nil {
				return 0, retryErr
			}
			changed = true
		} else {
			if s != nil && s.db != nil && taskID > 0 {
				_ = appendTaskEvent(context.Background(), s.db, taskID, "forward.devices.upload.failed", map[string]any{
					"source":    "netlab",
					"networkId": networkID,
					"error":     strings.TrimSpace(err.Error()),
				})
			}
			return 0, err
		}
	}
	for attempt := 1; attempt <= 3; attempt++ {
		if err := forwardStartCollection(ctx, client, networkID); err != nil {
			if strings.Contains(err.Error(), "No valid devices") && attempt < 3 {
				time.Sleep(time.Duration(attempt) * time.Second)
				continue
			}
			log.Printf("forward start collection: %v", err)
			break
		}
		break
	}
	if s != nil && s.db != nil && taskID > 0 {
		_ = appendTaskEvent(context.Background(), s.db, taskID, "forward.devices.upload.succeeded", map[string]any{
			"source":      "netlab",
			"networkId":   networkID,
			"deviceCount": len(devices),
		})
	}
	if changed {
		cfgAny[forwardCliCredentialMap] = credentialIDsByDevice
		if err := s.updateDeploymentConfig(ctx, pc.workspace.ID, dep.ID, cfgAny); err != nil {
			return 0, err
		}
	}
	return len(devices), nil
}

func applyForwardOverrides(base *forwardCredentials, override *forwardCredentials) *forwardCredentials {
	if override == nil {
		return base
	}
	if base == nil {
		return override
	}
	if strings.TrimSpace(override.BaseURL) != "" {
		base.BaseURL = strings.TrimSpace(override.BaseURL)
	}
	if strings.TrimSpace(override.Username) != "" {
		base.Username = strings.TrimSpace(override.Username)
	}
	if strings.TrimSpace(override.Password) != "" {
		base.Password = strings.TrimSpace(override.Password)
	}
	if strings.TrimSpace(override.CollectorID) != "" {
		base.CollectorID = strings.TrimSpace(override.CollectorID)
	}
	if strings.TrimSpace(override.DeviceUsername) != "" {
		base.DeviceUsername = strings.TrimSpace(override.DeviceUsername)
	}
	if strings.TrimSpace(override.DevicePassword) != "" {
		base.DevicePassword = strings.TrimSpace(override.DevicePassword)
	}
	return base
}

func (s *Service) updateDeploymentConfig(ctx context.Context, workspaceID, deploymentID string, cfgAny map[string]any) error {
	if s.db == nil {
		return fmt.Errorf("database unavailable")
	}
	cfg, err := toJSONMap(cfgAny)
	if err != nil {
		return err
	}
	cfgBytes, _ := json.Marshal(cfg)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `UPDATE sf_deployments SET
  config=$1,
  updated_at=now()
WHERE workspace_id=$2 AND id=$3`, cfgBytes, workspaceID, deploymentID)
	return err
}
