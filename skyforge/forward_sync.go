package skyforge

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
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

func labppCredentialForDevice(deviceType string) (netlabDeviceCredential, bool) {
	t := strings.ToLower(strings.TrimSpace(deviceType))
	if t == "" {
		return netlabDeviceCredential{
			Username: "admin",
			Password: "Testpasswd!",
		}, true
	}
	switch {
	case strings.Contains(t, "nxos"):
		return netlabDeviceCredential{Username: "admin", Password: "4h9MK7rSo6q2qua"}, true
	case strings.Contains(t, "docker"):
		return netlabDeviceCredential{Username: "root", Password: "Testpasswd!"}, true
	case strings.Contains(t, "xrv"):
		return netlabDeviceCredential{Username: "testuser", Password: "Testpasswd!"}, true
	case strings.Contains(t, "a10"):
		return netlabDeviceCredential{Username: "admin", Password: "a10"}, true
	case strings.Contains(t, "nokia") || strings.Contains(t, "vsim"):
		return netlabDeviceCredential{Username: "admin", Password: "admin"}, true
	case strings.Contains(t, "alpine"):
		return netlabDeviceCredential{Username: "root", Password: "Forward123"}, true
	}
	switch {
	case strings.Contains(t, "vmx"):
		return netlabCredentialForDevice("vmx", "")
	case strings.Contains(t, "vjunos-switch"):
		return netlabCredentialForDevice("vjunos-switch", "")
	case strings.Contains(t, "vjunos"):
		return netlabCredentialForDevice("vjunos-router", "")
	case strings.Contains(t, "vsrx"):
		return netlabCredentialForDevice("vsrx", "")
	case strings.Contains(t, "vptx"):
		return netlabCredentialForDevice("vptx", "")
	}
	return netlabDeviceCredential{
		Username: "admin",
		Password: "Testpasswd!",
	}, true
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
	lines := strings.Split(cleaned, "\n")
	for _, line := range lines {
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

type labppDeviceInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	MgmtIP string `json:"mgmtIp"`
	Port   int    `json:"port"`
}

type labppDevicesResponse struct {
	ID      string            `json:"id"`
	Devices []labppDeviceInfo `json:"devices"`
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

func (s *Service) ensureForwardNetworkForDeployment(ctx context.Context, pc *workspaceContext, dep *WorkspaceDeployment) (map[string]any, error) {
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	forwardCfg, err := s.forwardConfigForWorkspace(ctx, pc.workspace.ID)
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
		networkName := fmt.Sprintf("%s-%s", dep.Name, time.Now().UTC().Format("20060102-1504"))
		network, err := forwardCreateNetworkWithRetry(ctx, client, networkName)
		if err != nil {
			return cfgAny, err
		}
		networkID = network.ID
		cfgAny[forwardNetworkIDKey] = networkID
		cfgAny[forwardNetworkNameKey] = networkName
		credentialName = networkName
		changed = true
	}

	collectorUser := strings.TrimSpace(forwardCfg.CollectorUser)
	if collectorUser != "" {
		status, err := forwardGetCollectorStatus(ctx, client, networkID)
		if err != nil && strings.Contains(err.Error(), "not found") {
			networkName := fmt.Sprintf("%s-%s", dep.Name, time.Now().UTC().Format("20060102-1504"))
			network, createErr := forwardCreateNetworkWithRetry(ctx, client, networkName)
			if createErr != nil {
				return cfgAny, createErr
			}
			networkID = network.ID
			cfgAny[forwardNetworkIDKey] = networkID
			cfgAny[forwardNetworkNameKey] = networkName
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
	if snmpCredentialID == "" && getenvBool("SKYFORGE_FORWARD_SNMP_CREATE_PLACEHOLDER", true) {
		community := strings.TrimSpace(getenv("SKYFORGE_FORWARD_SNMP_COMMUNITY", "public"))
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
	if dep.Type == "labpp" && useUserJump {
		if userName := strings.TrimSpace(pc.claims.Username); userName != "" {
			jumpUser = userName
		}
	}
	if dep.Type == "netlab" && (jumpHost == "" || jumpKey == "" || jumpUser == "") {
		netlabServerName := getString("netlabServer")
		if netlabServerName != "" {
			if server, _ := resolveNetlabServer(s.cfg, netlabServerName); server != nil {
				if jumpHost == "" {
					jumpHost = strings.TrimSpace(server.SSHHost)
				}
				if jumpUser == "" || !useUserJump {
					jumpUser = strings.TrimSpace(server.SSHUser)
				}
				if jumpKey == "" && server.SSHKeyFile != "" {
					if keyBytes, err := os.ReadFile(server.SSHKeyFile); err == nil {
						jumpKey = strings.TrimSpace(string(keyBytes))
					}
				}
			}
		}
	}
	if dep.Type == "labpp" && (jumpHost == "" || jumpKey == "" || jumpUser == "") {
		eveServerName := getString("eveServer")
		if eveServerName != "" {
			if server := eveServerByName(s.cfg.EveServers, eveServerName); server != nil {
				eve := normalizeEveServer(*server, s.cfg.Labs)
				if jumpHost == "" {
					jumpHost = strings.TrimSpace(eve.SSHHost)
				}
				if jumpUser == "" || !useUserJump {
					jumpUser = strings.TrimSpace(eve.SSHUser)
				}
				if jumpKey == "" && strings.TrimSpace(s.cfg.Labs.EveSSHKeyFile) != "" {
					if keyBytes, err := os.ReadFile(strings.TrimSpace(s.cfg.Labs.EveSSHKeyFile)); err == nil {
						jumpKey = strings.TrimSpace(string(keyBytes))
					}
				}
			}
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
	if name == "" {
		name = fmt.Sprintf("deployment-%s", time.Now().UTC().Format("20060102-1504"))
	}
	for attempt := 0; attempt < 3; attempt++ {
		network, err := forwardCreateNetwork(ctx, client, name)
		if err == nil {
			return network, nil
		}
		if !strings.Contains(err.Error(), "already used") {
			return nil, err
		}
		name = fmt.Sprintf("%s-%02d", baseName, attempt+1)
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

func (s *Service) syncForwardNetlabDevices(ctx context.Context, taskID int, pc *workspaceContext, dep *WorkspaceDeployment, logText string) error {
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	cfgAny, err := s.ensureForwardNetworkForDeployment(ctx, pc, dep)
	if err != nil {
		return err
	}

	forwardCfg, err := s.forwardConfigForWorkspace(ctx, pc.workspace.ID)
	if err != nil || forwardCfg == nil {
		return err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return err
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
		return nil
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
		mgmt := strings.TrimSpace(row.MgmtIPv4)
		if mgmt == "" || mgmt == "—" {
			continue
		}
		key := strings.ToLower(mgmt)
		if seen[key] {
			continue
		}
		seen[key] = true
		name := strings.TrimSpace(row.Node)
		if name == "" {
			name = mgmt
		}
		deviceKey := strings.ToLower(strings.TrimSpace(row.Device))
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
					return err
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
		devices = append(devices, forwardClassicDevice{
			Name:                     name,
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
		return nil
	}
	if err := forwardPutClassicDevices(ctx, client, networkID, devices); err != nil {
		if isForwardJumpServerMissing(err) && jumpServerID != "" {
			cfgAny[forwardJumpServerIDKey] = ""
			refreshed, refreshErr := s.ensureForwardNetworkForDeployment(ctx, pc, dep)
			if refreshErr != nil {
				return refreshErr
			}
			cfgAny = refreshed
			jumpServerID = getString(forwardJumpServerIDKey)
			for i := range devices {
				devices[i].JumpServerID = jumpServerID
			}
			if retryErr := forwardPutClassicDevices(ctx, client, networkID, devices); retryErr != nil {
				return retryErr
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
			return err
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
			return err
		}
	}
	return nil
}

func readLabppDataSourcesCSV(path string) ([]labppDeviceInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := csv.NewReader(f)
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	devices := []labppDeviceInfo{}
	if len(records) == 0 {
		return nil, fmt.Errorf("data_sources.csv contains no devices")
	}
	header := make([]string, len(records[0]))
	for i, value := range records[0] {
		header[i] = strings.ToLower(strings.TrimSpace(value))
	}
	findIndex := func(names ...string) int {
		for _, name := range names {
			for idx, value := range header {
				if value == name {
					return idx
				}
			}
		}
		return -1
	}
	nameIdx := findIndex("name")
	if nameIdx == -1 {
		nameIdx = 0
	}
	ipIdx := findIndex("ip_address", "mgmt_ip", "mgmt_ip_address", "management_ip", "management_ipv4", "ip")
	hostIdx := findIndex("host", "hostname", "ssh_host")
	portIdx := findIndex("ssh_port", "port")

	extractIPv4 := func(value string) (string, bool) {
		clean := strings.TrimSpace(value)
		if clean == "" {
			return "", false
		}
		if slash := strings.Index(clean, "/"); slash > 0 {
			clean = clean[:slash]
		}
		if host, _, err := net.SplitHostPort(clean); err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
				return host, true
			}
		}
		if ip := net.ParseIP(clean); ip != nil && ip.To4() != nil {
			return clean, true
		}
		return "", false
	}

	for i := 1; i < len(records); i++ {
		record := records[i]
		if len(record) <= nameIdx {
			continue
		}
		name := strings.TrimSpace(record[nameIdx])
		if name == "" {
			continue
		}

		mgmtIP := ""
		host := ""
		if ipIdx >= 0 && len(record) > ipIdx {
			raw := strings.TrimSpace(record[ipIdx])
			if ip, ok := extractIPv4(raw); ok {
				mgmtIP = ip
			} else if raw != "" {
				// LabPP's data_sources.csv may use hostnames in the ip_address column
				// (e.g. EVE host + per-device ssh_port). Preserve it as a host so we
				// can still upload devices to Forward using host+port.
				host = raw
			}
		}
		if mgmtIP == "" {
			for _, value := range record {
				if ip, ok := extractIPv4(value); ok {
					mgmtIP = ip
					break
				}
			}
		}

		if mgmtIP == "" && hostIdx >= 0 && len(record) > hostIdx {
			host = firstNonEmptyTrimmed(host, record[hostIdx])
		}
		if mgmtIP == "" && host == "" {
			continue
		}

		port := 22
		if mgmtIP == "" {
			// Only honor explicit port values when we don't have a management IPv4.
			if portIdx >= 0 && len(record) > portIdx {
				if rawPort := strings.TrimSpace(record[portIdx]); rawPort != "" {
					if parsed, err := strconv.Atoi(rawPort); err == nil && parsed > 0 {
						port = parsed
					}
				}
			} else if host != "" {
				if hostOnly, portStr, err := net.SplitHostPort(host); err == nil {
					host = hostOnly
					if parsed, err := strconv.Atoi(strings.TrimSpace(portStr)); err == nil && parsed > 0 {
						port = parsed
					}
				}
			}
		}

		devices = append(devices, labppDeviceInfo{
			Name:   name,
			MgmtIP: firstNonEmptyTrimmed(mgmtIP, host),
			Port:   port,
		})
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("data_sources.csv contains no devices")
	}
	return devices, nil
}

func firstNonEmptyTrimmed(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Service) syncForwardLabppDevicesFromCSV(ctx context.Context, taskID int, pc *workspaceContext, deploymentID, csvPath string, startCollection bool, override *forwardCredentials) error {
	if pc == nil {
		return fmt.Errorf("workspace context unavailable")
	}
	if strings.TrimSpace(deploymentID) == "" {
		return fmt.Errorf("deployment id is required")
	}
	dep, err := s.getWorkspaceDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return err
	}
	if dep == nil {
		return fmt.Errorf("deployment not found")
	}
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	cfgAny, err = s.ensureForwardNetworkForDeployment(ctx, pc, dep)
	if err != nil {
		return err
	}
	devices, err := readLabppDataSourcesCSV(csvPath)
	if err != nil {
		return err
	}
	forwardCfg, err := s.forwardConfigForWorkspace(ctx, pc.workspace.ID)
	if err != nil {
		return err
	}
	forwardCfg = applyForwardOverrides(forwardCfg, override)
	if forwardCfg == nil {
		return nil
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return err
	}
	deviceUsername := strings.TrimSpace(forwardCfg.DeviceUsername)
	devicePassword := strings.TrimSpace(forwardCfg.DevicePassword)
	return s.syncForwardLabppDevicesWithList(ctx, taskID, pc, dep, cfgAny, client, deviceUsername, devicePassword, devices, startCollection)
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

func (s *Service) syncForwardLabppDevicesWithList(ctx context.Context, taskID int, pc *workspaceContext, dep *WorkspaceDeployment, cfgAny map[string]any, client *forwardClient, deviceUsername, devicePassword string, devicesResp []labppDeviceInfo, startCollection bool) error {
	if pc == nil || dep == nil {
		return fmt.Errorf("workspace context unavailable")
	}
	if client == nil {
		return fmt.Errorf("forward client is required")
	}
	if cfgAny == nil {
		cfgAny = map[string]any{}
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
		return fmt.Errorf("forward network missing for deployment")
	}
	if s != nil && s.db != nil && taskID > 0 {
		_ = appendTaskEvent(context.Background(), s.db, taskID, "forward.devices.upload.started", map[string]any{
			"source":    "labpp",
			"networkId": networkID,
		})
	}
	credentialName := strings.TrimSpace(getString(forwardNetworkNameKey))
	jumpServerID := getString(forwardJumpServerIDKey)
	defaultCliCredentialID := getString(forwardCliCredentialIDKey)
	snmpCredentialID := getString(forwardSnmpCredentialIDKey)

	credentialIDsByDevice := map[string]string{}
	if raw, ok := cfgAny[forwardCliCredentialMap]; ok {
		if decoded, ok := raw.(map[string]any); ok {
			for key, value := range decoded {
				if str, ok := value.(string); ok {
					credentialIDsByDevice[key] = str
				}
			}
		}
	}

	devices := []forwardClassicDevice{}
	for _, device := range devicesResp {
		name := strings.TrimSpace(device.Name)
		host := strings.TrimSpace(device.MgmtIP)
		if name == "" || host == "" {
			continue
		}
		port := device.Port
		if port <= 0 {
			port = 22
		}
		cliID := defaultCliCredentialID
		if cliID == "" && deviceUsername != "" && devicePassword != "" {
			cred, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialName, deviceUsername, devicePassword)
			if err != nil {
				if strings.Contains(err.Error(), "No collector configured") {
					log.Printf("forward cli credential skipped: %v", err)
				} else {
					return err
				}
			} else {
				cliID = cred.ID
				credentialIDsByDevice[name] = cliID
			}
		} else if cliID == "" {
			cred, ok := labppCredentialForDevice(device.Type)
			if !ok {
				cred, ok = netlabCredentialForDevice("", "")
			}
			if ok {
				created, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialName, cred.Username, cred.Password)
				if err != nil {
					if strings.Contains(err.Error(), "No collector configured") {
						log.Printf("forward cli credential skipped: %v", err)
					} else {
						return err
					}
				} else {
					cliID = created.ID
					credentialIDsByDevice[name] = cliID
				}
			}
		}

		devices = append(devices, forwardClassicDevice{
			Name:                     name,
			Host:                     host,
			Port:                     port,
			CliCredentialID:          cliID,
			SnmpCredentialID:         snmpCredentialID,
			JumpServerID:             jumpServerID,
			CollectBgpAdvertisements: true,
			BgpTableType:             "BOTH",
			BgpPeerType:              "BOTH",
			EnableSnmpCollection:     true,
		})
	}

	if err := forwardPutClassicDevices(ctx, client, networkID, devices); err != nil {
		if isForwardJumpServerMissing(err) && jumpServerID != "" {
			cfgAny[forwardJumpServerIDKey] = ""
			refreshed, refreshErr := s.ensureForwardNetworkForDeployment(ctx, pc, dep)
			if refreshErr != nil {
				return refreshErr
			}
			cfgAny = refreshed
			jumpServerID = getString(forwardJumpServerIDKey)
			for i := range devices {
				devices[i].JumpServerID = jumpServerID
			}
			if retryErr := forwardPutClassicDevices(ctx, client, networkID, devices); retryErr != nil {
				return retryErr
			}
		} else {
			if s != nil && s.db != nil && taskID > 0 {
				_ = appendTaskEvent(context.Background(), s.db, taskID, "forward.devices.upload.failed", map[string]any{
					"source":    "labpp",
					"networkId": networkID,
					"error":     strings.TrimSpace(err.Error()),
				})
			}
			return err
		}
	}
	if startCollection {
		if err := forwardStartCollection(ctx, client, networkID); err != nil {
			log.Printf("forward start collection: %v", err)
		}
	}
	if s != nil && s.db != nil && taskID > 0 {
		_ = appendTaskEvent(context.Background(), s.db, taskID, "forward.devices.upload.succeeded", map[string]any{
			"source":      "labpp",
			"networkId":   networkID,
			"deviceCount": len(devices),
		})
	}
	cfgAny[forwardCliCredentialMap] = credentialIDsByDevice
	if err := s.updateDeploymentConfig(ctx, pc.workspace.ID, dep.ID, cfgAny); err != nil {
		return err
	}
	return nil
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
