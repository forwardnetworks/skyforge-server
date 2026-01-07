package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "embed"
)

const (
	forwardNetworkIDKey       = "forwardNetworkId"
	forwardNetworkNameKey     = "forwardNetworkName"
	forwardCliCredentialIDKey = "forwardCliCredentialId"
	forwardCliCredentialMap   = "forwardCliCredentialIdsByDevice"
	forwardJumpServerIDKey    = "forwardJumpServerId"
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
		if set.Device != "" && strings.EqualFold(set.Device, device) && len(set.Credentials) > 0 {
			if isValid(set.Credentials[0]) {
				return set.Credentials[0], true
			}
			return netlabDeviceCredential{}, false
		}
	}
	for _, set := range netlabDefaults.Sets {
		if set.ImagePrefix != "" && strings.HasPrefix(image, strings.ToLower(set.ImagePrefix)) && len(set.Credentials) > 0 {
			if isValid(set.Credentials[0]) {
				return set.Credentials[0], true
			}
			return netlabDeviceCredential{}, false
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
	if cliCredentialID == "" && deviceUsername != "" && devicePassword != "" {
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

func (s *Service) syncForwardNetlabDevices(ctx context.Context, pc *workspaceContext, dep *WorkspaceDeployment, logText string) error {
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
	credentialName := strings.TrimSpace(getString(forwardNetworkNameKey))
	jumpServerID := getString(forwardJumpServerIDKey)
	defaultCliCredentialID := getString(forwardCliCredentialIDKey)
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
		if cliCredentialID == "" {
			cliCredentialID = defaultCliCredentialID
		}
		if cliCredentialID == "" && strings.TrimSpace(cred.Username) != "" {
			created, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialName, cred.Username, cred.Password)
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
		devices = append(devices, forwardClassicDevice{
			Name:            name,
			Host:            mgmt,
			Port:            22,
			CliCredentialID: cliCredentialID,
			JumpServerID:    jumpServerID,
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
	if changed {
		cfgAny[forwardCliCredentialMap] = credentialIDsByDevice
		if err := s.updateDeploymentConfig(ctx, pc.workspace.ID, dep.ID, cfgAny); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) syncForwardLabppDevices(ctx context.Context, pc *workspaceContext, deploymentID, apiURL, jobID string, insecure bool) error {
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

	forwardCfg, err := s.forwardConfigForWorkspace(ctx, pc.workspace.ID)
	if err != nil || forwardCfg == nil {
		return err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return err
	}

	deviceUsername := strings.TrimSpace(forwardCfg.DeviceUsername)
	devicePassword := strings.TrimSpace(forwardCfg.DevicePassword)

	resp, body, err := labppAPIGet(ctx, fmt.Sprintf("%s/jobs/%s/devices", strings.TrimRight(apiURL, "/"), jobID), insecure)
	if err != nil {
		return err
	}
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("labpp devices request failed: %s", strings.TrimSpace(string(body)))
	}
	var devicesResp labppDevicesResponse
	if err := json.Unmarshal(body, &devicesResp); err != nil {
		return fmt.Errorf("labpp devices response invalid: %w", err)
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
	credentialName := strings.TrimSpace(getString(forwardNetworkNameKey))
	jumpServerID := getString(forwardJumpServerIDKey)
	defaultCliCredentialID := getString(forwardCliCredentialIDKey)

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
	for _, device := range devicesResp.Devices {
		name := strings.TrimSpace(device.Name)
		host := strings.TrimSpace(device.MgmtIP)
		if name == "" || host == "" {
			continue
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
			Name:            name,
			Host:            host,
			CliCredentialID: cliID,
			JumpServerID:    jumpServerID,
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
			return err
		}
	}
	if err := forwardStartCollection(ctx, client, networkID); err != nil {
		log.Printf("forward start collection: %v", err)
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
