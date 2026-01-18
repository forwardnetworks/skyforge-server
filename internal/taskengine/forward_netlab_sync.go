package taskengine

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"encore.app/internal/taskstore"
)

const (
	forwardNetworkIDKey        = "forwardNetworkId"
	forwardNetworkNameKey      = "forwardNetworkName"
	forwardCliCredentialIDKey  = "forwardCliCredentialId"
	forwardCliCredentialMap    = "forwardCliCredentialIdsByDevice"
	forwardSnmpCredentialIDKey = "forwardSnmpCredentialId"
	forwardJumpServerIDKey     = "forwardJumpServerId"
)

const defaultForwardBaseURL = "https://fwd.app"

const (
	defaultNetlabDeviceUsername = "admin"
	defaultNetlabDevicePassword = "admin"
)

type forwardCredentials struct {
	BaseURL        string
	Username       string
	Password       string
	CollectorUser  string
	DeviceUsername string
	DevicePassword string
	JumpHost       string
	JumpUsername   string
	JumpPrivateKey string
	JumpCert       string
}

func getenv(key string, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func getenvBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}

func (e *Engine) forwardDeviceTypes(ctx context.Context) map[string]string {
	out := map[string]string{
		"linux": "linux_os_ssh",
		"eos":   "arista_eos_ssh",
	}
	if e == nil || e.db == nil {
		return out
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := e.db.QueryContext(ctxReq, `SELECT device_key, forward_type FROM sf_forward_device_types`)
	if err != nil {
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
	image = strings.TrimPrefix(image, "ghcr.io/forwardnetworks/")
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
		return netlabDeviceCredential{Username: defaultNetlabDeviceUsername, Password: defaultNetlabDevicePassword}, true
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
			Provider: cols[2],
			Status:   cols[3],
		}
		if len(cols) >= 5 {
			row.Image = cols[4]
		}
		if len(cols) >= 6 {
			row.MgmtIPv4 = cols[5]
		}
		rows = append(rows, row)
	}
	return rows
}

func (e *Engine) forwardConfigForWorkspace(ctx context.Context, workspaceID string) (*forwardCredentials, error) {
	if e == nil || e.db == nil || e.box == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := e.getWorkspaceForwardCredentials(ctxReq, workspaceID)
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

func (e *Engine) getWorkspaceForwardCredentials(ctx context.Context, workspaceID string) (*forwardCredentials, error) {
	if e == nil || e.db == nil || e.box == nil {
		return nil, fmt.Errorf("db unavailable")
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return nil, fmt.Errorf("workspace id is required")
	}
	var baseURL, username, password sql.NullString
	var collectorUser sql.NullString
	var deviceUser, devicePass sql.NullString
	var jumpHost, jumpUser, jumpKey, jumpCert sql.NullString
	err := e.db.QueryRowContext(ctx, `SELECT base_url, username, password,
  COALESCE(collector_username, ''),
  COALESCE(device_username, ''), COALESCE(device_password, ''),
  COALESCE(jump_host, ''), COALESCE(jump_username, ''), COALESCE(jump_private_key, ''), COALESCE(jump_cert, '')
FROM sf_workspace_forward_credentials WHERE workspace_id=$1`, workspaceID).Scan(
		&baseURL,
		&username,
		&password,
		&collectorUser,
		&deviceUser,
		&devicePass,
		&jumpHost,
		&jumpUser,
		&jumpKey,
		&jumpCert,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	dec := func(v sql.NullString) (string, error) {
		return e.box.decrypt(v.String)
	}
	baseURLValue, err := dec(baseURL)
	if err != nil {
		return nil, err
	}
	usernameValue, err := dec(username)
	if err != nil {
		return nil, err
	}
	passwordValue, err := dec(password)
	if err != nil {
		return nil, err
	}
	collectorUserValue, _ := dec(collectorUser)
	deviceUserValue, _ := dec(deviceUser)
	devicePassValue, _ := dec(devicePass)
	jumpHostValue, _ := dec(jumpHost)
	jumpUserValue, _ := dec(jumpUser)
	jumpKeyValue, _ := dec(jumpKey)
	jumpCertValue, _ := dec(jumpCert)

	return &forwardCredentials{
		BaseURL:        strings.TrimSpace(baseURLValue),
		Username:       strings.TrimSpace(usernameValue),
		Password:       strings.TrimSpace(passwordValue),
		CollectorUser:  strings.TrimSpace(collectorUserValue),
		DeviceUsername: strings.TrimSpace(deviceUserValue),
		DevicePassword: strings.TrimSpace(devicePassValue),
		JumpHost:       strings.TrimSpace(jumpHostValue),
		JumpUsername:   strings.TrimSpace(jumpUserValue),
		JumpPrivateKey: strings.TrimSpace(jumpKeyValue),
		JumpCert:       strings.TrimSpace(jumpCertValue),
	}, nil
}

func (e *Engine) updateDeploymentConfig(ctx context.Context, workspaceID, deploymentID string, cfgAny map[string]any) error {
	if e == nil || e.db == nil {
		return fmt.Errorf("database unavailable")
	}
	cfg, err := toJSONMap(cfgAny)
	if err != nil {
		return err
	}
	cfgBytes, _ := json.Marshal(cfg)
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err = e.db.ExecContext(ctxReq, `UPDATE sf_deployments SET
  config=$1,
  updated_at=now()
WHERE workspace_id=$2 AND id=$3`, cfgBytes, workspaceID, deploymentID)
	return err
}

func (e *Engine) ensureForwardNetworkForDeployment(ctx context.Context, pc *workspaceContext, dep *WorkspaceDeployment) (map[string]any, error) {
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	forwardCfg, err := e.forwardConfigForWorkspace(ctx, pc.workspace.ID)
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
	credentialName := networkName
	networkID := getString(forwardNetworkIDKey)
	changed := false
	if networkID == "" {
		name := fmt.Sprintf("%s-%s", dep.Name, time.Now().UTC().Format("20060102-1504"))
		network, err := forwardCreateNetworkWithRetry(ctx, client, sanitizeForwardName(name))
		if err != nil {
			return cfgAny, err
		}
		networkID = network.ID
		cfgAny[forwardNetworkIDKey] = networkID
		cfgAny[forwardNetworkNameKey] = name
		credentialName = name
		changed = true
	}

	collectorUser := strings.TrimSpace(forwardCfg.CollectorUser)
	if collectorUser != "" {
		status, err := forwardGetCollectorStatus(ctx, client, networkID)
		if err != nil {
			return cfgAny, err
		}
		if status != nil && !status.IsSet {
			if err := forwardSetCollector(ctx, client, networkID, collectorUser); err != nil {
				return cfgAny, err
			}
		}
	}

	snmpCredentialID := getString(forwardSnmpCredentialIDKey)
	if snmpCredentialID == "" && getenvBool("SKYFORGE_FORWARD_SNMP_CREATE_PLACEHOLDER", true) {
		community := strings.TrimSpace(getenv("SKYFORGE_FORWARD_SNMP_COMMUNITY", "public"))
		if community != "" {
			cred, err := forwardCreateSnmpCredential(ctx, client, networkID, credentialName, community)
			if err != nil {
				log.Printf("forward snmp credential skipped: %v", err)
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
	if strings.TrimSpace(pc.claims.Username) != "" && (jumpKey != "" || jumpCert != "") {
		jumpUser = strings.TrimSpace(pc.claims.Username)
	}
	if jumpUser == "" {
		jumpUser = strings.TrimSpace(pc.claims.Username)
	}
	if jumpServerID == "" && jumpHost != "" && jumpKey != "" && jumpUser != "" {
		jump, err := forwardCreateJumpServer(ctx, client, networkID, jumpHost, jumpUser, jumpKey, jumpCert)
		if err != nil {
			log.Printf("forward jump server skipped: %v", err)
		} else {
			jumpServerID = jump.ID
			cfgAny[forwardJumpServerIDKey] = jumpServerID
			changed = true
		}
	}

	if changed {
		if err := e.updateDeploymentConfig(ctx, pc.workspace.ID, dep.ID, cfgAny); err != nil {
			return cfgAny, err
		}
	}
	return cfgAny, nil
}

func (e *Engine) syncForwardNetlabDevices(ctx context.Context, taskID int, pc *workspaceContext, dep *WorkspaceDeployment, logText string) (int, error) {
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	cfgAny, err := e.ensureForwardNetworkForDeployment(ctx, pc, dep)
	if err != nil {
		return 0, err
	}
	forwardCfg, err := e.forwardConfigForWorkspace(ctx, pc.workspace.ID)
	if err != nil || forwardCfg == nil {
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
		return 0, nil
	}

	deploymentName := strings.TrimSpace(dep.Name)
	credentialBase := deploymentName
	if credentialBase == "" {
		credentialBase = strings.TrimSpace(getString(forwardNetworkNameKey))
	}
	jumpServerID := getString(forwardJumpServerIDKey)
	snmpCredentialID := getString(forwardSnmpCredentialIDKey)
	forwardTypes := e.forwardDeviceTypes(ctx)

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
		name := strings.TrimSpace(row.Node)
		deviceKey := strings.ToLower(strings.TrimSpace(row.Device))

		cred, ok := netlabCredentialForDevice(row.Device, row.Image)
		cliCredentialID := ""
		if deviceKey != "" {
			cliCredentialID = credentialIDsByDevice[deviceKey]
		}
		if cliCredentialID == "" && ok && strings.TrimSpace(cred.Username) != "" && strings.TrimSpace(cred.Password) != "" {
			created, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialNameForDevice(deviceKey), cred.Username, cred.Password)
			if err == nil {
				cliCredentialID = created.ID
				if deviceKey != "" {
					credentialIDsByDevice[deviceKey] = cliCredentialID
					changed = true
				}
			}
		}

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
		forwardType := ""
		if deviceKey != "" {
			forwardType = forwardTypes[deviceKey]
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
		return 0, nil
	}
	if err := forwardPutClassicDevices(ctx, client, networkID, devices); err != nil {
		if isForwardJumpServerMissing(err) && jumpServerID != "" {
			cfgAny[forwardJumpServerIDKey] = ""
			refreshed, refreshErr := e.ensureForwardNetworkForDeployment(ctx, pc, dep)
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
			return 0, err
		}
	}
	_ = forwardStartCollection(ctx, client, networkID)
	if changed {
		cfgAny[forwardCliCredentialMap] = credentialIDsByDevice
		if err := e.updateDeploymentConfig(ctx, pc.workspace.ID, dep.ID, cfgAny); err != nil {
			return 0, err
		}
	}
	if taskID > 0 {
		_ = taskstore.AppendTaskEvent(context.Background(), e.db, taskID, "forward.devices.upload.succeeded", map[string]any{
			"source":      "netlab",
			"networkId":   networkID,
			"deviceCount": len(devices),
		})
	}
	return len(devices), nil
}

func (e *Engine) maybeSyncForwardNetlabAfterRun(ctx context.Context, spec netlabRunSpec, log Logger, apiURL string) error {
	if e == nil {
		return fmt.Errorf("engine unavailable")
	}
	if log == nil {
		log = noopLogger{}
	}
	if spec.WorkspaceCtx == nil {
		return fmt.Errorf("workspace context unavailable")
	}
	if strings.TrimSpace(spec.DeploymentID) == "" {
		return fmt.Errorf("deployment id unavailable")
	}

	dep, err := e.loadDeployment(ctx, spec.WorkspaceCtx.workspace.ID, strings.TrimSpace(spec.DeploymentID))
	if err != nil {
		return err
	}
	if dep == nil || dep.Type != "netlab" {
		return fmt.Errorf("netlab deployment not found")
	}

	ctxReq, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	insecure := spec.Server.APIInsecure
	auth, err := e.netlabAPIAuthForUser(spec.Username, spec.Server)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"action":  "status",
		"workdir": strings.TrimSpace(spec.WorkspaceDir),
	}
	if strings.TrimSpace(spec.TopologyPath) != "" {
		payload["topologyPath"] = strings.TrimSpace(spec.TopologyPath)
	}

	postResp, body, err := netlabAPIDo(ctxReq, strings.TrimRight(apiURL, "/")+"/jobs", payload, insecure, auth)
	if err != nil {
		return fmt.Errorf("failed to reach netlab API: %w", err)
	}
	if postResp.StatusCode < 200 || postResp.StatusCode >= 300 {
		return fmt.Errorf("netlab API rejected status request: %s", strings.TrimSpace(string(body)))
	}
	var statusJob netlabAPIJob
	if err := json.Unmarshal(body, &statusJob); err != nil || strings.TrimSpace(statusJob.ID) == "" {
		return fmt.Errorf("netlab status returned invalid response")
	}

	statusLog := ""
	deadline := time.Now().Add(20 * time.Second)
	for {
		if time.Now().After(deadline) {
			break
		}
		getResp, getBody, err := netlabAPIGet(ctxReq, fmt.Sprintf("%s/jobs/%s", strings.TrimRight(apiURL, "/"), statusJob.ID), insecure, auth)
		if err == nil && getResp != nil && getResp.StatusCode >= 200 && getResp.StatusCode < 300 {
			_ = json.Unmarshal(getBody, &statusJob)
		}
		logResp, logBody, err := netlabAPIGet(ctxReq, fmt.Sprintf("%s/jobs/%s/log", strings.TrimRight(apiURL, "/"), statusJob.ID), insecure, auth)
		if err == nil && logResp != nil && logResp.StatusCode >= 200 && logResp.StatusCode < 300 {
			var lr netlabAPILog
			if err := json.Unmarshal(logBody, &lr); err == nil {
				statusLog = lr.Log
			}
		}
		state := strings.ToLower(strings.TrimSpace(statusJob.State))
		if state == "" {
			state = strings.ToLower(strings.TrimSpace(derefString(statusJob.Status)))
		}
		if state == "success" || state == "failed" || state == "canceled" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if strings.TrimSpace(statusLog) == "" {
		return fmt.Errorf("netlab status output unavailable")
	}

	_, err = e.syncForwardNetlabDevices(ctx, spec.TaskID, spec.WorkspaceCtx, dep, statusLog)
	if err != nil {
		log.Infof("forward netlab sync skipped: %v", err)
		return err
	}
	return nil
}
