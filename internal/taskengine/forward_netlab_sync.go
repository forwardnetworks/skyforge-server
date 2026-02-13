package taskengine

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"encore.app/internal/taskstore"

	"github.com/google/uuid"
)

const (
	forwardNetworkIDKey        = "forwardNetworkId"
	forwardNetworkNameKey      = "forwardNetworkName"
	forwardNetworkRefKey       = "forwardNetworkRef"
	forwardCliCredentialIDKey  = "forwardCliCredentialId"
	forwardCliCredentialMap    = "forwardCliCredentialIdsByDevice"
	forwardCliCredentialFPMap  = "forwardCliCredentialFingerprintsByDevice"
	forwardSnmpCredentialIDKey = "forwardSnmpCredentialId"
	forwardJumpServerIDKey     = "forwardJumpServerId"
	forwardEnabledKey          = "forwardEnabled"
	forwardCollectorUserKey    = "forwardCollectorUsername"
	forwardCollectorIDKey      = "forwardCollectorId"
)

const defaultForwardBaseURL = "https://fwd.app"

type forwardCredentials struct {
	BaseURL        string
	SkipTLSVerify  bool
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

func (e *Engine) forwardDeviceTypes(ctx context.Context) map[string]string {
	out := map[string]string{
		"linux": "linux_os_ssh",
		"eos":   "arista_eos_ssh",
		// Cisco IOL/IOS (vrnetlab) devices should be treated as classic IOS SSH.
		// Do not rely on Forward auto-detection here.
		"ios": "cisco_ios_ssh",
		// Some netlab outputs use IOS-XE-ish labels even when the device is IOL.
		"ios_xe":   "cisco_ios_ssh",
		"ios-xe":   "cisco_ios_ssh",
		"iosv":     "cisco_ios_ssh",
		"iosvl2":   "cisco_ios_ssh",
		"csr":      "cisco_ios_xe_ssh",
		"cat8000v": "cisco_ios_xe_ssh",
		"asav":     "cisco_asa_ssh",
		"fortios":  "fortinet_ssh",
		"nxos":     "cisco_nxos_ssh",
		"iosxr":    "cisco_ios_xr_ssh",
		// Juniper routers/switches (including vMX, vJunos-switch, vJunos-router).
		"vjunos-switch": "juniper_junos_ssh",
		"vjunos-router": "juniper_junos_ssh",
		"vmx":           "juniper_junos_ssh",
		"junos":         "juniper_junos_ssh",
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
	return netlabDeviceCredential{}, false
}

func forwardCredentialFingerprint(username, password string) string {
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)
	if username == "" || password == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(username + ":" + password))
	return hex.EncodeToString(sum[:])
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

func (e *Engine) forwardConfigForUser(ctx context.Context, username string) (*forwardCredentials, error) {
	return e.forwardConfigForUserCollector(ctx, username, "")
}

func (e *Engine) forwardConfigForUserCollector(ctx context.Context, username string, collectorConfigID string) (*forwardCredentials, error) {
	if e == nil || e.db == nil || e.box == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := e.getUserForwardCredentials(ctxReq, username, collectorConfigID)
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

func (e *Engine) getUserForwardCredentials(ctx context.Context, username string, collectorConfigID string) (*forwardCredentials, error) {
	if e == nil || e.db == nil || e.box == nil {
		return nil, fmt.Errorf("db unavailable")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	collectorConfigID = strings.TrimSpace(collectorConfigID)
	type row struct {
		credID        sql.NullString
		baseURL       sql.NullString
		fwdUser       sql.NullString
		fwdPass       sql.NullString
		collectorUser sql.NullString
		authKey       sql.NullString
		skipTLSVerify sql.NullBool
	}
	var r row
	if collectorConfigID != "" {
		err := e.db.QueryRowContext(ctx, `SELECT COALESCE(credential_id,''),
  base_url, forward_username, forward_password,
  COALESCE(collector_username, ''), COALESCE(authorization_key, ''),
  COALESCE(skip_tls_verify, false)
FROM sf_user_forward_collectors WHERE username=$1 AND id=$2`, username, collectorConfigID).Scan(
			&r.credID, &r.baseURL, &r.fwdUser, &r.fwdPass, &r.collectorUser, &r.authKey, &r.skipTLSVerify,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}
			if isMissingDBRelation(err) {
				return nil, nil
			}
			return nil, err
		}
	} else {
		err := e.db.QueryRowContext(ctx, `SELECT COALESCE(credential_id,''),
  base_url, forward_username, forward_password,
  COALESCE(collector_username, ''), COALESCE(authorization_key, ''),
  COALESCE(skip_tls_verify, false)
FROM sf_user_forward_collectors WHERE username=$1
ORDER BY is_default DESC, updated_at DESC
LIMIT 1`, username).Scan(
			&r.credID, &r.baseURL, &r.fwdUser, &r.fwdPass, &r.collectorUser, &r.authKey, &r.skipTLSVerify,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || isMissingDBRelation(err) {
				return nil, nil
			}
			return nil, err
		}
	}

	credID := strings.TrimSpace(r.credID.String)
	if credID != "" {
		// Preferred: shared credentials table (ciphertext stored as enc:...).
		var baseURLEnc sql.NullString
		var userEnc, passEnc sql.NullString
		var collectorUserEnc, authKeyEnc sql.NullString
		var deviceUserEnc, devicePassEnc sql.NullString
		var jumpHostEnc, jumpUserEnc, jumpKeyEnc, jumpCertEnc sql.NullString
		var skipTLSVerify sql.NullBool
		err := e.db.QueryRowContext(ctx, `
SELECT
  COALESCE(base_url_enc, ''), COALESCE(skip_tls_verify, false),
  COALESCE(forward_username_enc, ''), COALESCE(forward_password_enc, ''),
  COALESCE(collector_username_enc, ''), COALESCE(authorization_key_enc, ''),
  COALESCE(device_username_enc, ''), COALESCE(device_password_enc, ''),
  COALESCE(jump_host_enc, ''), COALESCE(jump_username_enc, ''), COALESCE(jump_private_key_enc, ''), COALESCE(jump_cert_enc, '')
FROM sf_credentials
WHERE id=$1 AND provider='forward' AND owner_username=$2 AND workspace_id IS NULL
`, credID, username).Scan(
			&baseURLEnc, &skipTLSVerify,
			&userEnc, &passEnc,
			&collectorUserEnc, &authKeyEnc,
			&deviceUserEnc, &devicePassEnc,
			&jumpHostEnc, &jumpUserEnc, &jumpKeyEnc, &jumpCertEnc,
		)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}
			return nil, err
		}
		dec := func(v sql.NullString) (string, error) { return e.box.decrypt(v.String) }
		baseURLValue, err := dec(baseURLEnc)
		if err != nil {
			return nil, fmt.Errorf("forward credentials could not be decrypted; re-save Forward settings")
		}
		usernameValue, err := dec(userEnc)
		if err != nil {
			return nil, fmt.Errorf("forward credentials could not be decrypted; re-save Forward settings")
		}
		passwordValue, err := dec(passEnc)
		if err != nil {
			return nil, fmt.Errorf("forward credentials could not be decrypted; re-save Forward settings")
		}
		collectorUserValue, _ := dec(collectorUserEnc)
		authKeyValue, _ := dec(authKeyEnc)
		if strings.TrimSpace(collectorUserValue) == "" && strings.TrimSpace(authKeyValue) != "" {
			if before, _, ok := strings.Cut(strings.TrimSpace(authKeyValue), ":"); ok {
				collectorUserValue = before
			}
		}
		deviceUserValue, _ := dec(deviceUserEnc)
		devicePassValue, _ := dec(devicePassEnc)
		jumpHostValue, _ := dec(jumpHostEnc)
		jumpUserValue, _ := dec(jumpUserEnc)
		jumpKeyValue, _ := dec(jumpKeyEnc)
		jumpCertValue, _ := dec(jumpCertEnc)

		return &forwardCredentials{
			BaseURL:        strings.TrimSpace(baseURLValue),
			SkipTLSVerify:  skipTLSVerify.Valid && skipTLSVerify.Bool,
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

	dec := func(v sql.NullString) (string, error) {
		return e.box.decrypt(v.String)
	}
	baseURLValue, err := dec(r.baseURL)
	if err != nil {
		return nil, fmt.Errorf("forward credentials could not be decrypted; re-save Forward settings")
	}
	usernameValue, err := dec(r.fwdUser)
	if err != nil {
		return nil, fmt.Errorf("forward credentials could not be decrypted; re-save Forward settings")
	}
	passwordValue, err := dec(r.fwdPass)
	if err != nil {
		return nil, fmt.Errorf("forward credentials could not be decrypted; re-save Forward settings")
	}
	collectorUserValue, _ := dec(r.collectorUser)
	authKeyValue, _ := dec(r.authKey)
	if strings.TrimSpace(collectorUserValue) == "" && strings.TrimSpace(authKeyValue) != "" {
		if before, _, ok := strings.Cut(strings.TrimSpace(authKeyValue), ":"); ok {
			collectorUserValue = before
		}
	}

	return &forwardCredentials{
		BaseURL:       strings.TrimSpace(baseURLValue),
		SkipTLSVerify: r.skipTLSVerify.Valid && r.skipTLSVerify.Bool,
		Username:      strings.TrimSpace(usernameValue),
		Password:      strings.TrimSpace(passwordValue),
		CollectorUser: strings.TrimSpace(collectorUserValue),
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
	enabled := false
	if raw, ok := cfgAny[forwardEnabledKey]; ok {
		if b, ok := raw.(bool); ok {
			enabled = b
		} else if s, ok := raw.(string); ok {
			s = strings.TrimSpace(s)
			enabled = strings.EqualFold(s, "true") || s == "1" || strings.EqualFold(s, "yes")
		} else if raw != nil {
			s := strings.TrimSpace(fmt.Sprintf("%v", raw))
			enabled = strings.EqualFold(s, "true") || s == "1" || strings.EqualFold(s, "yes")
		}
	}
	if !enabled {
		return cfgAny, nil
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

	collectorConfigID := strings.TrimSpace(getString(forwardCollectorIDKey))
	forwardCfg, err := e.forwardConfigForUserCollector(ctx, pc.claims.Username, collectorConfigID)
	if err != nil || forwardCfg == nil {
		return cfgAny, err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return cfgAny, err
	}

	networkID := getString(forwardNetworkIDKey)
	changed := false
	if networkID == "" {
		// Prefer a stable, human-friendly name: "<deployment>-<user>".
		// Only add a timestamp suffix on collision.
		baseName := sanitizeForwardName(fmt.Sprintf("%s-%s", dep.Name, strings.TrimSpace(pc.claims.Username)))
		network, err := forwardCreateNetworkWithRetry(ctx, client, baseName)
		if err != nil {
			return cfgAny, err
		}
		networkID = network.ID
		cfgAny[forwardNetworkIDKey] = networkID
		cfgAny[forwardNetworkNameKey] = strings.TrimSpace(network.Name)
		changed = true
	}

	// Ensure the network is registered in Skyforge's saved networks table so capacity/assurance
	// endpoints that use :networkRef have something to reference.
	if e != nil && e.db != nil {
		actor := strings.ToLower(strings.TrimSpace(pc.claims.Username))
		name := strings.TrimSpace(getString(forwardNetworkNameKey))
		if name == "" {
			name = strings.TrimSpace(dep.Name)
		}
		if name == "" {
			name = networkID
		}
		desc := ""
		if strings.TrimSpace(dep.Name) != "" {
			desc = strings.TrimSpace(fmt.Sprintf("Deployment: %s", strings.TrimSpace(dep.Name)))
		}

		ctxReq, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		// Best-effort ensure user exists for FK on created_by.
		if actor != "" {
			_, _ = e.db.ExecContext(ctxReq, `INSERT INTO sf_users(username) VALUES($1) ON CONFLICT DO NOTHING`, actor)
		}

		var networkRef string
		err := e.db.QueryRowContext(ctxReq, `
INSERT INTO sf_policy_report_forward_networks (
  id, workspace_id, owner_username, forward_network_id, name, description, collector_config_id, created_by
)
VALUES ($1,NULL,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7)
ON CONFLICT (owner_username, forward_network_id) WHERE owner_username IS NOT NULL
DO UPDATE SET
  name = EXCLUDED.name,
  description = EXCLUDED.description,
  collector_config_id = EXCLUDED.collector_config_id,
  updated_at = now()
WHERE sf_policy_report_forward_networks.name IS DISTINCT FROM EXCLUDED.name
   OR sf_policy_report_forward_networks.description IS DISTINCT FROM EXCLUDED.description
   OR sf_policy_report_forward_networks.collector_config_id IS DISTINCT FROM EXCLUDED.collector_config_id
RETURNING id::text
`, uuid.New().String(), actor, networkID, name, desc, collectorConfigID, actor).Scan(&networkRef)
		if err == nil {
			networkRef = strings.TrimSpace(networkRef)
			if networkRef != "" && strings.TrimSpace(getString(forwardNetworkRefKey)) != networkRef {
				cfgAny[forwardNetworkRefKey] = networkRef
				changed = true
			}
		}
	}

	collectorUser := strings.TrimSpace(getString(forwardCollectorUserKey))
	if collectorUser == "" {
		collectorUser = strings.TrimSpace(forwardCfg.CollectorUser)
	}
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
	if snmpCredentialID == "" && e.cfg.Forward.SNMPPlaceholderEnabled {
		snmpName := sanitizeForwardName(fmt.Sprintf("%s-%s-snmpv3", dep.Name, strings.TrimSpace(pc.claims.Username)))
		if snmpName == "" {
			snmpName = forwardSNMPv3DefaultName
		}
		cred, err := forwardCreateSnmpCredential(ctx, client, networkID, snmpName)
		if err != nil {
			log.Printf("forward snmp credential skipped: %v", err)
		} else {
			snmpCredentialID = cred.ID
			cfgAny[forwardSnmpCredentialIDKey] = snmpCredentialID
			changed = true
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
	// Only attach a jump server for BYOS-style deployments. In-cluster deployments
	// (netlab-c9s/clabernetes) should be reached directly by the in-cluster collector.
	allowJump := dep != nil && strings.ToLower(strings.TrimSpace(dep.Type)) != "netlab-c9s" && strings.ToLower(strings.TrimSpace(dep.Type)) != "clabernetes"
	if allowJump && jumpServerID == "" && jumpHost != "" && jumpKey != "" && jumpUser != "" {
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

func (e *Engine) startForwardCollectionForDeployment(ctx context.Context, taskID int, pc *workspaceContext, dep *WorkspaceDeployment) error {
	if e == nil || pc == nil || dep == nil {
		return nil
	}
	cfgAny, err := e.ensureForwardNetworkForDeployment(ctx, pc, dep)
	if err != nil || cfgAny == nil {
		return err
	}
	rawID, ok := cfgAny[forwardNetworkIDKey]
	if !ok || rawID == nil {
		return nil
	}
	networkID := strings.TrimSpace(fmt.Sprintf("%v", rawID))
	if networkID == "" {
		return nil
	}
	collectorConfigID := strings.TrimSpace(fmt.Sprintf("%v", cfgAny[forwardCollectorIDKey]))
	forwardCfg, err := e.forwardConfigForUserCollector(ctx, pc.claims.Username, collectorConfigID)
	if err != nil || forwardCfg == nil {
		return err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return err
	}
	if err := forwardStartCollection(ctx, client, networkID); err != nil {
		return err
	}
	if taskID > 0 {
		_ = taskstore.AppendTaskEvent(context.Background(), e.db, taskID, "forward.collection.started", map[string]any{
			"networkId": networkID,
		})
	}
	return nil
}

func (e *Engine) startForwardConnectivityTestsForDeployment(ctx context.Context, taskID int, pc *workspaceContext, dep *WorkspaceDeployment, graph *TopologyGraph) error {
	if e == nil || pc == nil || dep == nil || graph == nil {
		return nil
	}
	cfgAny, err := e.ensureForwardNetworkForDeployment(ctx, pc, dep)
	if err != nil || cfgAny == nil {
		return err
	}
	rawID, ok := cfgAny[forwardNetworkIDKey]
	if !ok || rawID == nil {
		return nil
	}
	networkID := strings.TrimSpace(fmt.Sprintf("%v", rawID))
	if networkID == "" {
		return nil
	}

	// Start connectivity tests for:
	// - classic devices (NOS nodes)
	// - endpoints (Linux nodes)
	classicNames := make([]string, 0, len(graph.Nodes))
	endpointNames := make([]string, 0, len(graph.Nodes))
	for _, node := range graph.Nodes {
		name := strings.TrimSpace(node.Label)
		if name == "" {
			name = strings.TrimSpace(node.ID)
		}
		if name == "" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(node.Kind), "linux") {
			endpointNames = append(endpointNames, name)
			continue
		}
		classicNames = append(classicNames, name)
	}
	if len(classicNames) == 0 && len(endpointNames) == 0 {
		return nil
	}

	collectorConfigID := strings.TrimSpace(fmt.Sprintf("%v", cfgAny[forwardCollectorIDKey]))
	forwardCfg, err := e.forwardConfigForUserCollector(ctx, pc.claims.Username, collectorConfigID)
	if err != nil || forwardCfg == nil {
		return err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return err
	}

	if len(classicNames) > 0 {
		if err := forwardBulkStartConnectivityTests(ctx, client, networkID, classicNames); err != nil {
			return err
		}
	}
	if len(endpointNames) > 0 {
		// Forward supports endpoint connectivity tests via:
		//   POST /api/networks/{id}/connectivityTests/bulkStart?type=endpoint
		if err := forwardBulkStartConnectivityTestsTyped(ctx, client, networkID, endpointNames, "endpoint"); err != nil {
			return err
		}
	}
	if taskID > 0 {
		_ = taskstore.AppendTaskEvent(context.Background(), e.db, taskID, "forward.connectivity.started", map[string]any{
			"networkId":     networkID,
			"deviceCount":   len(classicNames),
			"endpointCount": len(endpointNames),
		})
	}
	return nil
}

func sanitizeCredentialComponent(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.ToLower(raw)
	var b strings.Builder
	b.Grow(len(raw))
	for _, ch := range raw {
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteRune(ch)
		case ch >= '0' && ch <= '9':
			b.WriteRune(ch)
		case ch == '-' || ch == '_' || ch == '.':
			b.WriteRune(ch)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return ""
	}
	// Keep within Forward credential name constraints.
	if len(out) > 48 {
		out = out[:48]
		out = strings.TrimRight(out, "-")
	}
	return out
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

	collectorConfigID := getString(forwardCollectorIDKey)
	forwardCfg, err := e.forwardConfigForUserCollector(ctx, pc.claims.Username, collectorConfigID)
	if err != nil || forwardCfg == nil {
		return 0, err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return 0, err
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
	// Never use a jump server for in-cluster deployments.
	if dep != nil {
		t := strings.ToLower(strings.TrimSpace(dep.Type))
		if t == "netlab-c9s" || t == "clabernetes" {
			jumpServerID = ""
		}
	}
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
	credentialFPsByDevice := map[string]string{}
	if raw, ok := cfgAny[forwardCliCredentialFPMap]; ok {
		if parsed, ok := raw.(map[string]any); ok {
			for key, value := range parsed {
				if fp, ok := value.(string); ok && strings.TrimSpace(fp) != "" {
					credentialFPsByDevice[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(fp)
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
	endpoints := []forwardEndpoint{}
	seen := map[string]bool{}
	changed := false
	linuxProfileID := ""
	rows := parseNetlabStatusOutput(logText)

	// In-cluster deployments should use stable per-node service DNS names (not pod IPs).
	inCluster := dep != nil && (strings.EqualFold(strings.TrimSpace(dep.Type), "netlab-c9s") || strings.EqualFold(strings.TrimSpace(dep.Type), "clabernetes"))
	k8sNamespace := ""
	topologyName := ""
	nodeNameMapping := map[string]string{}
	if inCluster && pc != nil {
		k8sNamespace = clabernetesWorkspaceNamespace(pc.workspace.Slug)
		topologyName = clabernetesTopologyName(containerlabLabName(pc.workspace.Slug, dep.Name))

		// Build the same deterministic node-name mapping used for containerlab YAML sanitation.
		// This ensures Forward device names can preserve original case while hosts reference the
		// correct per-node Service names.
		oldNames := make([]string, 0, len(rows))
		for _, row := range rows {
			n := strings.TrimSpace(row.Node)
			if n != "" {
				oldNames = append(oldNames, n)
			}
		}
		sort.Strings(oldNames)
		used := map[string]bool{}
		for _, old := range oldNames {
			newName := sanitizeDNS1035Label(old)
			base := newName
			for i := 2; used[newName]; i++ {
				suffix := fmt.Sprintf("-%d", i)
				max := 63 - len(suffix)
				if max < 1 {
					newName = "n" + suffix
				} else if len(base) > max {
					newName = base[:max] + suffix
				} else {
					newName = base + suffix
				}
			}
			used[newName] = true
			nodeNameMapping[old] = newName
		}
	}

	for _, row := range rows {
		name := strings.TrimSpace(row.Node)
		rawDeviceKey := strings.ToLower(strings.TrimSpace(row.Device))
		deviceKey := rawDeviceKey
		switch deviceKey {
		case "cisco_iol", "iol", "ios_xe", "ios-xe", "iosxe":
			deviceKey = "ios"
		}

		mgmt := strings.TrimSpace(row.MgmtIPv4)
		if mgmt == "" || mgmt == "—" {
			continue
		}

		host := mgmt
		if inCluster && name != "" && k8sNamespace != "" && topologyName != "" {
			sanitizedNode := strings.TrimSpace(nodeNameMapping[name])
			if sanitizedNode == "" {
				sanitizedNode = sanitizeDNS1035Label(name)
			}
			serviceName := sanitizeKubeNameFallback(fmt.Sprintf("%s-%s", topologyName, sanitizedNode), topologyName)
			host = fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, k8sNamespace)
		}

		key := strings.ToLower(mgmt)
		if seen[key] {
			continue
		}
		seen[key] = true
		if name == "" {
			name = mgmt
		}

		// Linux nodes are uploaded as endpoints (not classic devices).
		if deviceKey == "linux" {
			if linuxProfileID == "" {
				profileID, err := forwardEnsureEndpointProfile(ctx, client, "Linux", []string{"UNIX"})
				if err != nil {
					return 0, fmt.Errorf("forward ensure linux endpoint profile failed: %w", err)
				}
				linuxProfileID = strings.TrimSpace(profileID)
				if linuxProfileID == "" {
					return 0, fmt.Errorf("forward ensure linux endpoint profile returned empty id")
				}
			}
			credID := credentialIDsByDevice["linux"]
			if credID == "" {
				if user, pass, ok0 := forwardDefaultCredentialForKind("linux"); ok0 {
					created, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialNameForDevice("linux"), user, pass)
					if err == nil && created != nil && strings.TrimSpace(created.ID) != "" {
						credID = strings.TrimSpace(created.ID)
						credentialIDsByDevice["linux"] = credID
						changed = true
					}
				}
			}
			collect := true
			endpoints = append(endpoints, forwardEndpoint{
				Type:         "CLI",
				Name:         name,
				Host:         host,
				Protocol:     "SSH",
				CredentialID: credID,
				ProfileID:    linuxProfileID,
				Collect:      &collect,
			})
			continue
		}

		cred, ok := netlabCredentialForDevice(row.Device, row.Image)
		// Some netlab status outputs omit the "device" field; fall back to our normalized
		// device key so we still select the correct default credentials.
		if !ok && deviceKey != "" {
			cred, ok = netlabCredentialForDevice(deviceKey, row.Image)
		}
		if !ok && deviceKey != "" {
			cred, ok = netlabCredentialForDevice(deviceKey, "")
		}
		desiredFP := ""
		if ok {
			desiredFP = forwardCredentialFingerprint(cred.Username, cred.Password)
		}
		cliCredentialID := ""
		if rawDeviceKey != "" {
			cliCredentialID = credentialIDsByDevice[rawDeviceKey]
		}
		if cliCredentialID == "" && deviceKey != "" {
			cliCredentialID = credentialIDsByDevice[deviceKey]
		}
		if cliCredentialID == "" && !ok {
			return 0, fmt.Errorf("netlab device %q (raw=%q image=%q) has no credential mapping", deviceKey, row.Device, row.Image)
		}

		// If this credential is Skyforge-managed and the desired credential fingerprint has changed
		// (or was never recorded), rotate the Forward CLI credential for this device kind.
		if desiredFP != "" && deviceKey != "" {
			storedFP := credentialFPsByDevice[deviceKey]
			if storedFP == "" || storedFP != desiredFP {
				cliCredentialID = ""
			}
		}

		if cliCredentialID == "" && ok && strings.TrimSpace(cred.Username) != "" && strings.TrimSpace(cred.Password) != "" {
			created, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialNameForDevice(deviceKey), cred.Username, cred.Password)
			if err == nil && created != nil {
				cliCredentialID = strings.TrimSpace(created.ID)
				if deviceKey != "" && cliCredentialID != "" {
					credentialIDsByDevice[deviceKey] = cliCredentialID
					if desiredFP != "" {
						credentialFPsByDevice[deviceKey] = desiredFP
					}
					changed = true
				}
			}
		}

		forwardType := ""
		if deviceKey != "" {
			forwardType = forwardTypes[deviceKey]
		}
		if forwardType == "" {
			imageLower := strings.ToLower(strings.TrimSpace(row.Image))
			if deviceKey == "ios" || strings.Contains(imageLower, "cisco_iol") {
				forwardType = "cisco_ios_ssh"
			}
		}
		devices = append(devices, forwardClassicDevice{
			Name:                     name,
			Type:                     forwardType,
			Host:                     host,
			CliCredentialID:          cliCredentialID,
			SnmpCredentialID:         snmpCredentialID,
			JumpServerID:             jumpServerID,
			CollectBgpAdvertisements: true,
			BgpTableType:             "BOTH",
			BgpPeerType:              "BOTH",
			EnableSnmpCollection:     true,
		})
	}

	if len(endpoints) > 0 {
		if err := forwardPutEndpointsBatch(ctx, client, networkID, endpoints); err != nil {
			return 0, err
		}
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
		cfgAny[forwardCliCredentialFPMap] = credentialFPsByDevice
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

func forwardDeviceKeyFromKind(kind string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch kind {
	case "ceos", "eos", "arista", "arista-eos":
		return "eos"
	case "linux", "alpine":
		return "linux"
	case "cisco_iol", "iol", "ios-xe", "ios_xe", "ios":
		return "ios"
	case "nxos", "cisco_n9kv", "n9kv":
		return "nxos"
	case "junos", "vmx", "vr-vmx", "vr_vmx", "juniper_vmx", "vjunos-router", "vjunos-switch":
		// Normalize Juniper devices to vMX/Junos (Forward type: juniper_junos_ssh).
		return "vmx"
	default:
		return kind
	}
}

func forwardDefaultCredentialForKind(kind string) (username, password string, ok bool) {
	switch forwardDeviceKeyFromKind(kind) {
	case "eos":
		return "admin", "admin", true
	case "linux":
		return "root", "admin", true
	case "ios":
		return "admin", "admin", true
	case "nxos":
		return "admin", "admin", true
	case "vmx":
		return "admin", "admin@123", true
	default:
		return "", "", false
	}
}

type forwardSyncOptions struct {
	// StartConnectivity controls whether we start Forward connectivity tests immediately
	// after importing devices/endpoints. For some in-cluster NOS images (vrnetlab/QEMU),
	// starting connectivity too early creates noisy "unreachable" signals. Those flows
	// should prefer an explicit SSH-ready gate before starting connectivity tests.
	StartConnectivity bool

	// StartCollection controls whether we start a Forward collection immediately after
	// importing devices/endpoints.
	StartCollection bool
}

func (e *Engine) syncForwardTopologyGraphDevices(ctx context.Context, taskID int, pc *workspaceContext, dep *WorkspaceDeployment, graph *TopologyGraph, opts forwardSyncOptions) (int, error) {
	if e == nil || pc == nil || dep == nil || graph == nil {
		return 0, nil
	}
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	cfgAny, err := e.ensureForwardNetworkForDeployment(ctx, pc, dep)
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

	collectorConfigID := getString(forwardCollectorIDKey)
	forwardCfg, err := e.forwardConfigForUserCollector(ctx, pc.claims.Username, collectorConfigID)
	if err != nil || forwardCfg == nil {
		return 0, err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return 0, err
	}

	forwardTypes := e.forwardDeviceTypes(ctx)
	jumpServerID := getString(forwardJumpServerIDKey)
	// Never use a jump server for in-cluster deployments.
	if dep != nil {
		t := strings.ToLower(strings.TrimSpace(dep.Type))
		if t == "netlab-c9s" || t == "clabernetes" {
			jumpServerID = ""
		}
	}
	snmpCredentialID := getString(forwardSnmpCredentialIDKey)

	credentialIDsByKind := map[string]string{}
	if raw, ok := cfgAny[forwardCliCredentialMap]; ok {
		if m, ok := raw.(map[string]any); ok {
			for k, v := range m {
				if s, ok := v.(string); ok {
					credentialIDsByKind[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(s)
				}
			}
		}
	}
	credentialFPsByKind := map[string]string{}
	if raw, ok := cfgAny[forwardCliCredentialFPMap]; ok {
		if m, ok := raw.(map[string]any); ok {
			for k, v := range m {
				if s, ok := v.(string); ok {
					fp := strings.TrimSpace(s)
					if fp != "" {
						credentialFPsByKind[strings.ToLower(strings.TrimSpace(k))] = fp
					}
				}
			}
		}
	}
	changed := false

	credentialNameForKind := func(kind string) string {
		base := sanitizeCredentialComponent(dep.Name)
		if base == "" {
			base = "deployment"
		}
		k := sanitizeCredentialComponent(kind)
		if k == "" {
			k = "default"
		}
		name := fmt.Sprintf("%s-%s", base, k)
		if len(name) > 80 {
			name = strings.TrimRight(name[:80], "-")
		}
		return name
	}

	devices := []forwardClassicDevice{}
	endpoints := []forwardEndpoint{}
	connectivityNames := []string{}
	seen := map[string]bool{}
	linuxEndpointProfileID := ""
	for _, node := range graph.Nodes {
		host := strings.TrimSpace(node.MgmtHost)
		if host == "" {
			host = strings.TrimSpace(node.MgmtIP)
		}
		pingIP := strings.TrimSpace(node.PingIP)
		if pingIP == "" {
			pingIP = strings.TrimSpace(node.MgmtIP)
		}
		if host == "" || host == "—" {
			continue
		}
		key := strings.ToLower(host)
		if seen[key] {
			continue
		}
		seen[key] = true

		deviceKey := forwardDeviceKeyFromKind(node.Kind)
		desiredCred, desiredOK := netlabCredentialForDevice(deviceKey, "")
		// Linux credentials are managed by Skyforge scripts and must remain root/admin.
		// Do not inherit the generic netlab catalog value (often vagrant/vagrant).
		if deviceKey == "linux" {
			if u, p, ok := forwardDefaultCredentialForKind(deviceKey); ok {
				desiredCred = netlabDeviceCredential{Username: u, Password: p}
				desiredOK = true
			}
		} else if !desiredOK {
			if u, p, ok := forwardDefaultCredentialForKind(deviceKey); ok {
				desiredCred = netlabDeviceCredential{Username: u, Password: p}
				desiredOK = true
			}
		}
		desiredFP := ""
		if desiredOK {
			desiredFP = forwardCredentialFingerprint(desiredCred.Username, desiredCred.Password)
		}
		if deviceKey == "linux" {
			if linuxEndpointProfileID == "" {
				profileID, err := forwardEnsureEndpointProfile(ctx, client, "Linux", []string{"UNIX"})
				if err != nil {
					return 0, fmt.Errorf("forward ensure linux endpoint profile failed: %w", err)
				}
				linuxEndpointProfileID = strings.TrimSpace(profileID)
				if linuxEndpointProfileID == "" {
					return 0, fmt.Errorf("forward ensure linux endpoint profile returned empty id")
				}
			}
			cliCredentialID := credentialIDsByKind[deviceKey]

			if desiredFP != "" {
				stored := credentialFPsByKind[deviceKey]
				if stored == "" || stored != desiredFP {
					cliCredentialID = ""
				}
			}
			if cliCredentialID == "" && desiredOK {
				created, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialNameForKind(deviceKey), desiredCred.Username, desiredCred.Password)
				if err == nil && created != nil && strings.TrimSpace(created.ID) != "" {
					cliCredentialID = strings.TrimSpace(created.ID)
					credentialIDsByKind[deviceKey] = cliCredentialID
					if desiredFP != "" {
						credentialFPsByKind[deviceKey] = desiredFP
					}
					changed = true
				}
			}
			name := strings.TrimSpace(node.Label)
			if name == "" {
				name = strings.TrimSpace(node.ID)
			}
			if name == "" {
				name = host
			}
			endpoints = append(endpoints, forwardEndpoint{
				Type:     "CLI",
				Name:     name,
				Host:     host,
				Protocol: "SSH",
				// Forward endpoint API uses "credentialId" (not "cliCredentialId").
				CredentialID: cliCredentialID,
				ProfileID:    linuxEndpointProfileID,
				Collect: func() *bool {
					v := true
					return &v
				}(),
			})
			continue
		}
		cliCredentialID := credentialIDsByKind[deviceKey]

		if desiredFP != "" && deviceKey != "" {
			stored := credentialFPsByKind[deviceKey]
			if stored == "" || stored != desiredFP {
				cliCredentialID = ""
			}
		}
		if cliCredentialID == "" && deviceKey != "" && desiredOK {
			created, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialNameForKind(deviceKey), desiredCred.Username, desiredCred.Password)
			if err == nil && created != nil && strings.TrimSpace(created.ID) != "" {
				cliCredentialID = strings.TrimSpace(created.ID)
				credentialIDsByKind[deviceKey] = cliCredentialID
				if desiredFP != "" {
					credentialFPsByKind[deviceKey] = desiredFP
				}
				changed = true
			}
		}

		name := strings.TrimSpace(node.Label)
		if name == "" {
			name = strings.TrimSpace(node.ID)
		}
		if name == "" {
			name = host
		}

		forwardType := ""
		if deviceKey != "" {
			forwardType = forwardTypes[deviceKey]
		}

		devices = append(devices, forwardClassicDevice{
			Name:                     name,
			Type:                     forwardType,
			Host:                     host,
			CliCredentialID:          cliCredentialID,
			SnmpCredentialID:         snmpCredentialID,
			JumpServerID:             jumpServerID,
			CollectBgpAdvertisements: true,
			BgpTableType:             "BOTH",
			BgpPeerType:              "BOTH",
			EnableSnmpCollection:     true,
		})
		connectivityNames = append(connectivityNames, name)
	}
	if len(endpoints) > 0 {
		if err := forwardPutEndpointsBatch(ctx, client, networkID, endpoints); err != nil {
			return 0, err
		}
	}
	if len(devices) == 0 {
		return 0, nil
	}
	if err := forwardPutClassicDevices(ctx, client, networkID, devices); err != nil {
		return 0, err
	}
	_ = opts.StartConnectivity // Connectivity tests are intentionally disabled.
	_ = connectivityNames
	if opts.StartCollection {
		_ = forwardStartCollection(ctx, client, networkID)
	}
	if changed {
		cfgAny[forwardCliCredentialMap] = credentialIDsByKind
		cfgAny[forwardCliCredentialFPMap] = credentialFPsByKind
		if err := e.updateDeploymentConfig(ctx, pc.workspace.ID, dep.ID, cfgAny); err != nil {
			return 0, err
		}
	}
	if taskID > 0 {
		_ = taskstore.AppendTaskEvent(context.Background(), e.db, taskID, "forward.devices.upload.succeeded", map[string]any{
			"source":      "topology",
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
