package skyforge

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

const (
	forwardNetworkIDKey       = "forwardNetworkId"
	forwardNetworkNameKey     = "forwardNetworkName"
	forwardCliCredentialIDKey = "forwardCliCredentialId"
	forwardJumpServerIDKey    = "forwardJumpServerId"
)

const (
	defaultNetlabDeviceUsername = "admin"
	defaultNetlabDevicePassword = "admin"
)

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
	lines := strings.Split(logText, "\n")
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

func (s *Service) forwardConfigForProject(ctx context.Context, projectID string) (*forwardCredentials, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rec, err := getProjectForwardCredentials(ctx, s.db, newSecretBox(s.cfg.SessionSecret), projectID)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, nil
	}
	if strings.TrimSpace(rec.BaseURL) == "" {
		rec.BaseURL = defaultForwardBaseURL
	}
	rec.DeviceUsername = ""
	rec.DevicePassword = ""
	rec.JumpHost = ""
	rec.JumpUsername = ""
	rec.JumpPrivateKey = ""
	rec.JumpCert = ""
	if strings.TrimSpace(rec.Username) == "" || strings.TrimSpace(rec.Password) == "" {
		return nil, nil
	}
	return rec, nil
}

func (s *Service) ensureForwardNetworkForDeployment(ctx context.Context, pc *projectContext, dep *ProjectDeployment) (map[string]any, error) {
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	forwardCfg, err := s.forwardConfigForProject(ctx, pc.project.ID)
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

	networkID := getString(forwardNetworkIDKey)
	changed := false
	if networkID == "" {
		networkName := fmt.Sprintf("skyforge/%s/%s", pc.project.Slug, dep.Name)
		network, err := forwardCreateNetwork(ctx, client, networkName)
		if err != nil {
			return cfgAny, err
		}
		networkID = network.ID
		cfgAny[forwardNetworkIDKey] = networkID
		cfgAny[forwardNetworkNameKey] = networkName
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

	cliCredentialID := getString(forwardCliCredentialIDKey)
	deviceUsername := strings.TrimSpace(forwardCfg.DeviceUsername)
	devicePassword := strings.TrimSpace(forwardCfg.DevicePassword)
	if deviceUsername == "" && devicePassword == "" && dep.Type == "netlab" {
		deviceUsername = defaultNetlabDeviceUsername
		devicePassword = defaultNetlabDevicePassword
	}
	if cliCredentialID == "" && deviceUsername != "" && devicePassword != "" {
		cred, err := forwardCreateCliCredential(ctx, client, networkID, deviceUsername, devicePassword)
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
	if dep.Type == "netlab" {
		userName := strings.TrimSpace(pc.claims.Username)
		if userName != "" {
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
				if jumpUser == "" {
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
		if err := s.updateDeploymentConfig(ctx, pc.project.ID, dep.ID, cfgAny); err != nil {
			return cfgAny, err
		}
	}
	return cfgAny, nil
}

func (s *Service) syncForwardNetlabDevices(ctx context.Context, pc *projectContext, dep *ProjectDeployment, logText string) error {
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	cfgAny, err := s.ensureForwardNetworkForDeployment(ctx, pc, dep)
	if err != nil {
		return err
	}

	forwardCfg, err := s.forwardConfigForProject(ctx, pc.project.ID)
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
	cliCredentialID := getString(forwardCliCredentialIDKey)
	jumpServerID := getString(forwardJumpServerIDKey)

	devices := []forwardClassicDevice{}
	seen := map[string]bool{}
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
		return err
	}
	if err := forwardStartCollection(ctx, client, networkID); err != nil {
		log.Printf("forward start collection: %v", err)
	}
	return nil
}

func (s *Service) updateDeploymentConfig(ctx context.Context, projectID, deploymentID string, cfgAny map[string]any) error {
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
WHERE project_id=$2 AND id=$3`, cfgBytes, projectID, deploymentID)
	return err
}
