package taskengine

import (
	"context"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"encore.app/internal/taskstore"
)

type labppDeviceInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	MgmtIP string `json:"mgmtIp"`
	Port   int    `json:"port"`
}

func extractIPv4(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	parsed := net.ParseIP(value)
	if parsed != nil && parsed.To4() != nil {
		return parsed.String(), true
	}
	// CIDR like 10.0.0.1/24
	if ip, _, err := net.ParseCIDR(value); err == nil && ip != nil && ip.To4() != nil {
		return ip.String(), true
	}
	return "", false
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
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
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
	ipIdx := findIndex("ip_address", "mgmt_ip", "mgmt_ip_address", "management_ip", "management_ipv4", "ip")
	hostIdx := findIndex("host", "hostname")
	portIdx := findIndex("port", "ssh_port")
	typeIdx := findIndex("type", "device_type")
	if nameIdx == -1 {
		nameIdx = 0
	}

	devices := make([]labppDeviceInfo, 0, len(records)-1)
	for i := 1; i < len(records); i++ {
		row := records[i]
		if len(row) == 0 {
			continue
		}
		name := ""
		if nameIdx >= 0 && len(row) > nameIdx {
			name = strings.TrimSpace(row[nameIdx])
		}
		mgmtIP := ""
		if ipIdx >= 0 && len(row) > ipIdx {
			if ip, ok := extractIPv4(row[ipIdx]); ok {
				mgmtIP = ip
			}
		}
		host := ""
		if mgmtIP == "" && hostIdx >= 0 && len(row) > hostIdx {
			host = strings.TrimSpace(row[hostIdx])
			if ip, ok := extractIPv4(host); ok {
				mgmtIP = ip
				host = ""
			}
		}
		if mgmtIP == "" && host == "" {
			continue
		}
		port := 22
		if mgmtIP == "" {
			if portIdx >= 0 && len(row) > portIdx {
				if raw := strings.TrimSpace(row[portIdx]); raw != "" {
					if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
						port = parsed
					}
				}
			}
		}
		typ := ""
		if typeIdx >= 0 && len(row) > typeIdx {
			typ = strings.TrimSpace(row[typeIdx])
		}
		devices = append(devices, labppDeviceInfo{
			Name:   firstNonEmptyTrimmed(name, mgmtIP, host),
			Type:   typ,
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

func forwardOverridesFromEnv(env map[string]string) *forwardCredentials {
	if len(env) == 0 {
		return nil
	}
	override := &forwardCredentials{}
	set := func(field *string, key string) {
		if value, ok := env[key]; ok {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				*field = trimmed
			}
		}
	}
	set(&override.BaseURL, "LABPP_FORWARD_URL")
	set(&override.BaseURL, "LABPP_FORWARD_BASE_URL")
	set(&override.Username, "LABPP_FORWARD_USERNAME")
	set(&override.Password, "LABPP_FORWARD_PASSWORD")
	set(&override.DeviceUsername, "LABPP_FORWARD_DEVICE_USERNAME")
	set(&override.DevicePassword, "LABPP_FORWARD_DEVICE_PASSWORD")
	if override.BaseURL == "" && override.Username == "" && override.Password == "" &&
		override.DeviceUsername == "" && override.DevicePassword == "" {
		return nil
	}
	return override
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
	if strings.TrimSpace(override.DeviceUsername) != "" {
		base.DeviceUsername = strings.TrimSpace(override.DeviceUsername)
	}
	if strings.TrimSpace(override.DevicePassword) != "" {
		base.DevicePassword = strings.TrimSpace(override.DevicePassword)
	}
	return base
}

func (e *Engine) syncForwardLabppDevicesFromCSV(ctx context.Context, taskID int, pc *workspaceContext, deploymentID, csvPath string, startCollection bool, override *forwardCredentials) error {
	if pc == nil {
		return fmt.Errorf("workspace context unavailable")
	}
	if strings.TrimSpace(deploymentID) == "" {
		return fmt.Errorf("deployment id is required")
	}
	dep, err := e.loadDeployment(ctx, pc.workspace.ID, deploymentID)
	if err != nil {
		return err
	}
	if dep == nil {
		return fmt.Errorf("deployment not found")
	}
	if strings.TrimSpace(dep.Type) != "labpp" {
		return fmt.Errorf("forward sync only supported for labpp deployments")
	}
	cfgAny, _ := fromJSONMap(dep.Config)
	if cfgAny == nil {
		cfgAny = map[string]any{}
	}
	cfgAny, _ = e.ensureForwardNetworkForDeployment(ctx, pc, dep)
	devicesResp, err := readLabppDataSourcesCSV(csvPath)
	if err != nil {
		return err
	}
	forwardCfg, err := e.forwardConfigForWorkspace(ctx, pc.workspace.ID)
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

	// Ensure we have a single CLI credential for all devices (LabPP doesn't provide per-device secrets).
	deviceUsername := strings.TrimSpace(forwardCfg.DeviceUsername)
	devicePassword := strings.TrimSpace(forwardCfg.DevicePassword)
	if deviceUsername == "" {
		deviceUsername = "admin"
	}
	if devicePassword == "" {
		devicePassword = "admin"
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
	if credentialName == "" {
		credentialName = "labpp"
	}
	cliID := getString(forwardCliCredentialIDKey)
	if cliID == "" && deviceUsername != "" && devicePassword != "" {
		cred, err := forwardCreateCliCredentialNamed(ctx, client, networkID, credentialName, deviceUsername, devicePassword)
		if err == nil {
			cliID = cred.ID
			cfgAny[forwardCliCredentialIDKey] = cliID
			_ = e.updateDeploymentConfig(ctx, pc.workspace.ID, dep.ID, cfgAny)
		}
	}
	jumpServerID := getString(forwardJumpServerIDKey)
	snmpCredentialID := getString(forwardSnmpCredentialIDKey)

	devices := make([]forwardClassicDevice, 0, len(devicesResp))
	for _, d := range devicesResp {
		host := strings.TrimSpace(d.MgmtIP)
		if host == "" {
			continue
		}
		port := d.Port
		if port <= 0 {
			port = 22
		}
		devices = append(devices, forwardClassicDevice{
			Name:                     firstNonEmptyTrimmed(d.Name, host),
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
	if len(devices) == 0 {
		return nil
	}
	if err := forwardPutClassicDevices(ctx, client, networkID, devices); err != nil {
		return err
	}
	if startCollection {
		_ = forwardStartCollection(ctx, client, networkID)
	}
	if taskID > 0 {
		_ = taskstore.AppendTaskEvent(context.Background(), e.db, taskID, "forward.devices.upload.succeeded", map[string]any{
			"source":      "labpp",
			"networkId":   networkID,
			"deviceCount": len(devices),
		})
	}
	return nil
}

var ipLine = regexp.MustCompile(`\\*\\*([A-Za-z0-9_.-]+):\\s*Received Ip\\s+([0-9.]+)/`)

func (e *Engine) maybeReadNetboxIPsFromTaskLogs(ctx context.Context, taskID int) map[string]string {
	if e == nil || e.db == nil || taskID <= 0 {
		return nil
	}
	ctxReq, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	logs, err := taskstore.ListTaskLogs(ctxReq, e.db, taskID, 5000)
	if err != nil {
		return nil
	}
	ipByName := map[string]string{}
	for _, entry := range logs {
		matches := ipLine.FindStringSubmatch(entry.Output)
		if len(matches) != 3 {
			continue
		}
		name := strings.TrimSpace(matches[1])
		ip := strings.TrimSpace(matches[2])
		parsed := net.ParseIP(ip)
		if name == "" || parsed == nil || parsed.To4() == nil {
			continue
		}
		ipByName[name] = parsed.String()
	}
	if len(ipByName) == 0 {
		return nil
	}
	return ipByName
}

func (e *Engine) rewriteLabppDataSourcesCSVWithIPs(taskID int, csvPath string) error {
	ipByName := e.maybeReadNetboxIPsFromTaskLogs(context.Background(), taskID)
	if len(ipByName) == 0 {
		return nil
	}
	f, err := os.Open(csvPath)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := csv.NewReader(f)
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	if len(records) < 2 {
		return nil
	}
	header := make([]string, len(records[0]))
	for i, value := range records[0] {
		header[i] = strings.ToLower(strings.TrimSpace(value))
	}
	findIndex := func(name string) int {
		for idx, value := range header {
			if value == name {
				return idx
			}
		}
		return -1
	}
	nameIdx := findIndex("name")
	if nameIdx == -1 {
		nameIdx = 0
	}
	out := [][]string{{"name", "ip_address"}}
	for i := 1; i < len(records); i++ {
		row := records[i]
		if len(row) <= nameIdx {
			continue
		}
		name := strings.TrimSpace(row[nameIdx])
		if name == "" {
			continue
		}
		ip, ok := ipByName[name]
		if !ok {
			continue
		}
		out = append(out, []string{name, ip})
	}
	if len(out) <= 1 {
		return nil
	}
	tmp := csvPath + ".tmp"
	outFile, err := os.Create(tmp)
	if err != nil {
		return err
	}
	writer := csv.NewWriter(outFile)
	if err := writer.WriteAll(out); err != nil {
		_ = outFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		_ = outFile.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := outFile.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, csvPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
