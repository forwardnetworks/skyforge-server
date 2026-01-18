package taskengine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	secretreader "encore.app/internal/secrets"
	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
	"encore.dev/rlog"
)

type labppTaskSpec struct {
	Action            string            `json:"action,omitempty"`
	EveServer         string            `json:"eveServer,omitempty"`
	EveURL            string            `json:"eveUrl,omitempty"`
	EveUsername       string            `json:"eveUsername,omitempty"`
	EvePasswordEnc    string            `json:"evePasswordEnc,omitempty"`
	Deployment        string            `json:"deployment,omitempty"`
	DeploymentID      string            `json:"deploymentId,omitempty"`
	TemplatesRoot     string            `json:"templatesRoot,omitempty"`
	Template          string            `json:"template,omitempty"`
	LabPath           string            `json:"labPath,omitempty"`
	ThreadCount       int               `json:"threadCount,omitempty"`
	MaxSeconds        int               `json:"maxSeconds,omitempty"`
	Environment       map[string]string `json:"environment,omitempty"`
	TemplateSource    string            `json:"templateSource,omitempty"`
	TemplateRepo      string            `json:"templateRepo,omitempty"`
	TemplatesDir      string            `json:"templatesDir,omitempty"`
	TemplatesDestRoot string            `json:"templatesDestRoot,omitempty"`
}

type labppRunSpec struct {
	TaskID        int
	WorkspaceCtx  *workspaceContext
	DeploymentID  string
	Action        string
	WorkspaceSlug string
	Username      string
	Deployment    string
	Environment   map[string]string
	TemplatesRoot string
	Template      string
	LabPath       string
	ThreadCount   int
	EveURL        string
	EveUsername   string
	EvePassword   string
	EveSSHHost    string
	EveSSHUser    string
	EveSSHKey     string
	EveSSHKeyFile string
	EveSkipTLS    bool
	MaxSeconds    int
	Metadata      JSONMap
}

func (e *Engine) dispatchLabppTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	var specIn labppTaskSpec
	if err := decodeTaskSpec(task, &specIn); err != nil {
		return err
	}
	ws, err := e.loadWorkspaceByKey(ctx, task.WorkspaceID)
	if err != nil {
		return err
	}
	username := strings.TrimSpace(task.CreatedBy)
	if username == "" {
		username = ws.primaryOwner()
	}
	pc := &workspaceContext{
		workspace: *ws,
		claims: SessionClaims{
			Username: username,
		},
	}

	serverRef := strings.TrimSpace(specIn.EveServer)
	if serverRef == "" {
		serverRef = strings.TrimSpace(pc.workspace.EveServer)
	}
	resolvedEve, err := e.resolveWorkspaceEveServerConfig(ctx, pc.workspace.ID, serverRef)
	if err != nil {
		return err
	}
	eveServer := &resolvedEve.Server
	skipTLSOverride := resolvedEve.SkipTLSOverride
	sshHostOverride := strings.TrimSpace(eveServer.SSHHost)
	sshUserOverride := strings.TrimSpace(eveServer.SSHUser)
	sshKeyOverride := strings.TrimSpace(resolvedEve.SSHKey)

	eveURL := strings.TrimSpace(specIn.EveURL)
	if eveURL == "" {
		eveURL = strings.TrimSpace(eveServer.WebURL)
		if eveURL == "" {
			eveURL = strings.TrimSpace(eveServer.APIURL)
		}
	}
	eveUsername := strings.TrimSpace(specIn.EveUsername)
	if eveUsername == "" {
		eveUsername = strings.TrimSpace(pc.claims.Username)
	}
	evePassword := ""
	if enc := strings.TrimSpace(specIn.EvePasswordEnc); enc != "" {
		if plaintext, err := e.decryptUserSecret(enc); err == nil {
			evePassword = strings.TrimSpace(plaintext)
		}
	}
	if evePassword == "" {
		if cached, ok := getCachedLDAPPassword(ctx, e.db, e.box, pc.claims.Username); ok {
			evePassword = strings.TrimSpace(cached)
		}
	}
	if strings.TrimSpace(eveUsername) == "" || strings.TrimSpace(evePassword) == "" {
		return fmt.Errorf("eve credentials are required (login again to refresh cached password)")
	}

	template := strings.TrimSpace(specIn.Template)
	if template == "" {
		return fmt.Errorf("template is required")
	}

	templatesRoot := strings.TrimSpace(specIn.TemplatesRoot)
	if templatesRoot == "" {
		source := strings.TrimSpace(specIn.TemplateSource)
		if source == "" {
			source = "blueprints"
		}
		syncedRoot := ""
		if err := taskdispatch.WithTaskStep(ctx, e.db, task.ID, "labpp.sync-template", func() error {
			destRoot := strings.TrimSpace(specIn.TemplatesDestRoot)
			if destRoot == "" {
				destRoot = filepath.Join("/var/lib/skyforge/labpp/tasks", fmt.Sprintf("task-%d", task.ID), "templates")
			}
			out, err := e.syncLabppTemplateDir(
				ctx,
				pc,
				eveServer,
				source,
				strings.TrimSpace(specIn.TemplateRepo),
				strings.TrimSpace(specIn.TemplatesDir),
				template,
				destRoot,
			)
			syncedRoot = strings.TrimSpace(out)
			return err
		}); err != nil {
			return fmt.Errorf("failed to sync labpp template: %w", err)
		}
		templatesRoot = syncedRoot
	}

	labPath := strings.TrimSpace(specIn.LabPath)
	if labPath == "" {
		deployment := strings.TrimSpace(specIn.Deployment)
		if deployment == "" {
			deployment = strings.TrimSpace(pc.workspace.Slug)
		}
		labPath = labppLabPath(pc.claims.Username, deployment, template, time.Now())
		labPath = labppNormalizeFolderPath(labPath)
	}

	maxSeconds := specIn.MaxSeconds
	if maxSeconds <= 0 {
		maxSeconds = 1200
	}

	runSpec := labppRunSpec{
		TaskID:        task.ID,
		WorkspaceCtx:  pc,
		DeploymentID:  strings.TrimSpace(specIn.DeploymentID),
		Action:        strings.TrimSpace(specIn.Action),
		WorkspaceSlug: strings.TrimSpace(pc.workspace.Slug),
		Username:      strings.TrimSpace(pc.claims.Username),
		Deployment:    strings.TrimSpace(specIn.Deployment),
		Environment:   specIn.Environment,
		TemplatesRoot: templatesRoot,
		Template:      template,
		LabPath:       labPath,
		ThreadCount:   specIn.ThreadCount,
		EveURL:        eveURL,
		EveUsername:   eveUsername,
		EvePassword:   evePassword,
		EveSSHHost:    sshHostOverride,
		EveSSHUser:    sshUserOverride,
		EveSSHKey:     sshKeyOverride,
		EveSkipTLS:    skipTLSOverride,
		MaxSeconds:    maxSeconds,
		Metadata:      task.Metadata,
	}

	action := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "labpp."+action, func() error {
		return e.runLabppTask(ctx, runSpec, log)
	})
}

func (e *Engine) decryptUserSecret(ciphertext string) (string, error) {
	ciphertext = strings.TrimSpace(ciphertext)
	if ciphertext == "" || e == nil || e.box == nil {
		return "", fmt.Errorf("secret unavailable")
	}
	plaintext, err := e.box.decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return "", fmt.Errorf("secret unavailable")
	}
	return plaintext, nil
}

func internalIntegrationURL(cfgValue string, fallback string) string {
	if v := strings.TrimSpace(cfgValue); v != "" {
		return strings.TrimRight(v, "/")
	}
	return strings.TrimRight(strings.TrimSpace(fallback), "/")
}

func (e *Engine) netboxInternalBaseURL() string {
	return internalIntegrationURL(e.cfg.NetboxInternalBaseURL, "http://netbox:8080/netbox")
}

func (e *Engine) runLabppTask(ctx context.Context, spec labppRunSpec, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	project := strings.TrimSpace(spec.WorkspaceSlug)
	if project == "" {
		project = strings.TrimSpace(spec.Username)
	}
	if project == "" {
		project = "default"
	}
	deployment := strings.TrimSpace(spec.Deployment)
	if deployment == "" {
		deployment = strings.TrimSpace(spec.Template)
	}
	labPath := strings.TrimSpace(spec.LabPath)
	if labPath == "" && strings.TrimSpace(spec.Template) != "" {
		labPath = labppLabPath(spec.Username, deployment, spec.Template, time.Now())
	}
	labPath = labppNormalizeFolderPath(labPath)
	labppRunnerPath := strings.TrimPrefix(strings.TrimSpace(labPath), "/")
	templatesRoot := strings.TrimSpace(spec.TemplatesRoot)
	if templatesRoot == "" {
		return fmt.Errorf("labpp templatesRoot missing (retry the run)")
	}
	taskDir := ""
	if spec.TaskID > 0 {
		taskDir = filepath.Join("/var/lib/skyforge/labpp/tasks", fmt.Sprintf("task-%d", spec.TaskID))
		if strings.HasPrefix(taskDir, "/var/lib/skyforge/labpp/tasks/") {
			defer os.RemoveAll(taskDir)
		}
	}
	action := strings.TrimSpace(spec.Action)
	if strings.EqualFold(action, "configure") {
		action = "config"
	}
	if strings.EqualFold(action, "e2e") {
		action = ""
	}
	if strings.EqualFold(action, "start") {
		action = ""
	}
	templateDir := filepath.Join(templatesRoot, spec.Template)
	if _, err := os.Stat(templateDir); err != nil {
		return fmt.Errorf("labpp template dir missing: %w", err)
	}
	if taskDir == "" {
		return fmt.Errorf("labpp task dir unavailable (retry the run)")
	}
	configDirBase := filepath.Join(taskDir, "configs")

	eveHost := resolveLabppHost(spec.EveURL)
	if eveHost == "" {
		return fmt.Errorf("eve host unavailable for labpp")
	}
	sshHost := strings.TrimSpace(spec.EveSSHHost)
	if sshHost == "" {
		sshHost = eveHost
	}
	sshUser := strings.TrimSpace(spec.EveSSHUser)
	if sshUser == "" {
		sshUser = strings.TrimSpace(e.cfg.Labs.EveSSHUser)
	}
	sshKey := strings.TrimSpace(spec.EveSSHKey)
	sshKeyFile := strings.TrimSpace(spec.EveSSHKeyFile)

	configFile, err := e.writeLabppConfigFile(configDirBase, eveHost, spec.EveUsername, spec.EvePassword)
	if err != nil {
		return err
	}
	defer os.Remove(configFile)

	debugID := uuid.NewString()
	debugFingerprint := ""
	if spec.EvePassword != "" {
		sum := sha256.Sum256([]byte(spec.EvePassword))
		debugFingerprint = fmt.Sprintf("%x", sum)
	}
	log.Infof("LabPP debug id: %s", debugID)
	log.Infof("LabPP EVE password fingerprint: %s", debugFingerprint)
	log.Infof("LabPP run: action=%s labPath=%s templateDir=%s", action, labPath, templateDir)

	customArgs := []string{"--verbose", "--debug", "labpp", "--no-forwarding", "--template-dir", templateDir, "--config-dir-base", configDirBase, "--labpp-config-file", configFile}
	if labppRunnerPath != "" {
		customArgs = append(customArgs, "--lab-path", labppRunnerPath)
	}
	if action != "" {
		customArgs = append(customArgs, "--action", strings.ToUpper(action))
	}
	if spec.ThreadCount > 0 {
		customArgs = append(customArgs, "--thread-count", strconv.Itoa(spec.ThreadCount))
	}

	jobEnv := map[string]string{
		"LABPP_NETBOX_URL":         e.netboxInternalBaseURL(),
		"LABPP_NETBOX_MGMT_SUBNET": strings.TrimSpace(e.cfg.LabppNetboxMgmtSubnet),
		"LABPP_EVE_HOST":           eveHost,
		"LABPP_CONFIG_FILE":        configFile,
		"LABPP_CONFIG_DIR_BASE":    configDirBase,
		"LABPP_TEMPLATES_DIR":      templateDir,
		"LABPP_LAB_PATH":           labppRunnerPath,
		"LABPP_ACTION":             action,
		"LABPP_EVE_SSH_HOST":       sshHost,
		"LABPP_EVE_SSH_USER":       sshUser,
		"LABPP_EVE_SSH_KEY_FILE":   "",
		"LABPP_EVE_SSH_PORT":       "22",
		"LABPP_EVE_SSH_TUNNEL":     fmt.Sprintf("%v", e.cfg.Labs.EveSSHTunnel),
		"LABPP_EVE_SSH_NO_PROXY":   "localhost|127.0.0.1|minio|netbox|nautobot|gitea|skyforge-server|*.svc|*.cluster.local",
		"LABPP_SKIP_FORWARD":       "true",
		"LABPP_DEPLOYMENT_ID":      strings.TrimSpace(spec.DeploymentID),
	}
	if sshKeyFile != "" {
		jobEnv["LABPP_EVE_SSH_KEY_FILE"] = sshKeyFile
		jobEnv["LABPP_EVE_SSH_KEY"] = ""
	} else if sshKey != "" {
		jobEnv["LABPP_EVE_SSH_KEY_FILE"] = ""
		jobEnv["LABPP_EVE_SSH_KEY"] = sshKey
	}
	jobEnv["LABPP_NETBOX_USERNAME"] = strings.TrimSpace(e.cfg.LabppNetboxUsername)
	jobEnv["LABPP_NETBOX_PASSWORD"] = strings.TrimSpace(e.cfg.LabppNetboxPassword)
	jobEnv["LABPP_NETBOX_TOKEN"] = strings.TrimSpace(e.cfg.LabppNetboxToken)
	if jobEnv["LABPP_NETBOX_USERNAME"] == "" {
		jobEnv["LABPP_NETBOX_USERNAME"] = strings.TrimSpace(os.Getenv("SKYFORGE_LABPP_NETBOX_USERNAME"))
	}
	if jobEnv["LABPP_NETBOX_USERNAME"] == "" {
		if secret, err := secretreader.ReadSecretFromEnvOrFile("SKYFORGE_LABPP_NETBOX_USERNAME", "skyforge-labpp-netbox-username"); err == nil {
			jobEnv["LABPP_NETBOX_USERNAME"] = strings.TrimSpace(secret)
		}
	}
	if jobEnv["LABPP_NETBOX_PASSWORD"] == "" {
		jobEnv["LABPP_NETBOX_PASSWORD"] = strings.TrimSpace(os.Getenv("SKYFORGE_LABPP_NETBOX_PASSWORD"))
	}
	if jobEnv["LABPP_NETBOX_PASSWORD"] == "" {
		if secret, err := secretreader.ReadSecretFromEnvOrFile("SKYFORGE_LABPP_NETBOX_PASSWORD", "skyforge-labpp-netbox-password"); err == nil {
			jobEnv["LABPP_NETBOX_PASSWORD"] = strings.TrimSpace(secret)
		}
	}
	if jobEnv["LABPP_NETBOX_TOKEN"] == "" {
		jobEnv["LABPP_NETBOX_TOKEN"] = strings.TrimSpace(os.Getenv("SKYFORGE_LABPP_NETBOX_TOKEN"))
	}
	if jobEnv["LABPP_NETBOX_TOKEN"] == "" {
		if secret, err := secretreader.ReadSecretFromEnvOrFile("SKYFORGE_LABPP_NETBOX_TOKEN", "skyforge-labpp-netbox-token"); err == nil {
			jobEnv["LABPP_NETBOX_TOKEN"] = strings.TrimSpace(secret)
		}
	}
	if spec.ThreadCount > 0 {
		jobEnv["LABPP_THREAD_COUNT"] = strconv.Itoa(spec.ThreadCount)
	}
	maps.Copy(jobEnv, spec.Environment)

	log.Infof("Starting LabPP runner job (%s)", strings.Join(customArgs, " "))
	jobName := fmt.Sprintf("labpp-%d", spec.TaskID)
	if err := e.runLabppJob(ctx, log, jobName, customArgs, jobEnv, spec.TaskID); err != nil {
		if isLabppForwardFailure(err.Error()) {
			e.appendTaskWarning(spec.TaskID, fmt.Sprintf("LabPP forward checks failed (ignored): %s", strings.TrimSpace(err.Error())))
			log.Infof("LabPP forward-check failure ignored: %v", err)
		} else if isLabppBenignFailure(action, err.Error(), "") {
			e.appendTaskWarning(spec.TaskID, fmt.Sprintf("LabPP benign failure treated as success: %s", strings.TrimSpace(err.Error())))
			log.Infof("LabPP %s treated as success: %v", action, err)
			return nil
		} else {
			return err
		}
	}

	shouldSyncForward := action == "" || strings.EqualFold(action, "upload") || strings.EqualFold(action, "create")
	if spec.WorkspaceCtx != nil && strings.TrimSpace(spec.DeploymentID) != "" && shouldSyncForward {
		dataSourcesDir := filepath.Join(taskDir, "data-sources")
		csvPath, err := e.generateLabppDataSourcesCSV(ctx, spec.TaskID, spec.DeploymentID, templateDir, configDirBase, configFile, labPath, dataSourcesDir, log, eveHost, sshHost, sshUser, sshKeyFile, sshKey)
		if err != nil {
			rlog.Error("labpp data_sources.csv generation failed", "task_id", spec.TaskID, "err", err)
		} else {
			if payload, err := os.ReadFile(csvPath); err != nil {
				rlog.Error("labpp data_sources.csv read failed", "task_id", spec.TaskID, "err", err)
			} else if len(payload) > 0 && len(payload) <= 2<<20 {
				ctxPut, cancel := context.WithTimeout(ctx, 10*time.Second)
				key := fmt.Sprintf("labpp/%s/data_sources.csv", strings.TrimSpace(spec.DeploymentID))
				if putKey, err := putWorkspaceArtifact(ctxPut, e.cfg, spec.WorkspaceCtx.workspace.ID, key, payload, "text/csv"); err != nil {
					rlog.Error("labpp data_sources.csv upload failed", "task_id", spec.TaskID, "err", err)
				} else {
					e.setTaskMetadataKey(spec.TaskID, "labppDataSourcesKey", putKey)
					log.Infof("LabPP data_sources.csv uploaded as %s", putKey)
				}
				cancel()
				log.Infof("LabPP data_sources.csv generated at %s", csvPath)
			}
			forwardOverride := forwardOverridesFromEnv(spec.Environment)
			startCollection := action == ""
			if err := e.syncForwardLabppDevicesFromCSV(ctx, spec.TaskID, spec.WorkspaceCtx, spec.DeploymentID, csvPath, startCollection, forwardOverride); err != nil {
				rlog.Error("forward labpp sync", "task_id", spec.TaskID, "err", err)
			}
		}
	}
	return nil
}

func resolveLabppHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err == nil && u != nil && u.Hostname() != "" {
		return u.Hostname()
	}
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "//")
	return strings.TrimSpace(strings.Split(raw, "/")[0])
}

func (e *Engine) writeLabppConfigFile(configDir, eveHost, username, password string) (string, error) {
	if strings.TrimSpace(username) == "" || strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("labpp eve credentials are required")
	}
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create labpp config dir: %w", err)
	}
	f, err := os.CreateTemp(configDir, "labpp-*.properties")
	if err != nil {
		return "", fmt.Errorf("failed to create labpp config file: %w", err)
	}
	defer f.Close()

	version := strings.TrimSpace(e.cfg.LabppConfigVersion)
	if version == "" {
		version = "1.0"
	}
	lines := []string{
		fmt.Sprintf("version=%s", version),
		fmt.Sprintf("username=%s", username),
		fmt.Sprintf("password=%s", password),
		fmt.Sprintf("server_url=https://%s", eveHost),
	}
	if e.cfg.LabppNetboxURL != "" {
		netboxURL := strings.TrimRight(e.cfg.LabppNetboxURL, "/")
		if !strings.Contains(netboxURL, "/netbox") {
			netboxURL = netboxURL + "/netbox"
		}
		lines = append(lines, fmt.Sprintf("netbox_server_url=%s", netboxURL))
	}
	if e.cfg.LabppNetboxUsername != "" {
		lines = append(lines, fmt.Sprintf("netbox_username=%s", e.cfg.LabppNetboxUsername))
	}
	if e.cfg.LabppNetboxPassword != "" {
		lines = append(lines, fmt.Sprintf("netbox_password=%s", e.cfg.LabppNetboxPassword))
	}
	if e.cfg.LabppNetboxMgmtSubnet != "" {
		lines = append(lines, fmt.Sprintf("netbox_mgmt_subnet_ip=%s", e.cfg.LabppNetboxMgmtSubnet))
	}
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return "", fmt.Errorf("failed to write labpp config file: %w", err)
	}
	return f.Name(), nil
}

func (e *Engine) generateLabppDataSourcesCSV(ctx context.Context, taskID int, deploymentID, templateDir, configDirBase, configFile, labPath, dataSourcesDir string, log Logger, eveHost, sshHost, sshUser, sshKeyFile, sshKey string) (string, error) {
	if dataSourcesDir == "" {
		dataSourcesDir = filepath.Join(os.TempDir(), "labpp-data-sources")
	}
	if err := os.MkdirAll(dataSourcesDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create data sources dir: %w", err)
	}
	customArgs := []string{"--verbose", "--debug", "labpp", "--no-forwarding", "--template-dir", templateDir, "--config-dir-base", configDirBase, "--labpp-config-file", configFile, "--action", "DATA_SOURCES_CSV", "--sources-dir", dataSourcesDir}
	labppRunnerPath := strings.TrimPrefix(strings.TrimSpace(labPath), "/")
	if labppRunnerPath != "" {
		customArgs = append(customArgs, "--lab-path", labppRunnerPath)
	}
	log.Infof("Generating labpp data_sources.csv")
	jobEnv := map[string]string{
		"LABPP_NETBOX_URL":         e.netboxInternalBaseURL(),
		"LABPP_NETBOX_MGMT_SUBNET": strings.TrimSpace(e.cfg.LabppNetboxMgmtSubnet),
		"LABPP_EVE_HOST":           eveHost,
		"LABPP_CONFIG_FILE":        configFile,
		"LABPP_CONFIG_DIR_BASE":    configDirBase,
		"LABPP_TEMPLATES_DIR":      templateDir,
		"LABPP_LAB_PATH":           labppRunnerPath,
		"LABPP_ACTION":             "DATA_SOURCES_CSV",
		"LABPP_SOURCES_DIR":        dataSourcesDir,
		"LABPP_EVE_SSH_HOST":       sshHost,
		"LABPP_EVE_SSH_USER":       sshUser,
		"LABPP_EVE_SSH_KEY_FILE":   "",
		"LABPP_EVE_SSH_PORT":       "22",
		"LABPP_EVE_SSH_TUNNEL":     fmt.Sprintf("%v", e.cfg.Labs.EveSSHTunnel),
		"LABPP_EVE_SSH_NO_PROXY":   "localhost|127.0.0.1|minio|netbox|nautobot|gitea|skyforge-server|*.svc|*.cluster.local",
		"LABPP_SKIP_FORWARD":       "true",
	}
	if sshKeyFile != "" {
		jobEnv["LABPP_EVE_SSH_KEY_FILE"] = sshKeyFile
		jobEnv["LABPP_EVE_SSH_KEY"] = ""
	} else if sshKey != "" {
		jobEnv["LABPP_EVE_SSH_KEY_FILE"] = ""
		jobEnv["LABPP_EVE_SSH_KEY"] = sshKey
	}
	jobEnv["LABPP_NETBOX_USERNAME"] = strings.TrimSpace(e.cfg.LabppNetboxUsername)
	jobEnv["LABPP_NETBOX_PASSWORD"] = strings.TrimSpace(e.cfg.LabppNetboxPassword)
	if jobEnv["LABPP_NETBOX_USERNAME"] == "" {
		jobEnv["LABPP_NETBOX_USERNAME"] = strings.TrimSpace(os.Getenv("SKYFORGE_LABPP_NETBOX_USERNAME"))
	}
	if jobEnv["LABPP_NETBOX_USERNAME"] == "" {
		if secret, err := secretreader.ReadSecretFromEnvOrFile("SKYFORGE_LABPP_NETBOX_USERNAME", "skyforge-labpp-netbox-username"); err == nil {
			jobEnv["LABPP_NETBOX_USERNAME"] = strings.TrimSpace(secret)
		}
	}
	if jobEnv["LABPP_NETBOX_PASSWORD"] == "" {
		jobEnv["LABPP_NETBOX_PASSWORD"] = strings.TrimSpace(os.Getenv("SKYFORGE_LABPP_NETBOX_PASSWORD"))
	}
	if jobEnv["LABPP_NETBOX_PASSWORD"] == "" {
		if secret, err := secretreader.ReadSecretFromEnvOrFile("SKYFORGE_LABPP_NETBOX_PASSWORD", "skyforge-labpp-netbox-password"); err == nil {
			jobEnv["LABPP_NETBOX_PASSWORD"] = strings.TrimSpace(secret)
		}
	}
	logName := fmt.Sprintf("labpp-sources-%s", deploymentID)
	if err := e.runLabppJob(ctx, log, logName, customArgs, jobEnv, 0); err != nil {
		return "", err
	}
	csvPath := filepath.Join(dataSourcesDir, "data_sources.csv")
	if _, err := os.Stat(csvPath); err != nil {
		return "", fmt.Errorf("labpp data_sources.csv missing: %w", err)
	}
	if taskID > 0 {
		if err := e.rewriteLabppDataSourcesCSVWithIPs(taskID, csvPath); err != nil {
			log.Infof("labpp data_sources.csv rewrite skipped: %v", err)
		}
	}
	return csvPath, nil
}

func isLabppBenignFailure(action string, errText string, logs string) bool {
	if action == "" {
		return false
	}
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "stop" && action != "delete" && action != "destroy" {
		return false
	}
	candidate := strings.ToLower(strings.TrimSpace(errText))
	if candidate == "" {
		candidate = strings.ToLower(strings.TrimSpace(logs))
	}
	if candidate == "" {
		return false
	}
	for _, marker := range []string{
		"lab does not exists",
		"lab does not exist",
		"lab not found",
		"not found",
	} {
		if strings.Contains(candidate, marker) {
			return true
		}
	}
	return false
}

func isLabppForwardFailure(errText string) bool {
	candidate := strings.ToLower(strings.TrimSpace(errText))
	if candidate == "" {
		return false
	}
	for _, marker := range []string{
		"connect to http://localhost",
		"connect to http://localhost:80",
		"no forward properties file found",
		"please provide one through the --fwd-config option",
		"fwd init helps to create these",
		"runsnapshotchecks",
		"getnetworkwithname",
		"fwdapi.getnetworks",
		"http host connect exception",
	} {
		if strings.Contains(candidate, marker) {
			return true
		}
	}
	return false
}

func labppLabPath(username, deployment, template string, now time.Time) string {
	username = strings.TrimSpace(username)
	deployment = strings.TrimSpace(deployment)
	template = strings.TrimSpace(template)
	if deployment == "" {
		deployment = "deployment"
	}
	if template == "" {
		template = "template"
	}
	stamp := now.UTC().Format("20060102-1504")
	return fmt.Sprintf("/%s_%s_%s_%s", username, deployment, template, stamp)
}

func labppNormalizeFolderPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.ReplaceAll(path, " ", "_")
	path = strings.ReplaceAll(path, "__", "_")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

// LabPP template sync (local filesystem) + Forward sync helpers are implemented in separate files.
