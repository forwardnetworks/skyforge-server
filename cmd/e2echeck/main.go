package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type workspaceCreateRequest struct {
	Name      string `json:"name"`
	Blueprint string `json:"blueprint,omitempty"`
}

type workspaceResponse struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type createdWorkspaceRecord struct {
	BaseURL        string `json:"baseUrl"`
	WorkspaceID    string `json:"workspaceId"`
	WorkspaceSlug  string `json:"workspaceSlug"`
	WorkspaceName  string `json:"workspaceName"`
	CreatedAt      string `json:"createdAt"`
}

type listWorkspacesResponse struct {
	User       string              `json:"user"`
	Workspaces []workspaceResponse `json:"workspaces"`
}

type netlabValidateRequest struct {
	Source       string            `json:"source"`
	Repo         string            `json:"repo"`
	Dir          string            `json:"dir"`
	Template     string            `json:"template"`
	Environment  map[string]string `json:"environment"`
	SetOverrides []string          `json:"setOverrides"`
}

type netlabValidateResponse struct {
	WorkspaceID string         `json:"workspaceId"`
	User        string         `json:"user"`
	Task        map[string]any `json:"task"`
}

type deploymentCreateRequest struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Config map[string]any `json:"config,omitempty"`
}

type deploymentResponse struct {
	ID          string         `json:"id"`
	WorkspaceID string         `json:"workspaceId"`
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Config      map[string]any `json:"config,omitempty"`
}

type deploymentActionResponse struct {
	WorkspaceID string             `json:"workspaceId"`
	Deployment  deploymentResponse `json:"deployment"`
	Run         map[string]any     `json:"run,omitempty"`
}

type deploymentForwardConfigRequest struct {
	Enabled           bool   `json:"enabled"`
	CollectorConfigID string `json:"collectorConfigId,omitempty"`
}

type deploymentTopologyResponse struct {
	GeneratedAt string `json:"generatedAt"`
	Source      string `json:"source"`
	Nodes       []struct {
		ID     string `json:"id"`
		Label  string `json:"label"`
		Kind   string `json:"kind,omitempty"`
		MgmtIP string `json:"mgmtIp,omitempty"`
		Status string `json:"status,omitempty"`
	} `json:"nodes"`
}

type collectorRuntimeStatus struct {
	Namespace      string `json:"namespace"`
	DeploymentName string `json:"deploymentName"`
	PodName        string `json:"podName,omitempty"`
	PodPhase       string `json:"podPhase,omitempty"`
	Ready          bool   `json:"ready"`
	Image          string `json:"image,omitempty"`
}

type userCollectorRuntimeResponse struct {
	Runtime *collectorRuntimeStatus `json:"runtime,omitempty"`
}

type listCollectorsResponse struct {
	Collectors []struct {
		ID        string                  `json:"id"`
		Name      string                  `json:"name"`
		IsDefault bool                    `json:"isDefault"`
		Runtime   *collectorRuntimeStatus `json:"runtime,omitempty"`
	} `json:"collectors"`
}

type putUserForwardCollectorRequest struct {
	BaseURL       string `json:"baseUrl"`
	SkipTLSVerify bool   `json:"skipTlsVerify"`
	Username      string `json:"username"`
	Password      string `json:"password"`
}

type matrixFile struct {
	Tests []matrixTest `yaml:"tests"`
}

type matrixTest struct {
	Name string `yaml:"name"`
	Kind string `yaml:"kind"`

	NetlabValidate *struct {
		Source       string            `yaml:"source"`
		Repo         string            `yaml:"repo"`
		Dir          string            `yaml:"dir"`
		Template     string            `yaml:"template"`
		Environment  map[string]string `yaml:"environment"`
		SetOverrides []string          `yaml:"setOverrides"`
		Timeout      string            `yaml:"timeout"`
	} `yaml:"netlab_validate,omitempty"`

	NetlabDeploy *struct {
		Type         string            `yaml:"type"` // netlab-c9s (recommended)
		Source       string            `yaml:"source"`
		Repo         string            `yaml:"repo"`
		Dir          string            `yaml:"dir"`
		Template     string            `yaml:"template"`
		Environment  map[string]string `yaml:"environment"`
		SetOverrides []string          `yaml:"setOverrides"`
		Timeout      string            `yaml:"timeout"`
		SSHBanners   bool              `yaml:"sshBanners"`
		SSHTimeout   string            `yaml:"sshTimeout"`
		Cleanup      bool              `yaml:"cleanup"`
	} `yaml:"netlab_deploy,omitempty"`

	ContainerlabDeploy *struct {
		Source      string            `yaml:"source"`
		Repo        string            `yaml:"repo"`
		Dir         string            `yaml:"dir"`
		Template    string            `yaml:"template"`
		Environment map[string]string `yaml:"environment"`
		Timeout     string            `yaml:"timeout"`
		Cleanup     bool              `yaml:"cleanup"`
	} `yaml:"containerlab_deploy,omitempty"`
}

type netlabDeviceDefaultsCatalog struct {
	Sets []struct {
		Device      string `json:"device"`
		ImagePrefix string `json:"image_prefix"`
	} `json:"sets"`
}

type workspaceNetlabServerConfig struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	APIURL      string `json:"apiUrl"`
	APIInsecure bool   `json:"apiInsecure,omitempty"`
	APIUser     string `json:"apiUser,omitempty"`
	APIPassword string `json:"apiPassword,omitempty"`
	APIToken    string `json:"apiToken,omitempty"`
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
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

func getenvBoolOK(key string) (bool, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return false, false
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "y", "on":
		return true, true
	case "0", "false", "no", "n", "off":
		return false, true
	default:
		return false, false
	}
}

func appendCreatedWorkspace(statusDir string, rec createdWorkspaceRecord) error {
	statusDir = strings.TrimSpace(statusDir)
	if statusDir == "" {
		return fmt.Errorf("statusDir missing")
	}
	path := filepath.Join(statusDir, "e2e-created-workspaces.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

func removeCreatedWorkspace(statusDir string, workspaceID string) error {
	statusDir = strings.TrimSpace(statusDir)
	workspaceID = strings.TrimSpace(workspaceID)
	if statusDir == "" || workspaceID == "" {
		return nil
	}
	path := filepath.Join(statusDir, "e2e-created-workspaces.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	lines := strings.Split(string(raw), "\n")
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var rec createdWorkspaceRecord
		if json.Unmarshal([]byte(ln), &rec) == nil && strings.TrimSpace(rec.WorkspaceID) == workspaceID {
			continue
		}
		out = append(out, ln)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func deleteWorkspaceByID(client *http.Client, baseURL, cookie, workspaceID, workspaceSlug string) error {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	workspaceID = strings.TrimSpace(workspaceID)
	workspaceSlug = strings.TrimSpace(workspaceSlug)
	if baseURL == "" || workspaceID == "" {
		return fmt.Errorf("missing baseURL/workspaceID")
	}
	deleteURL := fmt.Sprintf("%s/api/workspaces/%s?confirm=%s", baseURL, workspaceID, url.QueryEscape(workspaceSlug))
	resp, body, err := doJSON(client, http.MethodDelete, deleteURL, nil, map[string]string{"Cookie": cookie})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("workspace delete failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func mustEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return ""
	}
	return v
}

func loadPasswordFromSecretsFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	secrets, _ := doc["secrets"].(map[string]any)
	items, _ := secrets["items"].(map[string]any)
	entry, _ := items["skyforge-admin-shared"].(map[string]any)
	password, _ := entry["password"].(string)
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("skyforge-admin-shared.password not set")
	}
	return password, nil
}

func loadNetlabDeviceCatalog(path string) (map[string]struct{}, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var decoded netlabDeviceDefaultsCatalog
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	for _, s := range decoded.Sets {
		if d := strings.TrimSpace(s.Device); d != "" {
			out[d] = struct{}{}
		}
	}
	return out, nil
}

func splitCSVEnv(name string) map[string]struct{} {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil
	}
	out := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}

func containsSetCI(set map[string]struct{}, v string) bool {
	if len(set) == 0 {
		return false
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return false
	}
	for k := range set {
		if strings.ToLower(strings.TrimSpace(k)) == v {
			return true
		}
	}
	return false
}

func ensureWorkspaceNetlabServer(client *http.Client, baseURL, cookie, workspaceID string) (string, error) {
	apiURL := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_BYOS_NETLAB_API_URL"))
	if apiURL == "" {
		return "", fmt.Errorf("SKYFORGE_E2E_BYOS_NETLAB_API_URL is not set")
	}
	apiToken := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_BYOS_NETLAB_API_TOKEN"))
	apiUser := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_BYOS_NETLAB_API_USER"))
	apiPassword := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_BYOS_NETLAB_API_PASSWORD"))
	apiInsecure := getenvBool("SKYFORGE_E2E_BYOS_NETLAB_API_INSECURE", false)

	payload := workspaceNetlabServerConfig{
		Name:        "",
		APIURL:      apiURL,
		APIInsecure: apiInsecure,
		APIUser:     apiUser,
		APIPassword: apiPassword,
		APIToken:    apiToken,
	}
	url := fmt.Sprintf("%s/api/workspaces/%s/netlab/servers", strings.TrimRight(strings.TrimSpace(baseURL), "/"), strings.TrimSpace(workspaceID))
	resp, body, err := doJSON(client, http.MethodPut, url, payload, map[string]string{"Cookie": cookie})
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("upsert workspace netlab server failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out workspaceNetlabServerConfig
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("upsert workspace netlab server parse failed: %w", err)
	}
	if strings.TrimSpace(out.ID) == "" {
		return "", fmt.Errorf("upsert workspace netlab server returned empty id")
	}
	return "ws:" + strings.TrimSpace(out.ID), nil
}

type e2eTemplate struct {
	Name       string
	Source     string
	Dir        string
	Template   string
	Deployable bool
}

var e2eTemplatesBase = []e2eTemplate{
	{Name: "minimal", Source: "blueprints", Dir: "netlab/_e2e/minimal", Template: "topology.yml", Deployable: true},
}

var e2eTemplatesAdvanced = []e2eTemplate{
	// Advanced routing templates (opt-in via SKYFORGE_E2E_ADVANCED=true).
	{Name: "routing-ospf", Source: "blueprints", Dir: "netlab/_e2e/routing-ospf", Template: "topology.yml", Deployable: true},
	{Name: "routing-bgp", Source: "blueprints", Dir: "netlab/_e2e/routing-bgp", Template: "topology.yml", Deployable: true},
}

var e2eContainerlabTemplate = struct {
	Source   string
	Dir      string
	Template string
}{
	Source:   "blueprints",
	Dir:      "containerlab",
	Template: "smoke.clab.yml",
}

func allowedTemplatesForDevice(device string) map[string]struct{} {
	device = strings.TrimSpace(device)
	// For the default E2E suite we only care about "does this device type come up and accept SSH?"
	// Keep it minimal and fast. Advanced routing templates are opt-in and filtered separately.
	return map[string]struct{}{"minimal": {}}
}

func deployTimeoutsForDevice(device string) (deployTimeout string, sshTimeout string) {
	switch strings.TrimSpace(device) {
	// QEMU-heavy / slow-boot devices.
	case "vmx", "vptx", "cat8000v", "nxos", "sros":
		return "50m", "30m"
	default:
		return "25m", "12m"
	}
}

func deployableInSkyforge(device string) bool {
	switch strings.TrimSpace(device) {
	// These are the device types Skyforge currently exposes as "available"/"onboarded"
	// for in-cluster (clabernetes) netlab deployments.
	//
	// NOTE: Exclude vsrx (out of scope) even if the upstream netlab catalog includes it.
	case "eos", "iol", "iosv", "iosvl2", "csr", "nxos", "cumulus", "sros", "asav", "fortios", "vmx", "vjunos-router", "vjunos-switch", "cat8000v", "arubacx", "dellos10", "vptx", "linux":
		return true
	default:
		return false
	}
}

func onboardedNetlabDevices() []string {
	// Keep this list aligned with what we expose in the UI (Netlab device presets) and what
	// we actually build/push images for. This is intentionally not "every netlab device".
	return []string{
		"eos",
		"iol",
		"iosv",
		"iosvl2",
		"csr",
		"nxos",
		"cumulus",
		"sros",
		"asav",
		"fortios",
		"vmx",
		"vjunos-router",
		"vjunos-switch",
		"cat8000v",
		"arubacx",
		"dellos10",
		"vptx",
		"linux",
	}
}

func e2eTemplates() []e2eTemplate {
	out := make([]e2eTemplate, 0, len(e2eTemplatesBase)+len(e2eTemplatesAdvanced))
	out = append(out, e2eTemplatesBase...)
	if getenvBool("SKYFORGE_E2E_ADVANCED", false) {
		out = append(out, e2eTemplatesAdvanced...)
	}
	return out
}

func generateMatrixFromCatalog(catalogPath string) (matrixFile, error) {
	devices := map[string]struct{}{}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("SKYFORGE_E2E_DEVICE_SET")), "all") {
		catalogDevices, err := loadNetlabDeviceCatalog(catalogPath)
		if err != nil {
			return matrixFile{}, err
		}
		for d := range catalogDevices {
			devices[d] = struct{}{}
		}
	} else {
		for _, d := range onboardedNetlabDevices() {
			devices[d] = struct{}{}
		}
	}
	// Always include eos even if the catalog ever changes (Skyforge default).
	devices["eos"] = struct{}{}
	// Explicitly out-of-scope.
	delete(devices, "vsrx")

	deviceFilter := splitCSVEnv("SKYFORGE_E2E_DEVICES")
	templateFilter := splitCSVEnv("SKYFORGE_E2E_TEMPLATES")
	deployEnabled := getenvBool("SKYFORGE_E2E_DEPLOY", false)
	deployDeviceFilter := splitCSVEnv("SKYFORGE_E2E_DEPLOY_DEVICES")

	deviceList := make([]string, 0, len(devices))
	for d := range devices {
		if deviceFilter != nil {
			if _, ok := deviceFilter[d]; !ok {
				continue
			}
		}
		deviceList = append(deviceList, d)
	}
	sort.Strings(deviceList)

	tests := []matrixTest{}
	for _, d := range deviceList {
		allowed := allowedTemplatesForDevice(d)
		for _, tmpl := range e2eTemplates() {
			if _, ok := allowed[tmpl.Name]; !ok {
				continue
			}
			if templateFilter != nil {
				if _, ok := templateFilter[tmpl.Name]; !ok {
					continue
				}
			}

			validateName := fmt.Sprintf("netlab-validate-%s-%s", d, tmpl.Name)
			tests = append(tests, matrixTest{
				Name: validateName,
				Kind: "netlab_validate",
				NetlabValidate: &struct {
					Source       string            `yaml:"source"`
					Repo         string            `yaml:"repo"`
					Dir          string            `yaml:"dir"`
					Template     string            `yaml:"template"`
					Environment  map[string]string `yaml:"environment"`
					SetOverrides []string          `yaml:"setOverrides"`
					Timeout      string            `yaml:"timeout"`
				}{
					Source:   tmpl.Source,
					Repo:     "",
					Dir:      tmpl.Dir,
					Template: tmpl.Template,
					Environment: map[string]string{
						"NETLAB_DEVICE": d,
					},
					SetOverrides: nil,
					Timeout:      "10m",
				},
			})

			if deployEnabled && tmpl.Deployable {
				if !deployableInSkyforge(d) {
					continue
				}
				if deployDeviceFilter != nil {
					if _, ok := deployDeviceFilter[d]; !ok {
						continue
					}
				}
				deployName := fmt.Sprintf("netlab-deploy-%s-%s", d, tmpl.Name)
				deployTimeout, sshTimeout := deployTimeoutsForDevice(d)
				tests = append(tests, matrixTest{
					Name: deployName,
					Kind: "netlab_deploy",
					NetlabDeploy: &struct {
						Type         string            `yaml:"type"`
						Source       string            `yaml:"source"`
						Repo         string            `yaml:"repo"`
						Dir          string            `yaml:"dir"`
						Template     string            `yaml:"template"`
						Environment  map[string]string `yaml:"environment"`
						SetOverrides []string          `yaml:"setOverrides"`
						Timeout      string            `yaml:"timeout"`
						SSHBanners   bool              `yaml:"sshBanners"`
						SSHTimeout   string            `yaml:"sshTimeout"`
						Cleanup      bool              `yaml:"cleanup"`
					}{
						Type:     "netlab-c9s",
						Source:   tmpl.Source,
						Repo:     "",
						Dir:      tmpl.Dir,
						Template: tmpl.Template,
						Environment: map[string]string{
							"NETLAB_DEVICE": d,
						},
						SetOverrides: nil,
						Timeout:      deployTimeout,
						SSHBanners:   true,
						SSHTimeout:   sshTimeout,
						Cleanup:      true,
					},
				})
			}
		}
	}

	if getenvBool("SKYFORGE_E2E_BYOS", false) {
		byosDevices := splitCSVEnv("SKYFORGE_E2E_BYOS_DEVICES")
		if byosDevices == nil {
			// Default to a single lightweight BYOS smoke test.
			byosDevices = map[string]struct{}{"eos": {}}
		}

		for _, d := range deviceList {
			if _, ok := byosDevices[d]; !ok {
				continue
			}
			tmpl := e2eTemplatesBase[0] // minimal
			tests = append(tests, matrixTest{
				Name: fmt.Sprintf("netlab-byos-deploy-%s-%s", d, tmpl.Name),
				Kind: "netlab_byos_deploy",
				NetlabDeploy: &struct {
					Type         string            `yaml:"type"`
					Source       string            `yaml:"source"`
					Repo         string            `yaml:"repo"`
					Dir          string            `yaml:"dir"`
					Template     string            `yaml:"template"`
					Environment  map[string]string `yaml:"environment"`
					SetOverrides []string          `yaml:"setOverrides"`
					Timeout      string            `yaml:"timeout"`
					SSHBanners   bool              `yaml:"sshBanners"`
					SSHTimeout   string            `yaml:"sshTimeout"`
					Cleanup      bool              `yaml:"cleanup"`
				}{
					Type:     "netlab",
					Source:   tmpl.Source,
					Repo:     "",
					Dir:      tmpl.Dir,
					Template: tmpl.Template,
					Environment: map[string]string{
						"NETLAB_DEVICE": d,
					},
					SetOverrides: nil,
					Timeout:      "35m",
					SSHBanners:   false,
					SSHTimeout:   "",
					Cleanup:      true,
				},
			})
		}

		tests = append(tests, matrixTest{
			Name: "containerlab-byos-deploy-smoke",
			Kind: "containerlab_byos_deploy",
			ContainerlabDeploy: &struct {
				Source      string            `yaml:"source"`
				Repo        string            `yaml:"repo"`
				Dir         string            `yaml:"dir"`
				Template    string            `yaml:"template"`
				Environment map[string]string `yaml:"environment"`
				Timeout     string            `yaml:"timeout"`
				Cleanup     bool              `yaml:"cleanup"`
			}{
				Source:      e2eContainerlabTemplate.Source,
				Repo:        "",
				Dir:         e2eContainerlabTemplate.Dir,
				Template:    e2eContainerlabTemplate.Template,
				Environment: map[string]string{},
				Timeout:     "25m",
				Cleanup:     true,
			},
		})
	}

	return matrixFile{Tests: tests}, nil
}

func kubectlEnv() []string {
	kcfg := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_KUBECONFIG"))
	if kcfg == "" {
		// Default to the repo kubeconfig (used for prod/dev cluster access via tunnel).
		kcfg = "../.kubeconfig-skyforge"
	}
	if abs, err := filepath.Abs(kcfg); err == nil && strings.TrimSpace(abs) != "" {
		kcfg = abs
	}
	return append(os.Environ(), "KUBECONFIG="+kcfg)
}

func kubectlAvailable(ctx context.Context) error {
	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx2, "kubectl", "version", "--client=true", "-o", "json")
	cmd.Env = kubectlEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl not available: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func kubectlApplyYAML(ctx context.Context, yaml string) error {
	// kubectl -> API server can transiently fail under load (etcd timeouts, etc).
	// Retrying makes long E2E runs far less flaky.
	var last string
	backoff := 2 * time.Second
	for attempt := 1; attempt <= 6; attempt++ {
		ctx2, cancel := context.WithTimeout(ctx, 90*time.Second)
		cmd := exec.CommandContext(ctx2, "kubectl", "apply", "-f", "-")
		cmd.Env = kubectlEnv()
		cmd.Stdin = strings.NewReader(yaml)
		out, err := cmd.CombinedOutput()
		cancel()
		if err == nil {
			return nil
		}
		last = strings.TrimSpace(string(out))
		if attempt < 6 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("kubectl apply canceled: %s", last)
			case <-time.After(backoff):
			}
			if backoff < 15*time.Second {
				backoff *= 2
			}
			continue
		}
	}
	return fmt.Errorf("kubectl apply failed: %s", last)
}

func kubectlDeleteName(ctx context.Context, kind, namespace, name string) {
	kind = strings.TrimSpace(kind)
	namespace = strings.TrimSpace(namespace)
	name = strings.TrimSpace(name)
	if kind == "" || name == "" {
		return
	}
	args := []string{}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	args = append(args, "delete", kind, name, "--ignore-not-found=true", "--wait=false")
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx2, "kubectl", args...)
	cmd.Env = kubectlEnv()
	_, _ = cmd.CombinedOutput()
}

func sshProbeMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SKYFORGE_E2E_SSH_PROBE_MODE"))) {
	case "collector_exec":
		return "collector_exec"
	case "job":
		return "job"
	default:
		// Prefer the in-cluster API probe; it does not require local kubectl access.
		return "api"
	}
}

type adminSSHProbeRequest struct {
	Hosts          []string `json:"hosts"`
	Port           int      `json:"port,omitempty"`
	TimeoutSeconds int      `json:"timeoutSeconds,omitempty"`
	TCPOnly        bool     `json:"tcpOnly,omitempty"`
}

type adminSSHProbeResult struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Attempts int    `json:"attempts,omitempty"`
}

type adminSSHProbeResponse struct {
	OK      bool                           `json:"ok"`
	Results map[string]adminSSHProbeResult `json:"results,omitempty"`
}

func waitForSSHProbeAPI(ctx context.Context, client *http.Client, baseURL, cookie string, hosts []string, timeout time.Duration, tcpOnly bool) error {
	if len(hosts) == 0 {
		return fmt.Errorf("no hosts")
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return fmt.Errorf("baseURL missing")
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	timeoutSeconds := int(timeout.Seconds())
	if timeoutSeconds <= 0 {
		timeoutSeconds = 600
	}

	req := adminSSHProbeRequest{
		Hosts:          hosts,
		Port:           22,
		TimeoutSeconds: timeoutSeconds,
		TCPOnly:        tcpOnly,
	}
	url := baseURL + "/api/admin/e2e/sshprobe"

	// The probe endpoint is synchronous and may legitimately take minutes.
	// Use a dedicated client with a timeout that covers the whole probe window.
	probeClient := &http.Client{
		Transport:     client.Transport,
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       timeout + 60*time.Second,
	}
	resp, body, err := doJSONWithRetry(ctx, probeClient, http.MethodPost, url, req, map[string]string{"Cookie": cookie})
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ssh probe api failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out adminSSHProbeResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return fmt.Errorf("ssh probe api parse failed: %v", err)
	}
	if out.OK {
		return nil
	}
	if len(out.Results) == 0 {
		return fmt.Errorf("ssh probe failed (no results)")
	}

	type item struct {
		host string
		res  adminSSHProbeResult
	}
	items := make([]item, 0, len(out.Results))
	for h, r := range out.Results {
		items = append(items, item{host: h, res: r})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].host < items[j].host })

	var b strings.Builder
	for _, it := range items {
		if it.res.OK {
			continue
		}
		if it.res.Error != "" {
			fmt.Fprintf(&b, "%s: %s\n", it.host, it.res.Error)
		} else {
			fmt.Fprintf(&b, "%s: failed\n", it.host)
		}
	}
	msg := strings.TrimSpace(b.String())
	if msg == "" {
		msg = "ssh probe failed"
	}
	return fmt.Errorf("%s", msg)
}

func isSlowSSHDevice(device string) bool {
	switch strings.ToLower(strings.TrimSpace(device)) {
	case "iosv", "iosvl2":
		return true
	default:
		return false
	}
}

func waitForSSHProbeAPIForDevice(ctx context.Context, client *http.Client, baseURL, cookie string, device string, hosts []string, timeout time.Duration) error {
	// Fast path.
	if !isSlowSSHDevice(device) {
		return waitForSSHProbeAPI(ctx, client, baseURL, cookie, hosts, timeout, false)
	}

	// Two-phase probe for slow-booting NOS:
	// 1) wait until TCP/22 is open (no banner requirement)
	// 2) then require the SSH banner.
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	warmup := 6 * time.Minute
	if warmup > timeout/2 {
		warmup = timeout / 2
	}
	if warmup < 60*time.Second {
		warmup = 60 * time.Second
	}
	if err := waitForSSHProbeAPI(ctx, client, baseURL, cookie, hosts, warmup, true); err != nil {
		return err
	}
	return waitForSSHProbeAPI(ctx, client, baseURL, cookie, hosts, timeout-warmup, false)
}

func isRetryableSSProbeHTTPError(err error) bool {
	if err == nil {
		return false
	}
	// Common flaky failures we see when the API is rolling or proxying:
	// - EOF (connection reset mid-request)
	// - transient net errors
	// - context deadline exceeded (rare, but better to retry once within the overall probe window)
	if errors.Is(err, io.EOF) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return true
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		if errors.Is(ue.Err, io.EOF) {
			return true
		}
		var ne2 net.Error
		if errors.As(ue.Err, &ne2) {
			return true
		}
	}
	return false
}

func doJSONWithRetry(ctx context.Context, client *http.Client, method, urlStr string, body any, headers map[string]string) (*http.Response, []byte, error) {
	// Keep this narrow: only used for sshprobe, where we can tolerate brief API flaps.
	// Use small bounded retries and let the probe endpoint's own timeout handle the long tail.
	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		resp, b, err := doJSON(client, method, urlStr, body, headers)
		if err == nil {
			return resp, b, nil
		}
		lastErr = err
		if !isRetryableSSProbeHTTPError(err) || attempt == maxAttempts {
			return nil, nil, err
		}
		// small jittered backoff
		sleep := time.Duration(250+rand.Intn(500)) * time.Millisecond
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(sleep):
		}
	}
	return nil, nil, lastErr
}

func waitForSSHProbeJob(ctx context.Context, namespace string, hosts []string, timeout time.Duration) error {
	if err := kubectlAvailable(ctx); err != nil {
		return err
	}
	if len(hosts) == 0 {
		return fmt.Errorf("no hosts")
	}
	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = "skyforge"
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}

	hostArgs := []string{}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h != "" {
			hostArgs = append(hostArgs, h)
		}
	}
	if len(hostArgs) == 0 {
		return fmt.Errorf("no hosts")
	}

	jobName := fmt.Sprintf("e2e-sshprobe-%d", time.Now().Unix()%1_000_000)
	activeDeadline := int64(timeout.Seconds()) + 120
	if activeDeadline < 60 {
		activeDeadline = 60
	}

	script := `import os, socket, sys, time
hosts = [h for h in os.environ.get("HOSTS","").split() if h.strip()]
per_host_timeout = int(os.environ.get("TIMEOUT_SECONDS","300") or "300")
def probe(host):
  deadline = time.time() + per_host_timeout
  last = None
  while time.time() < deadline:
    try:
      s = socket.create_connection((host, 22), timeout=3)
      s.settimeout(3)
      data = s.recv(64)
      s.close()
      if b"SSH-" in data:
        return True, None
      last = f"bad_banner:{data[:16]!r}"
    except Exception as e:
      last = str(e)
    time.sleep(2)
  return False, last
for h in hosts:
  ok, err = probe(h)
  if not ok:
    sys.stderr.write(f"{h}: {err}\n")
    sys.exit(2)
print("ok")
`

	manifest := fmt.Sprintf(`apiVersion: batch/v1
kind: Job
metadata:
  name: %s
  namespace: %s
spec:
  backoffLimit: 0
  activeDeadlineSeconds: %d
  template:
    spec:
      imagePullSecrets:
      - name: ghcr-pull
      restartPolicy: Never
      containers:
      - name: probe
        image: %s
        imagePullPolicy: IfNotPresent
        env:
        - name: HOSTS
          value: %q
        - name: TIMEOUT_SECONDS
          value: %q
        command: ["python","-c",%q]
`, jobName, namespace, activeDeadline, getenv("SKYFORGE_E2E_SSH_PROBE_IMAGE", "ghcr.io/forwardnetworks/skyforge-netlab-generator:latest"), strings.Join(hostArgs, " "), fmt.Sprintf("%d", int(timeout.Seconds())), script)

	if err := kubectlApplyYAML(ctx, manifest); err != nil {
		return err
	}
	defer kubectlDeleteName(context.Background(), "job", namespace, jobName)

	ctx2, cancel := context.WithTimeout(ctx, timeout+2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx2, "kubectl", "-n", namespace, "wait", "--for=condition=complete", "job/"+jobName, "--timeout="+fmt.Sprintf("%ds", int(timeout.Seconds()+120)))
	cmd.Env = kubectlEnv()
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	return fmt.Errorf("ssh probe job %s failed: %s", jobName, strings.TrimSpace(string(out)))
}

func doJSON(client *http.Client, method, url string, body any, headers map[string]string) (*http.Response, []byte, error) {
	var r io.Reader
	if body != nil {
		enc, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		r = bytes.NewReader(enc)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b, nil
}

type dnsCacheDialer struct {
	dialer *net.Dialer
	mu     sync.Mutex
	cache  map[string]string // host -> ip
}

func newDNSCacheDialer() *dnsCacheDialer {
	d := &dnsCacheDialer{
		dialer: &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second},
		cache:  map[string]string{},
	}
	// Optional: seed overrides for environments where DNS is flaky or not configured
	// (e.g., local `.local` domains). Format:
	//   SKYFORGE_E2E_DNS_OVERRIDES=host1=1.2.3.4,host2=5.6.7.8
	if raw := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_DNS_OVERRIDES")); raw != "" {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			host, ip, ok := strings.Cut(part, "=")
			host = strings.TrimSpace(host)
			ip = strings.TrimSpace(ip)
			if !ok || host == "" || ip == "" {
				continue
			}
			d.cache[host] = ip
		}
	}
	return d
}

func (d *dnsCacheDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return d.dialer.DialContext(ctx, network, addr)
	}

	d.mu.Lock()
	cachedIP := d.cache[host]
	d.mu.Unlock()

	// Resolve and cache on first dial. If resolution fails but we have a cached
	// IP, keep going; this makes long E2E runs resilient to transient DNS issues.
	if cachedIP == "" {
		ips, _ := net.DefaultResolver.LookupIPAddr(ctx, host)
		for _, ip := range ips {
			if s := strings.TrimSpace(ip.IP.String()); s != "" {
				cachedIP = s
				break
			}
		}
		if cachedIP != "" {
			d.mu.Lock()
			d.cache[host] = cachedIP
			d.mu.Unlock()
		}
	}

	if cachedIP != "" {
		return d.dialer.DialContext(ctx, network, net.JoinHostPort(cachedIP, port))
	}
	return d.dialer.DialContext(ctx, network, addr)
}

func parseTaskID(task map[string]any) int {
	if task == nil {
		return 0
	}
	if v, ok := task["id"]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		case string:
			id, _ := strconv.Atoi(strings.TrimSpace(t))
			return id
		}
	}
	return 0
}

func waitForTaskFinished(client *http.Client, baseURL string, cookie string, workspaceID string, taskID int, timeout time.Duration) (status string, errMsg string, err error) {
	if taskID <= 0 {
		return "", "", fmt.Errorf("invalid task id")
	}
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	url := fmt.Sprintf("%s/api/runs/%d/lifecycle", strings.TrimRight(baseURL, "/"), taskID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return "", "", fmt.Errorf("task lifecycle SSE failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	defer resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	lineCh := make(chan string, 128)
	errCh := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for sc.Scan() {
			lineCh <- strings.TrimRight(sc.Text(), "\r")
		}
		if err := sc.Err(); err != nil {
			errCh <- err
			return
		}
		close(lineCh)
	}()

	pollEvery := 5 * time.Second
	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()

	heartbeatEvery := 30 * time.Second
	heartbeat := time.NewTicker(heartbeatEvery)
	defer heartbeat.Stop()

	start := time.Now()
	missingPolls := 0
	queuedPolls := 0
	lastPoll := ""

	var currentData strings.Builder
	for {
		select {
		case <-ctx.Done():
			if output, err := fetchRunOutput(client, baseURL, cookie, workspaceID, taskID); err == nil && strings.TrimSpace(output) != "" {
				fmt.Fprintf(os.Stderr, "--- task %d output ---\n%s\n--- end output ---\n", taskID, output)
			}
			return "", "", fmt.Errorf("timeout waiting for task %d", taskID)
		case err := <-errCh:
			if err != nil {
				return "", "", err
			}
		case <-heartbeat.C:
			fmt.Fprintf(os.Stderr, "WAIT task %d (elapsed %s) lastPoll=%q\n", taskID, time.Since(start).Truncate(time.Second), lastPoll)
		case <-ticker.C:
			if strings.TrimSpace(workspaceID) != "" {
				st, er, state := pollTaskStatus(client, baseURL, cookie, workspaceID, taskID)
				switch state {
				case pollTerminal:
					return st, er, nil
				case pollMissing:
					missingPolls++
					queuedPolls = 0
					lastPoll = "missing"
					if missingPolls >= 12 { // ~60s
						reconcileURL := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/api/admin/tasks/reconcile"
						_, _, _ = doJSON(client, http.MethodPost, reconcileURL, map[string]any{"limit": 200}, map[string]string{"Cookie": cookie})
						missingPolls = 0
					}
				case pollNonTerminal:
					missingPolls = 0
					lastPoll = strings.TrimSpace(st)
					if strings.EqualFold(strings.TrimSpace(st), "queued") {
						queuedPolls++
						if queuedPolls >= 12 { // ~60s
							reconcileURL := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/api/admin/tasks/reconcile"
							_, _, _ = doJSON(client, http.MethodPost, reconcileURL, map[string]any{"limit": 200}, map[string]string{"Cookie": cookie})
							queuedPolls = 0
						}
					} else {
						queuedPolls = 0
					}
				}
			}
		case line, ok := <-lineCh:
			if !ok {
				// Stream ended; fall back to a final poll.
				st, er, state := pollTaskStatus(client, baseURL, cookie, workspaceID, taskID)
				if state == pollTerminal {
					return st, er, nil
				}
				return "", "", fmt.Errorf("task lifecycle stream ended before task.finished")
			}
			if line == "" {
				// end of event
				if currentData.Len() > 0 {
					// The SSE stream uses event name `lifecycle` with a payload like:
					// {"cursor":123,"entries":[{"type":"task.started",...},{"type":"task.finished","payload":{"status":"succeeded"}}]}
					var envelope struct {
						Cursor  int64 `json:"cursor"`
						Entries []struct {
							Type    string         `json:"type"`
							Time    string         `json:"time"`
							Payload map[string]any `json:"payload"`
						} `json:"entries"`
					}
					_ = json.Unmarshal([]byte(currentData.String()), &envelope)
					currentData.Reset()
					for _, evt := range envelope.Entries {
						if strings.TrimSpace(evt.Type) != "task.finished" {
							continue
						}
						st, _ := evt.Payload["status"].(string)
						er, _ := evt.Payload["error"].(string)
						return strings.TrimSpace(st), strings.TrimSpace(er), nil
					}
				}
				continue
			}
			if strings.HasPrefix(line, "data:") {
				currentData.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
				continue
			}
		}
	}
}

type pollState int

const (
	pollMissing pollState = iota
	pollNonTerminal
	pollTerminal
)

func pollTaskStatus(client *http.Client, baseURL string, cookie string, workspaceID string, taskID int) (status string, errMsg string, state pollState) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" || taskID <= 0 {
		return "", "", pollMissing
	}
	url := fmt.Sprintf("%s/api/runs?workspace_id=%s&limit=25", strings.TrimRight(baseURL, "/"), workspaceID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", pollMissing
	}
	req.Header.Set("Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", pollMissing
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", pollMissing
	}
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		Tasks []map[string]any `json:"tasks"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", pollMissing
	}
	for _, t := range out.Tasks {
		id := 0
		switch v := t["id"].(type) {
		case float64:
			id = int(v)
		case int:
			id = v
		case string:
			id, _ = strconv.Atoi(strings.TrimSpace(v))
		}
		if id != taskID {
			continue
		}
		st, _ := t["status"].(string)
		if strings.EqualFold(strings.TrimSpace(st), "succeeded") ||
			strings.EqualFold(strings.TrimSpace(st), "success") ||
			strings.EqualFold(strings.TrimSpace(st), "failed") ||
			strings.EqualFold(strings.TrimSpace(st), "failure") ||
			strings.EqualFold(strings.TrimSpace(st), "error") ||
			strings.EqualFold(strings.TrimSpace(st), "canceled") {
			er, _ := t["error"].(string)
			return strings.TrimSpace(st), strings.TrimSpace(er), pollTerminal
		}
		return strings.TrimSpace(st), "", pollNonTerminal
	}
	return "", "", pollMissing
}

func fetchRunOutput(client *http.Client, baseURL string, cookie string, workspaceID string, taskID int) (string, error) {
	if taskID <= 0 {
		return "", fmt.Errorf("invalid task id")
	}
	url := fmt.Sprintf("%s/api/runs/%d/output?workspace_id=%s", strings.TrimRight(baseURL, "/"), taskID, strings.TrimSpace(workspaceID))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("output fetch failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		Output []struct {
			Output string `json:"output"`
			Time   string `json:"time"`
			Stream string `json:"stream"`
		} `json:"output"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	lines := make([]string, 0, len(out.Output))
	for _, row := range out.Output {
		if s := strings.TrimRight(row.Output, "\n"); s != "" {
			lines = append(lines, s)
		}
	}
	return strings.Join(lines, "\n"), nil
}

func resolveDefaultCollectorPod(client *http.Client, baseURL string, cookie string) (collectorConfigID string, namespace string, podName string, err error) {
	// Explicit override (useful when running e2e as a user that doesn't have a collector configured).
	if pod := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_COLLECTOR_POD")); pod != "" {
		ns := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_COLLECTOR_NAMESPACE"))
		if ns == "" {
			ns = "skyforge"
		}
		return "", ns, pod, nil
	}

	resp, body, err := doJSON(client, http.MethodGet, baseURL+"/api/forward/collector-configs", nil, map[string]string{"Cookie": cookie})
	if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var decoded listCollectorsResponse
		if json.Unmarshal(body, &decoded) == nil {
			var bestID string
			var bestRuntime *collectorRuntimeStatus
			bestDefault := false
			for _, c := range decoded.Collectors {
				if c.Runtime == nil || !c.Runtime.Ready || strings.TrimSpace(c.Runtime.PodName) == "" {
					continue
				}
				if bestRuntime == nil || (c.IsDefault && !bestDefault) {
					bestID = strings.TrimSpace(c.ID)
					bestRuntime = c.Runtime
					bestDefault = c.IsDefault
				}
			}
			if bestRuntime != nil {
				return bestID, strings.TrimSpace(bestRuntime.Namespace), strings.TrimSpace(bestRuntime.PodName), nil
			}
		}
	}

	resp, body, err = doJSON(client, http.MethodGet, baseURL+"/api/forward/collector/runtime", nil, map[string]string{"Cookie": cookie})
	if err != nil {
		return "", "", "", fmt.Errorf("collector runtime lookup failed: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", "", fmt.Errorf("collector runtime lookup failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var decoded userCollectorRuntimeResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", "", "", fmt.Errorf("collector runtime parse failed: %v", err)
	}
	if decoded.Runtime == nil || !decoded.Runtime.Ready || strings.TrimSpace(decoded.Runtime.PodName) == "" {
		// If we want to probe SSH from within the Forward collector pod, bootstrap the user's
		// Forward collector settings (which also ensures the in-cluster collector exists).
		//
		// This keeps E2E self-contained even if the admin user hasn't configured Forward yet.
		if getenvBool("SKYFORGE_E2E_BOOTSTRAP_COLLECTOR", true) && strings.EqualFold(sshProbeMode(), "collector_exec") {
			fwdUser := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_FORWARD_USERNAME"))
			fwdPass := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_FORWARD_PASSWORD"))
			if fwdUser == "" || fwdPass == "" {
				return "", "", "", fmt.Errorf("collector not ready (set SKYFORGE_E2E_FORWARD_USERNAME/SKYFORGE_E2E_FORWARD_PASSWORD to auto-bootstrap)")
			}
			fwdBase := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_FORWARD_BASE_URL"))
			if fwdBase == "" {
				fwdBase = "https://fwd.app"
			}

			_, _, _ = doJSON(client, http.MethodPut, baseURL+"/api/forward/collector", putUserForwardCollectorRequest{
				BaseURL:       fwdBase,
				SkipTLSVerify: getenvBool("SKYFORGE_E2E_FORWARD_SKIP_TLS_VERIFY", false),
				Username:      fwdUser,
				Password:      fwdPass,
			}, map[string]string{"Cookie": cookie})

			// Wait for the runtime to become ready.
			deadline := time.Now().Add(10 * time.Minute)
			for time.Now().Before(deadline) {
				resp2, body2, err2 := doJSON(client, http.MethodGet, baseURL+"/api/forward/collector/runtime", nil, map[string]string{"Cookie": cookie})
				if err2 == nil && resp2.StatusCode >= 200 && resp2.StatusCode < 300 {
					var rr userCollectorRuntimeResponse
					if json.Unmarshal(body2, &rr) == nil && rr.Runtime != nil && rr.Runtime.Ready && strings.TrimSpace(rr.Runtime.PodName) != "" {
						return "", strings.TrimSpace(rr.Runtime.Namespace), strings.TrimSpace(rr.Runtime.PodName), nil
					}
				}
				time.Sleep(5 * time.Second)
			}
			return "", "", "", fmt.Errorf("collector not ready after bootstrap wait")
		}
		return "", "", "", fmt.Errorf("collector not ready")
	}
	return "", strings.TrimSpace(decoded.Runtime.Namespace), strings.TrimSpace(decoded.Runtime.PodName), nil
}

func findAnyCollectorPodViaKubectl(ctx context.Context) (collectorConfigID string, namespace string, podName string, err error) {
	type podList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}

	ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx2, "kubectl", "get", "pods", "-A", "-l", "app.kubernetes.io/component=collector", "-o", "json")
	cmd.Env = kubectlEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", "", fmt.Errorf("kubectl get collector pods failed: %s", strings.TrimSpace(string(out)))
	}
	var decoded podList
	if err := json.Unmarshal(out, &decoded); err != nil {
		return "", "", "", fmt.Errorf("kubectl pods json parse failed: %v", err)
	}
	for _, item := range decoded.Items {
		if strings.EqualFold(strings.TrimSpace(item.Status.Phase), "running") &&
			strings.TrimSpace(item.Metadata.Name) != "" &&
			strings.TrimSpace(item.Metadata.Namespace) != "" {
			return "", strings.TrimSpace(item.Metadata.Namespace), strings.TrimSpace(item.Metadata.Name), nil
		}
	}
	return "", "", "", fmt.Errorf("no collector pods found in cluster")
}

func waitForCollectorSSH(ctx context.Context, namespace string, pod string, hosts []string, timeout time.Duration) error {
	if len(hosts) == 0 {
		return fmt.Errorf("no hosts")
	}
	namespace = strings.TrimSpace(namespace)
	pod = strings.TrimSpace(pod)
	if namespace == "" || pod == "" {
		return fmt.Errorf("collector namespace/pod missing")
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	deadline := time.Now().Add(timeout)

	pending := map[string]struct{}{}
	lastErr := map[string]string{}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h != "" {
			pending[h] = struct{}{}
		}
	}

	verbose := false
	if v := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_VERBOSE")); v != "" {
		verbose = strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
	}

	maxParallel := 8
	if v := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_SSH_PARALLEL")); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 64 {
			maxParallel = parsed
		}
	}
	if maxParallel > len(pending) && len(pending) > 0 {
		maxParallel = len(pending)
	}

	lastProgress := time.Time{}
	for len(pending) > 0 {
		if time.Now().After(deadline) {
			rest := make([]string, 0, len(pending))
			for h := range pending {
				rest = append(rest, h)
			}
			sort.Strings(rest)
			lines := make([]string, 0, len(rest))
			for _, h := range rest {
				if e := strings.TrimSpace(lastErr[h]); e != "" {
					lines = append(lines, fmt.Sprintf("%s: %s", h, e))
				} else {
					lines = append(lines, fmt.Sprintf("%s: (no error captured)", h))
				}
			}
			return fmt.Errorf("timeout waiting for ssh banner (remaining=%v)\n%s", rest, strings.Join(lines, "\n"))
		}
		if verbose && (lastProgress.IsZero() || time.Since(lastProgress) > 15*time.Second) {
			fmt.Printf("waitForCollectorSSH: remaining=%d (parallel=%d)\n", len(pending), maxParallel)
			lastProgress = time.Now()
		}

		type probeResult struct {
			host string
			ok   bool
			err  error
		}
		results := make(chan probeResult, len(pending))
		sem := make(chan struct{}, maxParallel)
		var wg sync.WaitGroup

		for host := range pending {
			host := host
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				ok, err := collectorSSHBannerOnce(ctx, namespace, pod, host)
				results <- probeResult{host: host, ok: ok, err: err}
			}()
		}

		wg.Wait()
		close(results)
		for r := range results {
			if r.ok {
				delete(pending, r.host)
				delete(lastErr, r.host)
				continue
			}
			if r.err != nil {
				lastErr[r.host] = r.err.Error()
			}
		}
		time.Sleep(2 * time.Second)
	}
	return nil
}

func collectorSSHBannerOnce(ctx context.Context, namespace string, pod string, host string) (bool, error) {
	script := `set -euo pipefail
host="$1"
set +e
out="$(timeout 10 bash -c 'exec 3<>/dev/tcp/${1}/22; dd bs=1 count=4 <&3 2>/dev/null' _ "$host" 2>&1)"
rc="$?"
set -e
if [ "$rc" = "0" ] && [ "$out" = "SSH-" ]; then
  exit 0
fi
echo "ssh_probe_failed rc=${rc} out=${out}" 1>&2
exit 2
`
	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx2, "kubectl", "-n", namespace, "exec", pod, "--", "bash", "-lc", script, "--", host)
	cmd.Env = kubectlEnv()
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	return false, fmt.Errorf("%s", strings.TrimSpace(string(out)))
}

func run() int {
	var (
		flagGenerateMatrix = flag.Bool("generate-matrix", false, "Print a generated E2E matrix to stdout (does not run tests)")
		flagRunGenerated   = flag.Bool("run-generated", false, "Generate an E2E matrix from the Skyforge netlab device catalog and run it")
	)
	flag.Parse()

	if *flagGenerateMatrix {
		catalogPath := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_NETLAB_DEVICE_DEFAULTS_FILE"))
		if catalogPath == "" {
			catalogPath = "internal/taskengine/netlab_device_defaults.json"
		}
		gen, err := generateMatrixFromCatalog(catalogPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate matrix from %s: %v\n", catalogPath, err)
			return 2
		}
		enc := yaml.NewEncoder(os.Stdout)
		enc.SetIndent(2)
		_ = enc.Encode(gen)
		_ = enc.Close()
		return 0
	}

	baseURL := strings.TrimRight(getenv("SKYFORGE_BASE_URL", "https://skyforge.local.forwardnetworks.com"), "/")
	username := getenv("SKYFORGE_E2E_USERNAME", getenv("SKYFORGE_SMOKE_USERNAME", "skyforge"))
	password := mustEnv("SKYFORGE_E2E_PASSWORD")
	if password == "" {
		password = mustEnv("SKYFORGE_SMOKE_PASSWORD")
	}
	if password == "" {
		secretsPath := strings.TrimSpace(getenv("SKYFORGE_SECRETS_FILE", "../deploy/skyforge-secrets.yaml"))
		abs, _ := filepath.Abs(secretsPath)
		loaded, err := loadPasswordFromSecretsFile(abs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "missing SKYFORGE_E2E_PASSWORD and failed to load from %s: %v\n", abs, err)
			return 2
		}
		password = loaded
	}

	timeout := 2 * time.Minute
	if v := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_HTTP_TIMEOUT")); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil && parsed > 0 {
			timeout = parsed
		}
	}
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	dialer := newDNSCacheDialer()
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     dialer.DialContext,
		// Keep a small pool of idle conns; e2echeck is chatty (polling + SSE + probes).
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
	}
	client := &http.Client{Timeout: timeout, Transport: tr}

	healthURL := baseURL + "/healthz"
	resp, body, err := doJSON(client, http.MethodGet, healthURL, nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "health request failed: %v\n", err)
		return 1
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "health failed: %s\n", strings.TrimSpace(string(body)))
		return 1
	}
	fmt.Printf("OK health: %s\n", healthURL)

	loginURL := baseURL + "/api/login"
	resp, body, err = doJSON(client, http.MethodPost, loginURL, loginRequest{Username: username, Password: password}, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "login request failed: %v\n", err)
		return 1
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "login failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		return 1
	}
	cookie := resp.Header.Get("Set-Cookie")
	if strings.TrimSpace(cookie) == "" {
		fmt.Fprintln(os.Stderr, "login missing Set-Cookie header")
		return 1
	}
	fmt.Printf("OK login: %s\n", username)

	wsReuseID := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_WORKSPACE_ID"))
	var ws workspaceResponse
	if wsReuseID != "" {
		resp, body, err := doJSON(client, http.MethodGet, baseURL+"/api/workspaces", nil, map[string]string{"Cookie": cookie})
		if err != nil {
			fmt.Fprintf(os.Stderr, "workspace list request failed: %v\n", err)
			return 1
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			fmt.Fprintf(os.Stderr, "workspace list failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
			return 1
		}
		var lr listWorkspacesResponse
		if err := json.Unmarshal(body, &lr); err != nil {
			fmt.Fprintf(os.Stderr, "workspace list parse failed: %v\n", err)
			return 1
		}
		found := false
		for _, w := range lr.Workspaces {
			if strings.TrimSpace(w.ID) == wsReuseID {
				ws = w
				found = true
				break
			}
		}
		if !found || strings.TrimSpace(ws.ID) == "" {
			fmt.Fprintf(os.Stderr, "workspace %q not found; set SKYFORGE_E2E_WORKSPACE_ID to an existing workspace id\n", wsReuseID)
			return 1
		}
		fmt.Printf("OK workspace reuse: %s (%s)\n", ws.Name, ws.ID)
	} else {
		wsName := fmt.Sprintf("e2e-%s", time.Now().UTC().Format("20060102-150405"))
		createURL := baseURL + "/api/workspaces"
		resp, body, err = doJSON(client, http.MethodPost, createURL, workspaceCreateRequest{Name: wsName}, map[string]string{"Cookie": cookie})
		if err != nil {
			fmt.Fprintf(os.Stderr, "workspace create request failed: %v\n", err)
			return 1
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			fmt.Fprintf(os.Stderr, "workspace create failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
			return 1
		}
		if err := json.Unmarshal(body, &ws); err != nil {
			fmt.Fprintf(os.Stderr, "workspace create parse failed: %v\n", err)
			return 1
		}
		if strings.TrimSpace(ws.ID) == "" {
			fmt.Fprintf(os.Stderr, "workspace create returned empty id: %s\n", strings.TrimSpace(string(body)))
			return 1
		}
		fmt.Printf("OK workspace create: %s (%s)\n", ws.Name, ws.ID)
	}

	var statusRec *e2eStatusRecorder
	var runLog *e2eRunLogger
	statusDir := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_STATUS_DIR"))
	if statusDir == "" {
		statusDir = "../docs"
	}
	if err := os.MkdirAll(statusDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to create statusDir %q: %v\n", statusDir, err)
	}
	if abs, err := filepath.Abs(statusDir); err == nil {
		fmt.Printf("OK e2echeck: statusDir=%s\n", abs)
	} else {
		fmt.Printf("OK e2echeck: statusDir=%s\n", statusDir)
	}

	if getenvBool("SKYFORGE_E2E_STATUS_ENABLED", true) {
		rl, err := newE2ERunLogger(filepath.Join(statusDir, "e2e-runlog.jsonl"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to init e2e run logger (%s): %v\n", filepath.Join(statusDir, "e2e-runlog.jsonl"), err)
		} else {
			runLog = rl
		}
		rec, err := newE2EStatusRecorder(
			filepath.Join(statusDir, "e2e-reachability-status.json"),
			filepath.Join(statusDir, "e2e-reachability-status.md"),
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to init e2e status recorder (%s): %v\n", statusDir, err)
		} else {
			statusRec = rec
		}
	}
	if statusRec != nil {
		// Keep the status file aligned with the device types Skyforge exposes.
		// This also prunes stale/renamed device keys from earlier runs.
		statusRec.syncDeviceSet(onboardedNetlabDevices())

		defer func() {
			if err := statusRec.flush(); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to write e2e status: %v\n", err)
			}
		}()
	}

	workspaceCleanup := true
	if v, ok := getenvBoolOK("SKYFORGE_E2E_WORKSPACE_CLEANUP"); ok {
		workspaceCleanup = v
	}

	if wsReuseID == "" {
		_ = appendCreatedWorkspace(statusDir, createdWorkspaceRecord{
			BaseURL:         strings.TrimRight(baseURL, "/"),
			WorkspaceID:     ws.ID,
			WorkspaceSlug:   ws.Slug,
			WorkspaceName:   ws.Name,
			CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		})
	}

	if wsReuseID == "" && workspaceCleanup {
		var deleteOnce sync.Once
		cleanup := func(reason string) {
			deleteOnce.Do(func() {
				if err := deleteWorkspaceByID(client, baseURL, cookie, ws.ID, ws.Slug); err != nil {
					fmt.Fprintf(os.Stderr, "warning: workspace delete failed (%s): %v\n", reason, err)
					return
				}
				_ = removeCreatedWorkspace(statusDir, ws.ID)
				fmt.Printf("OK workspace delete: %s\n", ws.ID)
			})
		}

		sigCh := make(chan os.Signal, 2)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigCh
			cleanup(fmt.Sprintf("signal=%s", sig.String()))
			os.Exit(130)
		}()

		defer func() {
			cleanup("defer")
		}()
	} else if wsReuseID == "" && !workspaceCleanup {
		fmt.Printf("SKIP workspace delete: SKYFORGE_E2E_WORKSPACE_CLEANUP=false (workspaceId=%s)\n", ws.ID)
	}

	var m matrixFile
	if *flagRunGenerated {
		catalogPath := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_NETLAB_DEVICE_DEFAULTS_FILE"))
		if catalogPath == "" {
			catalogPath = "internal/taskengine/netlab_device_defaults.json"
		}
		gen, err := generateMatrixFromCatalog(catalogPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to generate matrix from %s: %v\n", catalogPath, err)
			return 2
		}
		m = gen
	} else {
		matrixPath := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_MATRIX_FILE"))
		if matrixPath == "" {
			fmt.Println("OK e2echeck: no SKYFORGE_E2E_MATRIX_FILE set (skipping template validation)")
			return 0
		}
		raw, err := os.ReadFile(matrixPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read matrix file %s: %v\n", matrixPath, err)
			return 2
		}
		if err := yaml.Unmarshal(raw, &m); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse matrix file %s: %v\n", matrixPath, err)
			return 2
		}
	}

	// Even when running a static matrix file, allow the caller to:
	// - Select a subset of device types (SKYFORGE_E2E_DEVICES)
	// - Gate deploy tests separately (SKYFORGE_E2E_DEPLOY)
	// - Further restrict deploy tests (SKYFORGE_E2E_DEPLOY_DEVICES)
	deviceFilter := splitCSVEnv("SKYFORGE_E2E_DEVICES")
	deployEnabled := getenvBool("SKYFORGE_E2E_DEPLOY", false)
	deployDeviceFilter := splitCSVEnv("SKYFORGE_E2E_DEPLOY_DEVICES")
	verbose := getenvBool("SKYFORGE_E2E_VERBOSE", false)

	exitCode := 0
	for _, t := range m.Tests {
		name := strings.TrimSpace(t.Name)
		kind := strings.TrimSpace(t.Kind)
		if name == "" {
			name = kind
		}

		// Extract device type from the test's environment, if present.
		// This is used for selective runs and for the persistent status file.
		device := ""
		switch kind {
		case "netlab_validate":
			if t.NetlabValidate != nil && t.NetlabValidate.Environment != nil {
				device = strings.TrimSpace(t.NetlabValidate.Environment["NETLAB_DEVICE"])
			}
		case "netlab_deploy", "netlab_byos_deploy":
			if t.NetlabDeploy != nil && t.NetlabDeploy.Environment != nil {
				device = strings.TrimSpace(t.NetlabDeploy.Environment["NETLAB_DEVICE"])
			}
		case "containerlab_byos_deploy":
			if t.ContainerlabDeploy != nil && t.ContainerlabDeploy.Environment != nil {
				device = strings.TrimSpace(t.ContainerlabDeploy.Environment["NETLAB_DEVICE"])
			}
		}

		if len(deviceFilter) > 0 {
			if device == "" || !containsSetCI(deviceFilter, device) {
				if verbose {
					fmt.Printf("SKIP %s: device=%q filtered by SKYFORGE_E2E_DEVICES\n", name, device)
				}
				if statusRec != nil && device != "" {
					statusRec.update(device, "skip", "", "", 0, "", "skipped by SKYFORGE_E2E_DEVICES filter")
				}
				continue
			}
		}

		switch kind {
		case "netlab_deploy", "netlab_byos_deploy", "containerlab_byos_deploy":
			if !deployEnabled {
				if verbose {
					fmt.Printf("SKIP %s: deploy disabled (set SKYFORGE_E2E_DEPLOY=true)\n", name)
				}
				if statusRec != nil && device != "" {
					statusRec.update(device, "skip", "", "", 0, "", "deploy disabled (SKYFORGE_E2E_DEPLOY=false)")
				}
				continue
			}
			if len(deployDeviceFilter) > 0 && device != "" && !containsSetCI(deployDeviceFilter, device) {
				if verbose {
					fmt.Printf("SKIP %s: deploy device=%q filtered by SKYFORGE_E2E_DEPLOY_DEVICES\n", name, device)
				}
				if statusRec != nil && device != "" {
					statusRec.update(device, "skip", "", "", 0, "", "skipped by SKYFORGE_E2E_DEPLOY_DEVICES filter")
				}
				continue
			}
		}

		switch kind {
		case "netlab_validate":
			if t.NetlabValidate == nil {
				fmt.Fprintf(os.Stderr, "test %q: missing netlab_validate section\n", name)
				return 2
			}
			reqIn := netlabValidateRequest{
				Source:       strings.TrimSpace(t.NetlabValidate.Source),
				Repo:         strings.TrimSpace(t.NetlabValidate.Repo),
				Dir:          strings.TrimSpace(t.NetlabValidate.Dir),
				Template:     strings.TrimSpace(t.NetlabValidate.Template),
				Environment:  t.NetlabValidate.Environment,
				SetOverrides: t.NetlabValidate.SetOverrides,
			}
			if reqIn.Environment == nil {
				reqIn.Environment = map[string]string{}
			}
			if reqIn.SetOverrides == nil {
				reqIn.SetOverrides = []string{}
			}
			timeoutStr := strings.TrimSpace(t.NetlabValidate.Timeout)
			wait := 10 * time.Minute
			if timeoutStr != "" {
				if parsed, err := time.ParseDuration(timeoutStr); err == nil && parsed > 0 {
					wait = parsed
				}
			}
			url := fmt.Sprintf("%s/api/workspaces/%s/netlab/validate", baseURL, ws.ID)
			resp, body, err := doJSON(client, http.MethodPost, url, reqIn, map[string]string{"Cookie": cookie})
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: request failed: %v\n", name, err)
				return 1
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "test %q: validate failed (%d): %s\n", name, resp.StatusCode, strings.TrimSpace(string(body)))
				return 1
			}
			var out netlabValidateResponse
			if err := json.Unmarshal(body, &out); err != nil {
				fmt.Fprintf(os.Stderr, "test %q: validate response parse failed: %v\n", name, err)
				return 1
			}
			taskID := parseTaskID(out.Task)
			if taskID <= 0 {
				fmt.Fprintf(os.Stderr, "test %q: validate returned missing task id: %s\n", name, strings.TrimSpace(string(body)))
				return 1
			}
			fmt.Printf("OK %s: task=%d (waiting)\n", name, taskID)

			// Use a separate client without request timeout to allow long-lived SSE.
			sseClient := &http.Client{Transport: tr}
			status, errMsg, err := waitForTaskFinished(sseClient, baseURL, cookie, ws.ID, taskID, wait)
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: wait failed: %v\n", name, err)
				return 1
			}
			switch strings.ToLower(strings.TrimSpace(status)) {
			case "succeeded", "success":
			default:
				fmt.Fprintf(os.Stderr, "test %q: task finished with status=%q error=%q\n", name, status, errMsg)
				if output, err := fetchRunOutput(client, baseURL, cookie, ws.ID, taskID); err == nil && strings.TrimSpace(output) != "" {
					fmt.Fprintf(os.Stderr, "--- task %d output ---\n%s\n--- end output ---\n", taskID, output)
				}
				exitCode = 1
				continue
			}
			fmt.Printf("OK %s: succeeded\n", name)
		case "netlab_deploy":
			if t.NetlabDeploy == nil {
				fmt.Fprintf(os.Stderr, "test %q: missing netlab_deploy section\n", name)
				return 2
			}
			testFailed := false
			device := ""
			if t.NetlabDeploy.Environment != nil {
				device = strings.TrimSpace(t.NetlabDeploy.Environment["NETLAB_DEVICE"])
			}

			deployType := strings.ToLower(strings.TrimSpace(t.NetlabDeploy.Type))
			if deployType == "" {
				deployType = "netlab-c9s"
			}
			if deployType != "netlab-c9s" {
				fmt.Fprintf(os.Stderr, "test %q: unsupported deploy type %q\n", name, deployType)
				return 2
			}

			wait := 25 * time.Minute
			if timeoutStr := strings.TrimSpace(t.NetlabDeploy.Timeout); timeoutStr != "" {
				if parsed, err := time.ParseDuration(timeoutStr); err == nil && parsed > 0 {
					wait = parsed
				}
			}
			sshWait := 10 * time.Minute
			if timeoutStr := strings.TrimSpace(t.NetlabDeploy.SSHTimeout); timeoutStr != "" {
				if parsed, err := time.ParseDuration(timeoutStr); err == nil && parsed > 0 {
					sshWait = parsed
				}
			}

			cfg := map[string]any{
				"templateSource": strings.TrimSpace(t.NetlabDeploy.Source),
				"templateRepo":   strings.TrimSpace(t.NetlabDeploy.Repo),
				"templatesDir":   strings.TrimSpace(t.NetlabDeploy.Dir),
				"template":       strings.TrimSpace(t.NetlabDeploy.Template),
				"environment":    t.NetlabDeploy.Environment,
			}
			if cfg["templateSource"] == "" {
				cfg["templateSource"] = "blueprints"
			}
			if cfg["templatesDir"] == "" {
				cfg["templatesDir"] = "netlab/_e2e/minimal"
			}
			if cfg["template"] == "" {
				cfg["template"] = "topology.yml"
			}
			if len(t.NetlabDeploy.SetOverrides) > 0 {
				cfg["netlabSetOverrides"] = t.NetlabDeploy.SetOverrides
			}

			templateName := strings.TrimSpace(t.NetlabDeploy.Dir)
			if templateName == "" {
				templateName = "netlab/_e2e/minimal"
			}

			depName := strings.TrimPrefix(strings.ToLower(name), "netlab-deploy-")
			if depName == "" {
				depName = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
			}
			depName = strings.Trim(depName, "-")
			// When reusing a workspace across runs, avoid deployment name collisions by default.
			deploySuffix := strings.TrimSpace(os.Getenv("SKYFORGE_E2E_DEPLOY_SUFFIX"))
			if deploySuffix == "" && strings.TrimSpace(os.Getenv("SKYFORGE_E2E_WORKSPACE_ID")) != "" {
				deploySuffix = fmt.Sprintf("r%d", time.Now().Unix()%100000)
			}
			if deploySuffix != "" {
				depName = strings.Trim(depName+"-"+deploySuffix, "-")
			}
			if len(depName) > 40 {
				depName = depName[:40]
				depName = strings.Trim(depName, "-")
			}
			if depName == "" {
				depName = "e2e"
			}

			createDepURL := fmt.Sprintf("%s/api/workspaces/%s/deployments", baseURL, ws.ID)
			resp, body, err := doJSON(client, http.MethodPost, createDepURL, deploymentCreateRequest{
				Name:   depName,
				Type:   deployType,
				Config: cfg,
			}, map[string]string{"Cookie": cookie})
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: create deployment request failed: %v\n", name, err)
				return 1
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "test %q: create deployment failed (%d): %s\n", name, resp.StatusCode, strings.TrimSpace(string(body)))
				return 1
			}
			var dep deploymentResponse
			if err := json.Unmarshal(body, &dep); err != nil {
				fmt.Fprintf(os.Stderr, "test %q: create deployment parse failed: %v\n", name, err)
				return 1
			}
			if strings.TrimSpace(dep.ID) == "" {
				fmt.Fprintf(os.Stderr, "test %q: create deployment returned empty id\n", name)
				return 1
			}

			needCollector := sshProbeMode() == "collector_exec" || getenvBool("SKYFORGE_E2E_FORWARD", false)
			collectorConfigID, collectorNS, collectorPod := "", "", ""
			if needCollector {
				var err error
				collectorConfigID, collectorNS, collectorPod, err = resolveDefaultCollectorPod(client, baseURL, cookie)
				if err != nil {
					fmt.Fprintf(os.Stderr, "test %q: collector resolve failed: %v\n", name, err)
					return 1
				}
				if sshProbeMode() == "collector_exec" {
					if err := kubectlAvailable(context.Background()); err != nil {
						fmt.Fprintf(os.Stderr, "test %q: kubectl is required for collector_exec ssh probe but is not working.\n%s\n", name, err)
						return 1
					}
				}
			}

			// Best-effort: enable Forward on this deployment so we also exercise Forward sync plumbing.
			if getenvBool("SKYFORGE_E2E_FORWARD", false) && strings.TrimSpace(collectorConfigID) != "" {
				fwdCfgURL := fmt.Sprintf("%s/api/workspaces/%s/deployments/%s/forward", baseURL, ws.ID, dep.ID)
				resp, body, err = doJSON(client, http.MethodPut, fwdCfgURL, deploymentForwardConfigRequest{
					Enabled:           true,
					CollectorConfigID: collectorConfigID,
				}, map[string]string{"Cookie": cookie})
				if err != nil {
					fmt.Fprintf(os.Stderr, "test %q: forward config request failed: %v\n", name, err)
					return 1
				}
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					fmt.Fprintf(os.Stderr, "test %q: forward config failed (%d): %s\n", name, resp.StatusCode, strings.TrimSpace(string(body)))
					return 1
				}
			}

			startURL := fmt.Sprintf("%s/api/workspaces/%s/deployments/%s/start", baseURL, ws.ID, dep.ID)
			resp, body, err = doJSON(client, http.MethodPost, startURL, map[string]any{}, map[string]string{"Cookie": cookie})
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: start deployment request failed: %v\n", name, err)
				return 1
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "test %q: start deployment failed (%d): %s\n", name, resp.StatusCode, strings.TrimSpace(string(body)))
				return 1
			}
			var out deploymentActionResponse
			if err := json.Unmarshal(body, &out); err != nil {
				fmt.Fprintf(os.Stderr, "test %q: start response parse failed: %v\n", name, err)
				return 1
			}
			taskID := parseTaskID(out.Run)
			if taskID <= 0 {
				fmt.Fprintf(os.Stderr, "test %q: start returned missing task id\n", name)
				return 1
			}
			fmt.Printf("OK %s: task=%d (waiting)\n", name, taskID)

			sseClient := &http.Client{Transport: tr}
			status, errMsg, err := waitForTaskFinished(sseClient, baseURL, cookie, ws.ID, taskID, wait)
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: wait failed: %v\n", name, err)
				return 1
			}
			switch strings.ToLower(strings.TrimSpace(status)) {
			case "succeeded", "success":
			default:
				fmt.Fprintf(os.Stderr, "test %q: deployment task finished with status=%q error=%q\n", name, status, errMsg)
				if statusRec != nil && device != "" {
					statusRec.update(device, "fail", templateName, deployType, taskID, errMsg, "deployment failed")
					_ = statusRec.flush()
				}
				if runLog != nil {
					runLog.append(e2eRunLogEntry{
						BaseURL:     baseURL,
						Workspace:   ws.Name,
						WorkspaceID: ws.ID,
						Test:        name,
						Kind:        kind,
						Device:      device,
						Template:    templateName,
						DeployType:  deployType,
						TaskID:      taskID,
						Status:      "fail",
						Error:       errMsg,
						Notes:       "deployment failed",
					})
				}
				if output, err := fetchRunOutput(client, baseURL, cookie, ws.ID, taskID); err == nil && strings.TrimSpace(output) != "" {
					fmt.Fprintf(os.Stderr, "--- task %d output ---\n%s\n--- end output ---\n", taskID, output)
				}
				exitCode = 1
				testFailed = true
			}

			if !testFailed && sshWait > 0 && getenvBool("SKYFORGE_E2E_SSH_PROBE", true) {
				topURL := fmt.Sprintf("%s/api/workspaces/%s/deployments/%s/topology", baseURL, ws.ID, dep.ID)
				resp, body, err = doJSON(client, http.MethodGet, topURL, nil, map[string]string{"Cookie": cookie})
				if err != nil {
					fmt.Fprintf(os.Stderr, "test %q: topology request failed: %v\n", name, err)
					exitCode = 1
					testFailed = true
				} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					fmt.Fprintf(os.Stderr, "test %q: topology failed (%d): %s\n", name, resp.StatusCode, strings.TrimSpace(string(body)))
					exitCode = 1
					testFailed = true
				} else {
					var topo deploymentTopologyResponse
					if err := json.Unmarshal(body, &topo); err != nil {
						fmt.Fprintf(os.Stderr, "test %q: topology parse failed: %v\n", name, err)
						exitCode = 1
						testFailed = true
					} else {
						hosts := []string{}
						for _, n := range topo.Nodes {
							if ip := strings.TrimSpace(n.MgmtIP); ip != "" {
								hosts = append(hosts, ip)
							}
						}
						if len(hosts) == 0 {
							fmt.Fprintf(os.Stderr, "test %q: no mgmt IPs in topology\n", name)
							exitCode = 1
							testFailed = true
						} else {
							switch sshProbeMode() {
							case "collector_exec":
								if err := waitForCollectorSSH(context.Background(), collectorNS, collectorPod, hosts, sshWait); err != nil {
									fmt.Fprintf(os.Stderr, "test %q: collector ssh banner failed: %v\n", name, err)
									if statusRec != nil && device != "" {
										statusRec.update(device, "fail", templateName, deployType, taskID, err.Error(), "collector ssh probe failed")
										_ = statusRec.flush()
									}
									if runLog != nil {
										runLog.append(e2eRunLogEntry{
											BaseURL:     baseURL,
											Workspace:   ws.Name,
											WorkspaceID: ws.ID,
											Test:        name,
											Kind:        kind,
											Device:      device,
											Template:    templateName,
											DeployType:  deployType,
											TaskID:      taskID,
											Status:      "fail",
											Error:       err.Error(),
											Notes:       "collector ssh probe failed",
										})
									}
									exitCode = 1
									testFailed = true
								} else {
									fmt.Printf("OK %s: collector ssh ok (hosts=%d)\n", name, len(hosts))
									if statusRec != nil && device != "" {
										statusRec.update(device, "pass", templateName, deployType, taskID, "", "deploy+collector-ssh ok")
										_ = statusRec.flush()
									}
									if runLog != nil {
										runLog.append(e2eRunLogEntry{
											BaseURL:     baseURL,
											Workspace:   ws.Name,
											WorkspaceID: ws.ID,
											Test:        name,
											Kind:        kind,
											Device:      device,
											Template:    templateName,
											DeployType:  deployType,
											TaskID:      taskID,
											Status:      "pass",
											Notes:       "deploy+collector-ssh ok",
										})
									}
								}
							case "job":
								probeNS := strings.TrimSpace(collectorNS)
								if probeNS == "" {
									probeNS = "skyforge"
								}
								if err := waitForSSHProbeJob(context.Background(), probeNS, hosts, sshWait); err != nil {
									fmt.Fprintf(os.Stderr, "test %q: ssh probe job failed: %v\n", name, err)
									if statusRec != nil && device != "" {
										statusRec.update(device, "fail", templateName, deployType, taskID, err.Error(), "ssh probe job failed")
										_ = statusRec.flush()
									}
									if runLog != nil {
										runLog.append(e2eRunLogEntry{
											BaseURL:     baseURL,
											Workspace:   ws.Name,
											WorkspaceID: ws.ID,
											Test:        name,
											Kind:        kind,
											Device:      device,
											Template:    templateName,
											DeployType:  deployType,
											TaskID:      taskID,
											Status:      "fail",
											Error:       err.Error(),
											Notes:       "ssh probe job failed",
										})
									}
									exitCode = 1
									testFailed = true
								} else {
									fmt.Printf("OK %s: ssh probe ok (namespace=%s hosts=%d)\n", name, probeNS, len(hosts))
									if statusRec != nil && device != "" {
										statusRec.update(device, "pass", templateName, deployType, taskID, "", "deploy+ssh probe job ok")
										_ = statusRec.flush()
									}
									if runLog != nil {
										runLog.append(e2eRunLogEntry{
											BaseURL:     baseURL,
											Workspace:   ws.Name,
											WorkspaceID: ws.ID,
											Test:        name,
											Kind:        kind,
											Device:      device,
											Template:    templateName,
											DeployType:  deployType,
											TaskID:      taskID,
											Status:      "pass",
											Notes:       "deploy+ssh probe job ok",
										})
									}
								}
							default:
								if err := waitForSSHProbeAPIForDevice(context.Background(), client, baseURL, cookie, device, hosts, sshWait); err != nil {
									fmt.Fprintf(os.Stderr, "test %q: ssh probe api failed: %v\n", name, err)
									if statusRec != nil && device != "" {
										statusRec.update(device, "fail", templateName, deployType, taskID, err.Error(), "ssh probe failed")
										_ = statusRec.flush()
									}
									if runLog != nil {
										runLog.append(e2eRunLogEntry{
											BaseURL:     baseURL,
											Workspace:   ws.Name,
											WorkspaceID: ws.ID,
											Test:        name,
											Kind:        kind,
											Device:      device,
											Template:    templateName,
											DeployType:  deployType,
											TaskID:      taskID,
											Status:      "fail",
											Error:       err.Error(),
											Notes:       "ssh probe api failed",
										})
									}
									exitCode = 1
									testFailed = true
								} else {
									fmt.Printf("OK %s: ssh probe ok (api hosts=%d)\n", name, len(hosts))
									if statusRec != nil && device != "" {
										statusRec.update(device, "pass", templateName, deployType, taskID, "", "deploy+ssh ok")
										_ = statusRec.flush()
									}
									if runLog != nil {
										runLog.append(e2eRunLogEntry{
											BaseURL:     baseURL,
											Workspace:   ws.Name,
											WorkspaceID: ws.ID,
											Test:        name,
											Kind:        kind,
											Device:      device,
											Template:    templateName,
											DeployType:  deployType,
											TaskID:      taskID,
											Status:      "pass",
											Notes:       "deploy+ssh ok",
										})
									}
								}
							}
						}
					}
				}
			}

			cleanup := t.NetlabDeploy.Cleanup
			if v, ok := getenvBoolOK("SKYFORGE_E2E_CLEANUP"); ok {
				cleanup = v
			}
			if cleanup {
				destroyURL := fmt.Sprintf("%s/api/workspaces/%s/deployments/%s/destroy", baseURL, ws.ID, dep.ID)
				resp, body, err = doJSON(client, http.MethodPost, destroyURL, map[string]any{}, map[string]string{"Cookie": cookie})
				if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
					var destroyed deploymentActionResponse
					if json.Unmarshal(body, &destroyed) == nil {
						destroyTask := parseTaskID(destroyed.Run)
						if destroyTask > 0 {
							_, _, _ = waitForTaskFinished(&http.Client{Transport: tr}, baseURL, cookie, ws.ID, destroyTask, wait)
						}
					}
				}
			}

			if !testFailed {
				fmt.Printf("OK %s: succeeded\n", name)
			}
		case "netlab_byos_deploy":
			if t.NetlabDeploy == nil {
				fmt.Fprintf(os.Stderr, "test %q: missing netlab_deploy section\n", name)
				return 2
			}

			deployType := strings.ToLower(strings.TrimSpace(t.NetlabDeploy.Type))
			if deployType == "" {
				deployType = "netlab"
			}
			if deployType != "netlab" {
				fmt.Fprintf(os.Stderr, "test %q: unsupported byos deploy type %q\n", name, deployType)
				return 2
			}

			wait := 35 * time.Minute
			if timeoutStr := strings.TrimSpace(t.NetlabDeploy.Timeout); timeoutStr != "" {
				if parsed, err := time.ParseDuration(timeoutStr); err == nil && parsed > 0 {
					wait = parsed
				}
			}

			serverRef, err := ensureWorkspaceNetlabServer(client, baseURL, cookie, ws.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: byos netlab server not configured: %v\n", name, err)
				return 1
			}

			cfg := map[string]any{
				"netlabServer":       serverRef,
				"templateSource":     strings.TrimSpace(t.NetlabDeploy.Source),
				"templateRepo":       strings.TrimSpace(t.NetlabDeploy.Repo),
				"templatesDir":       strings.TrimSpace(t.NetlabDeploy.Dir),
				"template":           strings.TrimSpace(t.NetlabDeploy.Template),
				"environment":        t.NetlabDeploy.Environment,
				"netlabSetOverrides": t.NetlabDeploy.SetOverrides,
			}
			if cfg["environment"] == nil {
				cfg["environment"] = map[string]string{}
			}

			createDepURL := fmt.Sprintf("%s/api/workspaces/%s/deployments", baseURL, ws.ID)
			resp, body, err := doJSON(client, http.MethodPost, createDepURL, deploymentCreateRequest{
				Name:   strings.TrimSpace(name),
				Type:   "netlab",
				Config: cfg,
			}, map[string]string{"Cookie": cookie})
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: create deployment request failed: %v\n", name, err)
				return 1
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "test %q: create deployment failed (%d): %s\n", name, resp.StatusCode, strings.TrimSpace(string(body)))
				return 1
			}
			var dep deploymentResponse
			if err := json.Unmarshal(body, &dep); err != nil {
				fmt.Fprintf(os.Stderr, "test %q: create deployment parse failed: %v\n", name, err)
				return 1
			}
			if strings.TrimSpace(dep.ID) == "" {
				fmt.Fprintf(os.Stderr, "test %q: create deployment returned empty id\n", name)
				return 1
			}

			startURL := fmt.Sprintf("%s/api/workspaces/%s/deployments/%s/start", baseURL, ws.ID, dep.ID)
			resp, body, err = doJSON(client, http.MethodPost, startURL, map[string]any{}, map[string]string{"Cookie": cookie})
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: start deployment request failed: %v\n", name, err)
				return 1
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "test %q: start deployment failed (%d): %s\n", name, resp.StatusCode, strings.TrimSpace(string(body)))
				return 1
			}
			var out deploymentActionResponse
			if err := json.Unmarshal(body, &out); err != nil {
				fmt.Fprintf(os.Stderr, "test %q: start response parse failed: %v\n", name, err)
				return 1
			}
			taskID := parseTaskID(out.Run)
			if taskID <= 0 {
				fmt.Fprintf(os.Stderr, "test %q: start returned missing task id\n", name)
				return 1
			}
			fmt.Printf("OK %s: task=%d (waiting)\n", name, taskID)

			sseClient := &http.Client{Transport: tr}
			status, errMsg, err := waitForTaskFinished(sseClient, baseURL, cookie, ws.ID, taskID, wait)
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: wait failed: %v\n", name, err)
				return 1
			}
			switch strings.ToLower(strings.TrimSpace(status)) {
			case "succeeded", "success":
				fmt.Printf("OK %s: succeeded\n", name)
			default:
				fmt.Fprintf(os.Stderr, "test %q: byos deployment task finished with status=%q error=%q\n", name, status, errMsg)
				if output, err := fetchRunOutput(client, baseURL, cookie, ws.ID, taskID); err == nil && strings.TrimSpace(output) != "" {
					fmt.Fprintf(os.Stderr, "--- task %d output ---\n%s\n--- end output ---\n", taskID, output)
				}
				exitCode = 1
			}
		case "containerlab_byos_deploy":
			if t.ContainerlabDeploy == nil {
				fmt.Fprintf(os.Stderr, "test %q: missing containerlab_deploy section\n", name)
				return 2
			}
			wait := 25 * time.Minute
			if timeoutStr := strings.TrimSpace(t.ContainerlabDeploy.Timeout); timeoutStr != "" {
				if parsed, err := time.ParseDuration(timeoutStr); err == nil && parsed > 0 {
					wait = parsed
				}
			}
			serverRef, err := ensureWorkspaceNetlabServer(client, baseURL, cookie, ws.ID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: byos netlab server not configured: %v\n", name, err)
				return 1
			}
			cfg := map[string]any{
				"netlabServer":   serverRef,
				"templateSource": strings.TrimSpace(t.ContainerlabDeploy.Source),
				"templateRepo":   strings.TrimSpace(t.ContainerlabDeploy.Repo),
				"templatesDir":   strings.TrimSpace(t.ContainerlabDeploy.Dir),
				"template":       strings.TrimSpace(t.ContainerlabDeploy.Template),
				"environment":    t.ContainerlabDeploy.Environment,
			}
			if cfg["environment"] == nil {
				cfg["environment"] = map[string]string{}
			}
			createDepURL := fmt.Sprintf("%s/api/workspaces/%s/deployments", baseURL, ws.ID)
			resp, body, err := doJSON(client, http.MethodPost, createDepURL, deploymentCreateRequest{
				Name:   strings.TrimSpace(name),
				Type:   "containerlab",
				Config: cfg,
			}, map[string]string{"Cookie": cookie})
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: create deployment request failed: %v\n", name, err)
				return 1
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "test %q: create deployment failed (%d): %s\n", name, resp.StatusCode, strings.TrimSpace(string(body)))
				return 1
			}
			var dep deploymentResponse
			if err := json.Unmarshal(body, &dep); err != nil {
				fmt.Fprintf(os.Stderr, "test %q: create deployment parse failed: %v\n", name, err)
				return 1
			}
			if strings.TrimSpace(dep.ID) == "" {
				fmt.Fprintf(os.Stderr, "test %q: create deployment returned empty id\n", name)
				return 1
			}
			startURL := fmt.Sprintf("%s/api/workspaces/%s/deployments/%s/start", baseURL, ws.ID, dep.ID)
			resp, body, err = doJSON(client, http.MethodPost, startURL, map[string]any{}, map[string]string{"Cookie": cookie})
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: start deployment request failed: %v\n", name, err)
				return 1
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr, "test %q: start deployment failed (%d): %s\n", name, resp.StatusCode, strings.TrimSpace(string(body)))
				return 1
			}
			var out deploymentActionResponse
			if err := json.Unmarshal(body, &out); err != nil {
				fmt.Fprintf(os.Stderr, "test %q: start response parse failed: %v\n", name, err)
				return 1
			}
			taskID := parseTaskID(out.Run)
			if taskID <= 0 {
				fmt.Fprintf(os.Stderr, "test %q: start returned missing task id\n", name)
				return 1
			}
			fmt.Printf("OK %s: task=%d (waiting)\n", name, taskID)
			sseClient := &http.Client{Transport: tr}
			status, errMsg, err := waitForTaskFinished(sseClient, baseURL, cookie, ws.ID, taskID, wait)
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: wait failed: %v\n", name, err)
				return 1
			}
			switch strings.ToLower(strings.TrimSpace(status)) {
			case "succeeded", "success":
				fmt.Printf("OK %s: succeeded\n", name)
			default:
				fmt.Fprintf(os.Stderr, "test %q: containerlab task finished with status=%q error=%q\n", name, status, errMsg)
				if output, err := fetchRunOutput(client, baseURL, cookie, ws.ID, taskID); err == nil && strings.TrimSpace(output) != "" {
					fmt.Fprintf(os.Stderr, "--- task %d output ---\n%s\n--- end output ---\n", taskID, output)
				}
				exitCode = 1
			}
		default:
			fmt.Fprintf(os.Stderr, "unknown test kind %q (%s)\n", kind, name)
			return 2
		}
	}
	fmt.Printf("OK e2echeck: %d test(s)\n", len(m.Tests))
	return exitCode
}

func main() {
	os.Exit(run())
}
