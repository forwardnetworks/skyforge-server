package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
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

func deployableInSkyforge(device string) bool {
	switch strings.TrimSpace(device) {
	// These are the device types Skyforge currently exposes as "available"/"onboarded"
	// for in-cluster (clabernetes) netlab deployments.
	//
	// NOTE: Exclude vsrx (out of scope) even if the upstream netlab catalog includes it.
	case "eos", "iol", "iosv", "iosvl2", "csr", "nxos", "cumulus", "sros", "asav", "fortios", "vmx", "vjunos-router", "vjunos-switch", "linux":
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
						Timeout:      "25m",
						SSHBanners:   true,
						SSHTimeout:   "12m",
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
	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx2, "kubectl", "apply", "-f", "-")
	cmd.Env = kubectlEnv()
	cmd.Stdin = strings.NewReader(yaml)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
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
	default:
		return "job"
	}
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
      data = s.recv(4)
      s.close()
      if data == b"SSH-":
        return True, None
      last = f"bad_banner:{data!r}"
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
      restartPolicy: Never
      containers:
      - name: probe
        image: python:3.12-alpine
        imagePullPolicy: IfNotPresent
        env:
        - name: HOSTS
          value: %q
        - name: TIMEOUT_SECONDS
          value: %q
        command: ["python","-c",%q]
`, jobName, namespace, activeDeadline, strings.Join(hostArgs, " "), fmt.Sprintf("%d", int(timeout.Seconds())), script)

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

	var currentData strings.Builder
	for {
		select {
		case <-ctx.Done():
			return "", "", fmt.Errorf("timeout waiting for task %d", taskID)
		case err := <-errCh:
			if err != nil {
				return "", "", err
			}
		case <-ticker.C:
			if strings.TrimSpace(workspaceID) != "" {
				if st, er, ok := pollTaskStatus(client, baseURL, cookie, workspaceID, taskID); ok {
					return st, er, nil
				}
			}
		case line, ok := <-lineCh:
			if !ok {
				// Stream ended; fall back to a final poll.
				if st, er, ok := pollTaskStatus(client, baseURL, cookie, workspaceID, taskID); ok {
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

func pollTaskStatus(client *http.Client, baseURL string, cookie string, workspaceID string, taskID int) (status string, errMsg string, ok bool) {
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" || taskID <= 0 {
		return "", "", false
	}
	url := fmt.Sprintf("%s/api/runs?workspace_id=%s&limit=25", strings.TrimRight(baseURL, "/"), workspaceID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		Tasks []map[string]any `json:"tasks"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", false
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
			return strings.TrimSpace(st), strings.TrimSpace(er), true
		}
		return "", "", false
	}
	return "", "", false
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
		// Fall back to kubectl.
		return findAnyCollectorPodViaKubectl(context.Background())
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Fall back to kubectl.
		return findAnyCollectorPodViaKubectl(context.Background())
	}
	var decoded userCollectorRuntimeResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		// Fall back to kubectl.
		return findAnyCollectorPodViaKubectl(context.Background())
	}
	if decoded.Runtime == nil || !decoded.Runtime.Ready || strings.TrimSpace(decoded.Runtime.PodName) == "" {
		// Fall back to kubectl (some users may not have a collector configured).
		return findAnyCollectorPodViaKubectl(context.Background())
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
	var ws workspaceResponse
	if err := json.Unmarshal(body, &ws); err != nil {
		fmt.Fprintf(os.Stderr, "workspace create parse failed: %v\n", err)
		return 1
	}
	if strings.TrimSpace(ws.ID) == "" {
		fmt.Fprintf(os.Stderr, "workspace create returned empty id: %s\n", strings.TrimSpace(string(body)))
		return 1
	}
	fmt.Printf("OK workspace create: %s (%s)\n", ws.Name, ws.ID)

	defer func() {
		deleteURL := baseURL + "/api/workspaces/" + ws.ID + "?confirm=" + ws.Slug
		resp, body, err := doJSON(client, http.MethodDelete, deleteURL, nil, map[string]string{"Cookie": cookie})
		if err != nil {
			fmt.Fprintf(os.Stderr, "workspace delete request failed: %v\n", err)
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			fmt.Fprintf(os.Stderr, "workspace delete failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
			return
		}
		fmt.Printf("OK workspace delete: %s\n", ws.ID)
	}()

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

	exitCode := 0
	for _, t := range m.Tests {
		name := strings.TrimSpace(t.Name)
		kind := strings.TrimSpace(t.Kind)
		if name == "" {
			name = kind
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

			depName := strings.TrimPrefix(strings.ToLower(name), "netlab-deploy-")
			if depName == "" {
				depName = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
			}
			depName = strings.Trim(depName, "-")
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

			collectorConfigID, collectorNS, collectorPod, err := resolveDefaultCollectorPod(client, baseURL, cookie)
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %q: collector resolve failed: %v\n", name, err)
				return 1
			}

			if t.NetlabDeploy.SSHBanners {
				if err := kubectlAvailable(context.Background()); err != nil {
					fmt.Fprintf(os.Stderr, "test %q: kubectl is required for ssh banner checks but is not working.\n%s\n", name, err)
					fmt.Fprintf(os.Stderr, "Hint: if you're using the repo kubeconfig, start the tunnel:\n  ssh -N -L 6443:127.0.0.1:6443 skyforge.local.forwardnetworks.com\n")
					return 1
				}
			}

			// Best-effort: enable Forward on this deployment so we also exercise Forward sync plumbing.
			if strings.TrimSpace(collectorConfigID) != "" {
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
				if output, err := fetchRunOutput(client, baseURL, cookie, ws.ID, taskID); err == nil && strings.TrimSpace(output) != "" {
					fmt.Fprintf(os.Stderr, "--- task %d output ---\n%s\n--- end output ---\n", taskID, output)
				}
				exitCode = 1
				testFailed = true
			}

			if !testFailed && t.NetlabDeploy.SSHBanners {
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
									exitCode = 1
									testFailed = true
								} else {
									fmt.Printf("OK %s: collector ssh banner ok (hosts=%d)\n", name, len(hosts))
								}
							default:
								probeNS := strings.TrimSpace(collectorNS)
								if probeNS == "" {
									probeNS = "skyforge"
								}
								if err := waitForSSHProbeJob(context.Background(), probeNS, hosts, sshWait); err != nil {
									fmt.Fprintf(os.Stderr, "test %q: ssh probe job failed: %v\n", name, err)
									exitCode = 1
									testFailed = true
								} else {
									fmt.Printf("OK %s: ssh probe ok (namespace=%s hosts=%d)\n", name, probeNS, len(hosts))
								}
							}
						}
					}
				}
			}

			if t.NetlabDeploy.Cleanup {
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
