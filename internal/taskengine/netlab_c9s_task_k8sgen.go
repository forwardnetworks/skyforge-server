package taskengine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type netlabC9sManifest struct {
	ClabYAML string `json:"clabYAML"`
	Nodes    map[string]struct {
		ConfigMapName string `json:"configMapName"`
		Files         []struct {
			Key string `json:"key"`
			Rel string `json:"rel"`
		} `json:"files"`
	} `json:"nodes"`
	SharedFiles *struct {
		ConfigMapName string `json:"configMapName"`
		Files         []struct {
			Key string `json:"key"`
			Rel string `json:"rel"`
		} `json:"files"`
	} `json:"sharedFiles,omitempty"`
	NetlabOutput *struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Chunks   []struct {
			ConfigMapName string `json:"configMapName"`
			Key           string `json:"key"`
		} `json:"chunks"`
	} `json:"netlabOutput,omitempty"`
}

const defaultNetlabC9sGeneratorImage = "ghcr.io/forwardnetworks/skyforge-netlab-generator:latest"

var generatedSnmpConfigTemplates = map[string]string{
	"linux": `#!/bin/sh
# Keep Linux hosts SNMP-free; no device SNMP config is required here.
exit 0`,
	"arubacx": `snmp-server community {{ defaults.snmp.community }} unrestricted
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server host {{ defaults.snmp.trap_host }} community {{ defaults.snmp.community }}
{% endif %}`,
	"asav": `snmp-server community {{ defaults.snmp.community }}
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ mgmt_if|default('Management0/0') }} {{ defaults.snmp.trap_host }} community {{ defaults.snmp.community }}
{% endif %}`,
	"cat8000v": `snmp-server community {{ defaults.snmp.community }} RO
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ defaults.snmp.trap_host }} version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"csr": `snmp-server community {{ defaults.snmp.community }} RO
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ defaults.snmp.trap_host }} version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"dellos10": `snmp-server community {{ defaults.snmp.community }} ro
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server host {{ defaults.snmp.trap_host }} traps version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"eos": `snmp-server community {{ defaults.snmp.community }} ro
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ defaults.snmp.trap_host }} version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"fortios": `config system snmp community
  edit 1
    set name "skyforge"
    set query-v1-status disable
    set query-v2c-status enable
    set community "{{ defaults.snmp.community }}"
  next
end
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
config system snmp sysinfo
  set status enable
end
config system snmp user
  edit 1
    set name "skyforge"
    set security-level no-auth-no-priv
    set notify-hosts {{ defaults.snmp.trap_host }}
  next
end
{% endif %}`,
	"iol": `snmp-server community {{ defaults.snmp.community }} RO
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ defaults.snmp.trap_host }} version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"ioll2": `snmp-server community {{ defaults.snmp.community }} RO
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ defaults.snmp.trap_host }} version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"ios": `snmp-server community {{ defaults.snmp.community }} RO
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ defaults.snmp.trap_host }} version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"iosv": `snmp-server community {{ defaults.snmp.community }} RO
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ defaults.snmp.trap_host }} version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"iosvl2": `snmp-server community {{ defaults.snmp.community }} RO
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ defaults.snmp.trap_host }} version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"iosxe": `snmp-server community {{ defaults.snmp.community }} RO
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ defaults.snmp.trap_host }} version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"iosxr": `snmp-server community {{ defaults.snmp.community }} RO`,
	"junos": `set snmp community {{ defaults.snmp.community }} authorization read-only
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
set snmp trap-group SKYFORGE categories link
set snmp trap-group SKYFORGE categories chassis
set snmp trap-group SKYFORGE targets {{ defaults.snmp.trap_host }}
{% endif %}`,
	"nxos": `snmp-server community {{ defaults.snmp.community }} group network-operator
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
snmp-server enable traps
snmp-server host {{ defaults.snmp.trap_host }} traps version 2c {{ defaults.snmp.community }}
{% endif %}`,
	"sros": `/configure system security snmp community "{{ defaults.snmp.community }}" access-permissions r
/configure system security snmp community "{{ defaults.snmp.community }}" version v2c
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
/configure system security snmp trap-group "skyforge" trap-target "{{ defaults.snmp.trap_host }}"
{% endif %}`,
	"vjunos-router": `set snmp community {{ defaults.snmp.community }} authorization read-only
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
set snmp trap-group SKYFORGE categories link
set snmp trap-group SKYFORGE categories chassis
set snmp trap-group SKYFORGE targets {{ defaults.snmp.trap_host }}
{% endif %}`,
	"vjunos-switch": `set snmp community {{ defaults.snmp.community }} authorization read-only
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
set snmp trap-group SKYFORGE categories link
set snmp trap-group SKYFORGE categories chassis
set snmp trap-group SKYFORGE targets {{ defaults.snmp.trap_host }}
{% endif %}`,
	"vmx": `set snmp community {{ defaults.snmp.community }} authorization read-only
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
set snmp trap-group SKYFORGE categories link
set snmp trap-group SKYFORGE categories chassis
set snmp trap-group SKYFORGE targets {{ defaults.snmp.trap_host }}
{% endif %}`,
	"vptx": `set snmp community {{ defaults.snmp.community }} authorization read-only
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
set snmp trap-group SKYFORGE categories link
set snmp trap-group SKYFORGE categories chassis
set snmp trap-group SKYFORGE targets {{ defaults.snmp.trap_host }}
{% endif %}`,
	"vsrx": `set snmp community {{ defaults.snmp.community }} authorization read-only
{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}
set snmp trap-group SKYFORGE categories link
set snmp trap-group SKYFORGE categories chassis
set snmp trap-group SKYFORGE targets {{ defaults.snmp.trap_host }}
{% endif %}`,
}

const generatedEOSAuthConfigTemplate = `aaa authentication login default local
username admin privilege 15 role network-admin secret admin
management ssh
   no shutdown
ip ssh password-authentication yes`

func renderGeneratedSnmpTemplate(tpl, community, trapHost string) string {
	out := strings.ReplaceAll(tpl, "{{ defaults.snmp.community }}", community)
	out = strings.ReplaceAll(out, "{{ defaults.snmp.trap_host }}", trapHost)
	cond := `{% if defaults.snmp.trap_host is defined and defaults.snmp.trap_host %}`
	escapedHost := strings.ReplaceAll(trapHost, `"`, `\"`)
	out = strings.ReplaceAll(out, cond, `{% if "`+escapedHost+`" %}`)
	return out
}

func patchNetlabTopologyYAMLForSnmp(topologyYAML []byte, community, trapHost string, trapPort int) ([]byte, error) {
	var topo map[string]any
	if err := yaml.Unmarshal(topologyYAML, &topo); err != nil {
		return nil, fmt.Errorf("parse topology.yml: %w", err)
	}
	if topo == nil {
		topo = map[string]any{}
	}

	ensureMap := func(parent map[string]any, key string) map[string]any {
		if parent == nil {
			return map[string]any{}
		}
		raw, ok := parent[key]
		if !ok || raw == nil {
			m := map[string]any{}
			parent[key] = m
			return m
		}
		if m, ok := raw.(map[string]any); ok {
			return m
		}
		m := map[string]any{}
		parent[key] = m
		return m
	}

	ensureAnyMap := func(raw any) map[string]any {
		switch vv := raw.(type) {
		case map[string]any:
			return vv
		case map[any]any:
			out := map[string]any{}
			for k, v := range vv {
				key := strings.TrimSpace(fmt.Sprintf("%v", k))
				if key == "" {
					continue
				}
				out[key] = v
			}
			return out
		default:
			return map[string]any{}
		}
	}

	// Ensure the files plugin is enabled so generated configlets are materialized into templates.
	rawPlugin, _ := topo["plugin"]
	hasFilesPlugin := false
	switch v := rawPlugin.(type) {
	case nil:
		topo["plugin"] = []any{"files"}
	case string:
		p := strings.TrimSpace(v)
		if strings.EqualFold(p, "files") {
			hasFilesPlugin = true
		}
		if !hasFilesPlugin {
			if p == "" {
				topo["plugin"] = []any{"files"}
			} else {
				topo["plugin"] = []any{p, "files"}
			}
		}
	case []any:
		for _, item := range v {
			if strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", item)), "files") {
				hasFilesPlugin = true
				break
			}
		}
		if !hasFilesPlugin {
			topo["plugin"] = append(v, "files")
		}
	case []string:
		for _, item := range v {
			if strings.EqualFold(strings.TrimSpace(item), "files") {
				hasFilesPlugin = true
				break
			}
		}
		if !hasFilesPlugin {
			next := make([]any, 0, len(v)+1)
			for _, item := range v {
				next = append(next, item)
			}
			next = append(next, "files")
			topo["plugin"] = next
		}
	default:
		topo["plugin"] = []any{"files"}
	}

	// Append required config modules.
	// - snmp_config applies globally (templates are generated for all supported devices).
	// - skyforge_eos_auth applies only to EOS groups to keep native netlab config_mode=sh
	//   while ensuring SSH/password auth defaults are present for Forward.
	groups := ensureMap(topo, "groups")
	all := ensureMap(groups, "all")
	var hasConfigModule func(v any, module string) bool
	hasConfigModule = func(v any, module string) bool {
		module = strings.TrimSpace(module)
		if module == "" {
			return false
		}
		switch vv := v.(type) {
		case string:
			return strings.TrimSpace(vv) == module
		case []any:
			for _, item := range vv {
				if hasConfigModule(item, module) {
					return true
				}
			}
		case []string:
			for _, item := range vv {
				if strings.TrimSpace(item) == module {
					return true
				}
			}
		}
		return false
	}
	appendConfigModule := func(group map[string]any, module string) {
		rawCfg, _ := group["config"]
		switch v := rawCfg.(type) {
		case nil:
			group["config"] = []any{module}
		case string:
			if !hasConfigModule(v, module) {
				if strings.TrimSpace(v) == "" {
					group["config"] = []any{module}
				} else {
					group["config"] = []any{strings.TrimSpace(v), module}
				}
			}
		case []any:
			if !hasConfigModule(v, module) {
				group["config"] = append(v, module)
			}
		case []string:
			if !hasConfigModule(v, module) {
				group["config"] = append(v, module)
			}
		default:
			group["config"] = []any{module}
		}
	}
	appendConfigModule(all, "snmp_config")
	eosGroup := ensureMap(groups, "eos")
	appendConfigModule(eosGroup, "skyforge_eos_auth")

	community = strings.TrimSpace(community)
	if community == "" {
		community = "public"
	}
	trapHost = strings.TrimSpace(trapHost)

	// Generate configlets directly in topology.yml so we do not depend on
	// repo-specific `_skyforge/*` overlay files.
	configlets := ensureMap(topo, "configlets")
	snmpConfiglets := ensureAnyMap(configlets["snmp_config"])
	for device, tpl := range generatedSnmpConfigTemplates {
		existing, exists := snmpConfiglets[device]
		if !exists || strings.TrimSpace(fmt.Sprintf("%v", existing)) == "" {
			snmpConfiglets[device] = renderGeneratedSnmpTemplate(tpl, community, trapHost)
		}
	}
	configlets["snmp_config"] = snmpConfiglets

	eosAuthConfiglets := ensureAnyMap(configlets["skyforge_eos_auth"])
	if existing, exists := eosAuthConfiglets["eos"]; !exists || strings.TrimSpace(fmt.Sprintf("%v", existing)) == "" {
		eosAuthConfiglets["eos"] = generatedEOSAuthConfigTemplate
	}
	if existing, exists := eosAuthConfiglets["ceos"]; !exists || strings.TrimSpace(fmt.Sprintf("%v", existing)) == "" {
		eosAuthConfiglets["ceos"] = generatedEOSAuthConfigTemplate
	}
	configlets["skyforge_eos_auth"] = eosAuthConfiglets

	defaults := ensureMap(topo, "defaults")
	snmp := ensureMap(defaults, "snmp")
	snmp["community"] = community
	// trap_host can be empty; templates should treat that as "poll-only".
	snmp["trap_host"] = trapHost
	if trapPort > 0 {
		snmp["trap_port"] = trapPort
	} else {
		delete(snmp, "trap_port")
	}

	out, err := yaml.Marshal(topo)
	if err != nil {
		return nil, fmt.Errorf("render topology.yml: %w", err)
	}
	return out, nil
}

func patchNetlabBundleB64(bundleB64 string, patchTopology func([]byte) ([]byte, error)) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundleB64))
	if err != nil {
		return "", fmt.Errorf("decode bundle: %w", err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("gunzip bundle: %w", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)

	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	tw := tar.NewWriter(gw)
	defer func() {
		_ = tw.Close()
		_ = gw.Close()
	}()

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read bundle tar: %w", err)
		}
		name := path.Clean(strings.TrimPrefix(strings.TrimSpace(hdr.Name), "/"))
		if name == "" || name == "." || strings.HasPrefix(name, "..") {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return "", fmt.Errorf("read bundle file %s: %w", name, err)
		}
		if name == "topology.yml" && patchTopology != nil {
			data, err = patchTopology(data)
			if err != nil {
				return "", err
			}
			hdr.Size = int64(len(data))
		}
		hdr.Name = name
		if err := tw.WriteHeader(hdr); err != nil {
			return "", fmt.Errorf("write bundle header %s: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return "", fmt.Errorf("write bundle file %s: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	if err := gw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(out.Bytes()), nil
}

// runNetlabC9sTaskK8sGenerator runs a netlab generator job inside the workspace namespace,
// waits for it to complete, then reads the generated manifest/configmaps.
//
// Contract:
// - Generator job reads `/input/bundle.b64` (a tar.gz base64) and extracts into /work.
// - Generator job runs `netlab create` and emits a clab.yml + node_files.
// - Generator job writes a ConfigMap named `c9s-<topologyName>-manifest` containing `manifest.json`.
// - `manifest.json` includes:
//   - `clabYAML` (string; contents of clab.yml)
//   - `nodes` mapping node -> {configMapName, files:[{key,rel}]}
//
// The worker uses this to mount node_files into clabernetes node pods without needing a tarball.
func (e *Engine) runNetlabC9sTaskK8sGenerator(ctx context.Context, spec netlabC9sRunSpec, topologyPath, tarballName string, log Logger) ([]byte, map[string][]c9sFileFromConfigMap, *netlabC9sManifest, error) {
	if log == nil {
		log = noopLogger{}
	}
	if e == nil {
		return nil, nil, nil, fmt.Errorf("engine unavailable")
	}

	image := strings.TrimSpace(e.cfg.NetlabGeneratorImage)
	if image == "" {
		image = defaultNetlabC9sGeneratorImage
		log.Infof("Netlab generator image not configured; defaulting to %s", image)
	}
	pullPolicy := strings.TrimSpace(e.cfg.NetlabGeneratorPullPolicy)
	if pullPolicy == "" {
		pullPolicy = "IfNotPresent"
	}
	if spec.WorkspaceCtx == nil {
		return nil, nil, nil, fmt.Errorf("workspace context unavailable")
	}
	if strings.TrimSpace(spec.Template) == "" {
		return nil, nil, nil, fmt.Errorf("netlab template is required")
	}

	ns := strings.TrimSpace(spec.K8sNamespace)
	if ns == "" {
		ns = clabernetesWorkspaceNamespace(spec.WorkspaceCtx.workspace.Slug)
	}
	topologyName := strings.TrimSpace(spec.TopologyName)
	if topologyName == "" {
		topologyName = clabernetesTopologyName(strings.TrimSpace(spec.LabName))
	}

	// Build the flattened topology bundle (tar.gz base64). This is copied into the generator pod
	// via a ConfigMap.
	bundleB64, err := e.buildNetlabTopologyBundleB64(ctx, spec.WorkspaceCtx, spec.TemplateSource, spec.TemplateRepo, spec.TemplatesDir, spec.Template)
	if err != nil {
		return nil, nil, nil, err
	}
	bundleB64 = strings.TrimSpace(bundleB64)
	if bundleB64 == "" {
		return nil, nil, nil, fmt.Errorf("netlab topology bundle is empty")
	}
	// Defensive cap: Kubernetes object size limit is ~1MiB; base64 expands.
	if len(bundleB64) > 900_000 {
		return nil, nil, nil, fmt.Errorf("netlab topology bundle too large for in-cluster generator (%d bytes base64)", len(bundleB64))
	}
	if _, err := base64.StdEncoding.DecodeString(bundleB64); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid netlab topology bundle encoding: %w", err)
	}

	// Always enable netlab-native SNMP by injecting generated snmp_config templates directly
	// into topology.yml (no external template directory dependency). Forward-enabled deployments
	// are upgraded to per-user SNMP credentials + trap target.
	community := "public"
	trapHost := ""
	trapPort := 0
	if spec.WorkspaceCtx != nil && strings.TrimSpace(spec.DeploymentID) != "" {
		dep, depErr := e.loadDeployment(ctx, strings.TrimSpace(spec.WorkspaceCtx.workspace.ID), strings.TrimSpace(spec.DeploymentID))
		if depErr == nil && dep != nil {
			cfgAny, _ := fromJSONMap(dep.Config)
			enabled := false
			if raw, ok := cfgAny[forwardEnabledKey]; ok {
				switch v := raw.(type) {
				case bool:
					enabled = v
				case string:
					s := strings.TrimSpace(v)
					enabled = strings.EqualFold(s, "true") || s == "1" || strings.EqualFold(s, "yes")
				default:
					s := strings.TrimSpace(fmt.Sprintf("%v", raw))
					enabled = strings.EqualFold(s, "true") || s == "1" || strings.EqualFold(s, "yes")
				}
			}
			if enabled {
				if c, tokErr := e.ensureUserSnmpTrapToken(ctx, strings.TrimSpace(spec.WorkspaceCtx.claims.Username)); tokErr == nil {
					if strings.TrimSpace(c) != "" {
						community = strings.TrimSpace(c)
					}
				} else {
					return nil, nil, nil, tokErr
				}
				// Prefer an IP over DNS to avoid assumptions about NOS DNS.
				if ip, found, ipErr := kubeGetServiceClusterIP(ctx, kubeNamespace(), "skyforge-snmp-trap"); ipErr == nil && found {
					trapHost = strings.TrimSpace(ip)
				}
				trapPort = 162
			}
		}
	}
	patched, patchErr := patchNetlabBundleB64(bundleB64, func(b []byte) ([]byte, error) {
		return patchNetlabTopologyYAMLForSnmp(b, community, trapHost, trapPort)
	})
	if patchErr != nil {
		return nil, nil, nil, patchErr
	}
	bundleB64 = patched

	if err := kubeEnsureNamespace(ctx, ns); err != nil {
		return nil, nil, nil, err
	}
	// The generator runs in the workspace namespace and pulls its image from GHCR.
	// Ensure the image pull secret exists in the workspace namespace before creating the Job.
	if err := kubeEnsureNamespaceImagePullSecret(ctx, ns, strings.TrimSpace(e.cfg.ImagePullSecretName), strings.TrimSpace(e.cfg.ImagePullSecretNamespace)); err != nil {
		return nil, nil, nil, err
	}

	labels := map[string]string{
		"skyforge-c9s-topology": topologyName,
	}

	bundleCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-bundle", topologyName), "c9s-bundle")
	if err := kubeUpsertConfigMap(ctx, ns, bundleCM, map[string]string{
		"bundle.b64": bundleB64,
	}, labels); err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		_, _ = kubeDeleteConfigMap(context.Background(), ns, bundleCM)
	}()

	// Ensure the generator SA has permissions to create/patch ConfigMaps in the workspace namespace.
	const saName = "skyforge-netlab-generator"
	const roleName = "skyforge-netlab-generator"
	const rbName = "skyforge-netlab-generator"
	if err := kubeUpsertServiceAccount(ctx, ns, saName, labels); err != nil {
		return nil, nil, nil, err
	}
	// kubeUpsertServiceAccount doesn't include imagePullSecrets; ensure the generator SA can pull.
	secretName := strings.TrimSpace(e.cfg.ImagePullSecretName)
	if secretName == "" {
		secretName = "ghcr-pull"
	}
	if err := kubeEnsureServiceAccountImagePullSecret(ctx, ns, saName, secretName); err != nil {
		return nil, nil, nil, err
	}
	rules := []map[string]any{
		{
			"apiGroups": []string{""},
			"resources": []string{"configmaps"},
			"verbs":     []string{"get", "list", "create", "update", "patch", "delete"},
		},
	}
	if err := kubeUpsertRole(ctx, ns, roleName, rules, labels); err != nil {
		return nil, nil, nil, err
	}
	if err := kubeUpsertRoleBinding(ctx, ns, rbName, roleName, saName, labels); err != nil {
		return nil, nil, nil, err
	}

	jobName := sanitizeKubeNameFallback(fmt.Sprintf("netlab-gen-%s-%d", topologyName, time.Now().Unix()%10_000), "netlab-gen")
	manifestCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-manifest", topologyName), "c9s-manifest")

	payload := map[string]any{
		"apiVersion": "batch/v1",
		"kind":       "Job",
		"metadata": map[string]any{
			"name":      jobName,
			"namespace": ns,
			"labels": map[string]any{
				"app":                   "skyforge-netlab-generator",
				"skyforge-c9s-topology": topologyName,
				"skyforge-task-id":      fmt.Sprintf("%d", spec.TaskID),
			},
		},
		"spec": map[string]any{
			"backoffLimit":            0,
			"ttlSecondsAfterFinished": 3600,
			"template": map[string]any{
				"metadata": map[string]any{
					"labels": map[string]any{
						"app": "skyforge-netlab-generator",
					},
				},
				"spec": map[string]any{
					"restartPolicy":      "Never",
					"serviceAccountName": saName,
					"containers": []map[string]any{
						{
							"name":            "generator",
							"image":           image,
							"imagePullPolicy": pullPolicy,
							"env": func() []map[string]any {
								genEnv := map[string]string{
									"SKYFORGE_NETLAB_BUNDLE_PATH":   "/input/bundle.b64",
									"SKYFORGE_NETLAB_TOPOLOGY_PATH": strings.TrimSpace(topologyPath),
									"SKYFORGE_C9S_NAMESPACE":        ns,
									"SKYFORGE_C9S_TOPOLOGY_NAME":    topologyName,
									"SKYFORGE_C9S_LAB_NAME":         strings.TrimSpace(spec.LabName),
									"SKYFORGE_C9S_MANIFEST_CM":      manifestCM,
								}
								if len(spec.SetOverrides) > 0 {
									genEnv["SKYFORGE_NETLAB_SET_OVERRIDES"] = strings.Join(spec.SetOverrides, "\n")
								}
								for k, v := range spec.Environment {
									kk := strings.TrimSpace(k)
									if kk == "" {
										continue
									}
									up := strings.ToUpper(kk)
									if strings.HasPrefix(up, "NETLAB_") || strings.HasPrefix(kk, "netlab_") || up == "SKYFORGE_NETLAB_SET_OVERRIDES" {
										// Prefer explicit SetOverrides over environment-provided overrides.
										if up == "SKYFORGE_NETLAB_SET_OVERRIDES" && len(spec.SetOverrides) > 0 {
											continue
										}
										genEnv[kk] = v
									}
								}
								return kubeEnvList(genEnv)
							}(),
							"volumeMounts": []map[string]any{
								{"name": "input", "mountPath": "/input", "readOnly": true},
								{"name": "work", "mountPath": "/work"},
							},
						},
					},
					"volumes": []map[string]any{
						{
							"name": "input",
							"configMap": map[string]any{
								"name": bundleCM,
							},
						},
						{
							"name": "work",
							"emptyDir": map[string]any{
								"sizeLimit": "2Gi",
							},
						},
					},
				},
			},
		},
	}

	if err := kubeCreateJob(ctx, ns, payload); err != nil {
		return nil, nil, nil, err
	}
	jobSucceeded := false
	defer func() {
		// Keep failed Jobs around until TTLSecondsAfterFinished so we can debug them.
		// Successful jobs are safe to delete immediately to reduce cluster noise.
		if jobSucceeded {
			_ = kubeDeleteJob(context.Background(), ns, jobName)
		}
	}()

	log.Infof("Netlab generator job created: %s", jobName)
	if err := kubeWaitJob(ctx, ns, jobName, log, func() bool {
		if spec.TaskID <= 0 || e == nil {
			return false
		}
		canceled, _ := e.taskCanceled(ctx, spec.TaskID)
		return canceled
	}); err != nil {
		return nil, nil, nil, err
	}
	jobSucceeded = true

	data, ok, err := kubeGetConfigMap(ctx, ns, manifestCM)
	if err != nil {
		return nil, nil, nil, err
	}
	if !ok {
		return nil, nil, nil, fmt.Errorf("netlab generator did not write manifest configmap %s", manifestCM)
	}
	raw := strings.TrimSpace(data["manifest.json"])
	if raw == "" {
		return nil, nil, nil, fmt.Errorf("netlab generator manifest is empty")
	}
	var manifest netlabC9sManifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid netlab generator manifest: %w", err)
	}
	clab := strings.TrimSpace(manifest.ClabYAML)
	if clab == "" {
		return nil, nil, nil, fmt.Errorf("netlab generator manifest missing clabYAML")
	}

	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	nodeMounts := map[string][]c9sFileFromConfigMap{}

	sharedMounts := []c9sFileFromConfigMap{}
	if manifest.SharedFiles != nil {
		cmName := strings.TrimSpace(manifest.SharedFiles.ConfigMapName)
		for _, f := range manifest.SharedFiles.Files {
			key := strings.TrimSpace(f.Key)
			rel := path.Clean(strings.TrimPrefix(strings.TrimSpace(f.Rel), "/"))
			if cmName == "" || key == "" || rel == "" || rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			mountPath := path.Join(mountRoot, "node_files", rel)
			sharedMounts = append(sharedMounts, c9sFileFromConfigMap{
				ConfigMapName: cmName,
				ConfigMapPath: key,
				FilePath:      mountPath,
				Mode:          "read",
			})
		}
	}

	for node, entry := range manifest.Nodes {
		node = strings.TrimSpace(node)
		cmName := strings.TrimSpace(entry.ConfigMapName)
		if node == "" || cmName == "" || len(entry.Files) == 0 {
			continue
		}
		mounts := make([]c9sFileFromConfigMap, 0, len(entry.Files))
		for _, f := range entry.Files {
			key := strings.TrimSpace(f.Key)
			rel := path.Clean(strings.TrimPrefix(strings.TrimSpace(f.Rel), "/"))
			if key == "" || rel == "" || rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			mountPath := path.Join(mountRoot, "node_files", node, rel)
			mounts = append(mounts, c9sFileFromConfigMap{
				ConfigMapName: cmName,
				ConfigMapPath: key,
				FilePath:      mountPath,
				Mode:          "read",
			})
		}
		if len(mounts) == 0 {
			continue
		}
		if len(sharedMounts) > 0 {
			mounts = append(mounts, sharedMounts...)
		}
		nodeMounts[node] = mounts
	}

	return []byte(clab), nodeMounts, &manifest, nil
}
