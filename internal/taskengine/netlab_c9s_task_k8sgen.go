package taskengine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
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
	// Backward/forward compatibility: some generator versions used snake_case for netlab output metadata.
	NetlabOutputSnake *struct {
		Type     string `json:"type"`
		Encoding string `json:"encoding"`
		Chunks   []struct {
			ConfigMapName string `json:"configMapName"`
			Key           string `json:"key"`
		} `json:"chunks"`
	} `json:"netlab_output,omitempty"`
}

// NOTE: Do not default to :latest; our deployments pin a known-good generator tag and
// the :latest tag may not be published (which breaks netlab-c9s deploy/validate in new namespaces).

type snmpV3Profile struct {
	Username        string
	AuthProtocol    string
	AuthPassword    string
	PrivacyProtocol string
	PrivacyPassword string
}

var snmpV3UsernameCleaner = regexp.MustCompile(`[^a-z0-9_]`)

func snmpV3ProfileForUsername(username string) snmpV3Profile {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		username = "skyforge"
	}
	base := snmpV3UsernameCleaner.ReplaceAllString(username, "_")
	base = strings.Trim(base, "_")
	if base == "" {
		base = "skyforge"
	}
	if len(base) > 20 {
		base = strings.Trim(base[:20], "_")
	}
	if base == "" {
		base = "skyforge"
	}
	authSum := sha256.Sum256([]byte("skyforge-snmpv3-auth:" + username))
	privSum := sha256.Sum256([]byte("skyforge-snmpv3-priv:" + username))
	authHex := hex.EncodeToString(authSum[:])
	privHex := hex.EncodeToString(privSum[:])
	return snmpV3Profile{
		Username:        base,
		AuthProtocol:    "SHA_256",
		AuthPassword:    "SfAuth-" + authHex[:24],
		PrivacyProtocol: "AES_128",
		PrivacyPassword: "SfPriv-" + privHex[:24],
	}
}

func patchNetlabTopologyYAMLForSnmp(topologyYAML []byte, profile snmpV3Profile) ([]byte, error) {
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

	// Keep SNMP configlet definition local to the patched topology so native netlab
	// generation does not depend on external defaults.yml packaging state.
	ceosCmd := fmt.Sprintf("snmp-server view sfv3 iso included\nsnmp-server group sfgroup v3 priv read sfv3\nsnmp-server user %s sfgroup v3 auth sha256 %s priv aes-128 %s", profile.Username, profile.AuthPassword, profile.PrivacyPassword)
	iosCmd := fmt.Sprintf("snmp-server view sfv3 iso included\nsnmp-server group sfgroup v3 priv read sfv3\nsnmp-server user %s sfgroup v3 auth sha %s priv aes 128 %s", profile.Username, profile.AuthPassword, profile.PrivacyPassword)
	snmpConfigletTemplates := map[string]string{
		"linux":             "# no-op (keep linux hosts SNMP-free by default)",
		"ceos":              ceosCmd,
		"iol":               iosCmd,
		"ioll2":             iosCmd,
		"asa":               "# SNMPv3 auto-config not available for ASA template",
		"junos":             "# SNMPv3 auto-config not available for Junos template",
		"vmx":               "# SNMPv3 auto-config not available for vMX template",
		"vsrx":              "# SNMPv3 auto-config not available for vSRX template",
		"vjunos-router":     "# SNMPv3 auto-config not available for vJunos-router template",
		"vjunos-switch":     "# SNMPv3 auto-config not available for vJunos-switch template",
		"vptx":              "# SNMPv3 auto-config not available for vPTX template",
		"nxos":              "# SNMPv3 auto-config not available for NX-OS template",
		"dellos10":          "# SNMPv3 auto-config not available for Dell OS10 template",
		"arubacx":           "# SNMPv3 auto-config not available for Aruba CX template",
		"fortios":           "# SNMPv3 auto-config not available for FortiOS template",
		"sros":              "# SNMPv3 auto-config not available for SR OS template",
		"cumulus_nvue":      "echo 'SNMP managed externally'",
		"xrd-control-plane": iosCmd,
	}

	groups := ensureMap(topo, "groups")
	all := ensureMap(groups, "all")
	rawCfg, _ := all["config"]
	var hasSnmp func(v any) bool
	hasSnmp = func(v any) bool {
		switch vv := v.(type) {
		case string:
			return strings.TrimSpace(vv) == "snmp_config"
		case []any:
			for _, item := range vv {
				if hasSnmp(item) {
					return true
				}
			}
		case []string:
			for _, item := range vv {
				if strings.TrimSpace(item) == "snmp_config" {
					return true
				}
			}
		}
		return false
	}
	switch v := rawCfg.(type) {
	case nil:
		all["config"] = []any{"snmp_config"}
	case string:
		if !hasSnmp(v) {
			if strings.TrimSpace(v) == "" {
				all["config"] = []any{"snmp_config"}
			} else {
				all["config"] = []any{strings.TrimSpace(v), "snmp_config"}
			}
		}
	case []any:
		if !hasSnmp(v) {
			all["config"] = append(v, "snmp_config")
		}
	case []string:
		if !hasSnmp(v) {
			all["config"] = append(v, "snmp_config")
		}
	default:
		all["config"] = []any{"snmp_config"}
	}

	defaults := ensureMap(topo, "defaults")
	configlets := ensureMap(defaults, "configlets")
	rawSnmpCfg, _ := configlets["snmp_config"]
	snmpCfgMap, ok := rawSnmpCfg.(map[string]any)
	if !ok || snmpCfgMap == nil {
		snmpCfgMap = map[string]any{}
	}
	for dev, cfg := range snmpConfigletTemplates {
		if _, exists := snmpCfgMap[dev]; !exists {
			snmpCfgMap[dev] = cfg
		}
	}
	// Netlab device identifiers remain canonical (for example eos/iosxr/cumulus),
	// even when we standardize image families to ceos/xrd-control-plane/cumulus_nvue.
	for alias, canonical := range map[string]string{
		"eos":     "ceos",
		"iosxr":   "xrd-control-plane",
		"cumulus": "cumulus_nvue",
	} {
		if _, exists := snmpCfgMap[alias]; exists {
			continue
		}
		if cfg, ok := snmpCfgMap[canonical]; ok {
			snmpCfgMap[alias] = cfg
		}
	}
	configlets["snmp_config"] = snmpCfgMap

	snmp := ensureMap(defaults, "snmp")
	snmp["version"] = "v3"
	snmp["username"] = profile.Username
	snmp["auth_protocol"] = strings.ToLower(profile.AuthProtocol)
	snmp["auth_password"] = profile.AuthPassword
	snmp["privacy_protocol"] = strings.ToLower(profile.PrivacyProtocol)
	snmp["privacy_password"] = profile.PrivacyPassword

	out, err := yaml.Marshal(topo)
	if err != nil {
		return nil, fmt.Errorf("render topology.yml: %w", err)
	}
	return out, nil
}

func snmpTemplateFilesForBundle(profile snmpV3Profile) map[string]string {
	ceosCmd := fmt.Sprintf("snmp-server view sfv3 iso included\nsnmp-server group sfgroup v3 priv read sfv3\nsnmp-server user %s sfgroup v3 auth sha256 %s priv aes-128 %s\n", profile.Username, profile.AuthPassword, profile.PrivacyPassword)
	iosCmd := fmt.Sprintf("snmp-server view sfv3 iso included\nsnmp-server group sfgroup v3 priv read sfv3\nsnmp-server user %s sfgroup v3 auth sha %s priv aes 128 %s\n", profile.Username, profile.AuthPassword, profile.PrivacyPassword)
	baseByDevice := map[string]string{
		"ceos":              ceosCmd,
		"iol":               iosCmd,
		"ioll2":             iosCmd,
		"asa":               "# SNMPv3 auto-config not available for ASA template\n",
		"junos":             "# SNMPv3 auto-config not available for Junos template\n",
		"vmx":               "# SNMPv3 auto-config not available for vMX template\n",
		"vsrx":              "# SNMPv3 auto-config not available for vSRX template\n",
		"vjunos-router":     "# SNMPv3 auto-config not available for vJunos-router template\n",
		"vjunos-switch":     "# SNMPv3 auto-config not available for vJunos-switch template\n",
		"vptx":              "# SNMPv3 auto-config not available for vPTX template\n",
		"nxos":              "# SNMPv3 auto-config not available for NX-OS template\n",
		"dellos10":          "# SNMPv3 auto-config not available for Dell OS10 template\n",
		"arubacx":           "# SNMPv3 auto-config not available for Aruba CX template\n",
		"fortios":           "# SNMPv3 auto-config not available for FortiOS template\n",
		"sros":              "# SNMPv3 auto-config not available for SR OS template\n",
		"cumulus_nvue":      "# SNMP managed externally\n",
		"xrd-control-plane": iosCmd,
	}

	templates := make(map[string]string, len(baseByDevice)+3)
	for dev, content := range baseByDevice {
		templates[path.Join("snmp_config", dev+".j2")] = content
	}
	for alias, canonical := range map[string]string{
		"eos":     "ceos",
		"iosxr":   "xrd-control-plane",
		"cumulus": "cumulus_nvue",
	} {
		if content, ok := baseByDevice[canonical]; ok {
			templates[path.Join("snmp_config", alias+".j2")] = content
		}
	}
	return templates
}

func patchNetlabBundleB64(bundleB64 string, patchTopology func([]byte) ([]byte, error), extraFiles map[string]string) (string, error) {
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
	existing := map[string]struct{}{}
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
		existing[name] = struct{}{}
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
	for rawName, body := range extraFiles {
		name := path.Clean(strings.TrimPrefix(strings.TrimSpace(rawName), "/"))
		if name == "" || name == "." || strings.HasPrefix(name, "..") {
			continue
		}
		if _, ok := existing[name]; ok {
			continue
		}
		content := []byte(body)
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", fmt.Errorf("write bundle header %s: %w", name, err)
		}
		if _, err := tw.Write(content); err != nil {
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

func validateNoLegacyIOSVMTopology(topologyYAML []byte) error {
	var topo map[string]any
	if err := yaml.Unmarshal(topologyYAML, &topo); err != nil {
		return fmt.Errorf("parse topology.yml: %w", err)
	}
	if topo == nil {
		return nil
	}
	nodes, _ := topo["nodes"].(map[string]any)
	if len(nodes) == 0 {
		if top, ok := topo["topology"].(map[string]any); ok {
			nodes, _ = top["nodes"].(map[string]any)
		}
	}
	if len(nodes) == 0 {
		return nil
	}
	legacyKinds := map[string]bool{
		"iosv":           true,
		"iosvl2":         true,
		"iosxe":          true,
		"ios":            true,
		"csr":            true,
		"cat8000v":       true,
		"cisco_vios":     true,
		"cisco_viosl2":   true,
		"vr-csr":         true,
		"cisco_c8000v":   true,
		"cisco_csr1000v": true,
	}
	legacyImageFragments := []string{
		"/cisco_vios",
		"/cisco_viosl2",
		"/vr-csr",
		"/cisco_c8000",
		"cisco/csr1000v",
		"cisco/iosv",
	}
	for nodeName, raw := range nodes {
		node, _ := raw.(map[string]any)
		if node == nil {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", node["kind"])))
		image := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", node["image"])))
		if legacyKinds[kind] {
			return fmt.Errorf("legacy Cisco IOS VM kind %q is not supported in native mode (node=%s); use iol/ioll2", kind, strings.TrimSpace(nodeName))
		}
		for _, frag := range legacyImageFragments {
			if strings.Contains(image, frag) {
				return fmt.Errorf("legacy Cisco IOS VM image %q is not supported in native mode (node=%s); use cisco_iol/cisco_iol_l2", image, strings.TrimSpace(nodeName))
			}
		}
	}
	return nil
}

const defaultNetlabC9sGeneratorImage = "ghcr.io/forwardnetworks/skyforge-netlab-generator:20260127-b8947318"

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
	// Hard-cut legacy Cisco IOS VM device types. Templates must use IOL variants.
	validatedBundle, validateErr := patchNetlabBundleB64(bundleB64, func(b []byte) ([]byte, error) {
		if err := validateNoLegacyIOSVMTopology(b); err != nil {
			return nil, err
		}
		return b, nil
	}, nil)
	if validateErr != nil {
		return nil, nil, nil, validateErr
	}
	bundleB64 = validatedBundle

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
			if enabled && e.cfg.Forward.SNMPPlaceholderEnabled {
				profile := snmpV3ProfileForUsername(strings.TrimSpace(spec.WorkspaceCtx.claims.Username))
				patched, patchErr := patchNetlabBundleB64(bundleB64, func(b []byte) ([]byte, error) {
					return patchNetlabTopologyYAMLForSnmp(b, profile)
				}, snmpTemplateFilesForBundle(profile))
				if patchErr != nil {
					return nil, nil, nil, patchErr
				}
				bundleB64 = patched
			}
		}
	}

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
	// Normalize generator manifest schema variants.
	if manifest.NetlabOutput == nil && manifest.NetlabOutputSnake != nil {
		manifest.NetlabOutput = manifest.NetlabOutputSnake
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
