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
	"sort"
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

	toStringList := func(v any) []string {
		out := []string{}
		seen := map[string]struct{}{}
		var visit func(any)
		visit = func(x any) {
			switch vv := x.(type) {
			case string:
				s := strings.TrimSpace(vv)
				if s == "" {
					return
				}
				if _, ok := seen[s]; ok {
					return
				}
				seen[s] = struct{}{}
				out = append(out, s)
			case []any:
				for _, item := range vv {
					visit(item)
				}
			case []string:
				for _, item := range vv {
					visit(item)
				}
			}
		}
		visit(v)
		return out
	}
	asAnyList := func(items []string) []any {
		out := make([]any, 0, len(items))
		for _, item := range items {
			out = append(out, item)
		}
		return out
	}
	containsString := func(items []string, target string) bool {
		for _, item := range items {
			if item == target {
				return true
			}
		}
		return false
	}

	groups := ensureMap(topo, "groups")
	// Never apply snmp_config globally via groups.all, because that also applies
	// to linux nodes (which do not have a netlab snmp_config template).
	if allRaw, ok := groups["all"]; ok {
		if all, ok := allRaw.(map[string]any); ok {
			cfg := toStringList(all["config"])
			filtered := make([]string, 0, len(cfg))
			for _, item := range cfg {
				if item != "snmp_config" {
					filtered = append(filtered, item)
				}
			}
			if len(filtered) == 0 {
				delete(all, "config")
			} else {
				all["config"] = asAnyList(filtered)
			}
		}
	}

	// Build device lookup for groups so we can infer node device when it is not
	// explicitly set on the node.
	groupDevice := map[string]string{}
	groupMembers := map[string]map[string]struct{}{}
	groupNames := make([]string, 0, len(groups))
	for name := range groups {
		groupNames = append(groupNames, name)
	}
	sort.Strings(groupNames)
	for _, groupName := range groupNames {
		groupRaw, ok := groups[groupName]
		if !ok {
			continue
		}
		groupMap, ok := groupRaw.(map[string]any)
		if !ok {
			continue
		}
		if d, ok := groupMap["device"].(string); ok && strings.TrimSpace(d) != "" {
			groupDevice[groupName] = strings.TrimSpace(d)
		}
		memberSet := map[string]struct{}{}
		for _, member := range toStringList(groupMap["members"]) {
			memberSet[member] = struct{}{}
		}
		if len(memberSet) > 0 {
			groupMembers[groupName] = memberSet
		}
	}

	defaults := ensureMap(topo, "defaults")
	defaultDevice := ""
	if d, ok := defaults["device"].(string); ok {
		defaultDevice = strings.TrimSpace(d)
	}
	nodes := ensureMap(topo, "nodes")
	nodeNames := make([]string, 0, len(nodes))
	for nodeName := range nodes {
		nodeNames = append(nodeNames, nodeName)
	}
	sort.Strings(nodeNames)
	for _, nodeName := range nodeNames {
		nodeRaw, ok := nodes[nodeName]
		if !ok {
			continue
		}
		nodeMap, ok := nodeRaw.(map[string]any)
		if !ok {
			continue
		}
		device := ""
		if d, ok := nodeMap["device"].(string); ok {
			device = strings.TrimSpace(d)
		}
		if device == "" {
			for _, groupName := range toStringList(nodeMap["group"]) {
				if d := strings.TrimSpace(groupDevice[groupName]); d != "" {
					device = d
					break
				}
			}
		}
		if device == "" {
			for _, groupName := range toStringList(nodeMap["groups"]) {
				if d := strings.TrimSpace(groupDevice[groupName]); d != "" {
					device = d
					break
				}
			}
		}
		if device == "" {
			for _, groupName := range groupNames {
				if _, ok := groupMembers[groupName][nodeName]; !ok {
					continue
				}
				if d := strings.TrimSpace(groupDevice[groupName]); d != "" {
					device = d
					break
				}
			}
		}
		if device == "" {
			device = defaultDevice
		}
		if strings.EqualFold(strings.TrimSpace(device), "linux") {
			continue
		}
		cfg := toStringList(nodeMap["config"])
		if !containsString(cfg, "snmp_config") {
			cfg = append(cfg, "snmp_config")
			nodeMap["config"] = asAnyList(cfg)
		}
	}

	snmp := ensureMap(defaults, "snmp")
	if strings.TrimSpace(community) != "" {
		snmp["community"] = strings.TrimSpace(community)
	}
	// trap_host can be empty; templates should treat that as "poll-only".
	snmp["trap_host"] = strings.TrimSpace(trapHost)
	if trapPort > 0 {
		snmp["trap_port"] = trapPort
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

	// Forward-synced deployments: enable netlab-native SNMP via custom config templates.
	// We patch topology.yml in the bundle so netlab create validates/renders snmp_config templates.
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
				community, tokErr := e.ensureUserSnmpTrapToken(ctx, strings.TrimSpace(spec.WorkspaceCtx.claims.Username))
				if tokErr != nil {
					return nil, nil, nil, tokErr
				}
				// Prefer an IP over DNS to avoid assumptions about NOS DNS.
				trapHost := ""
				if ip, found, ipErr := kubeGetServiceClusterIP(ctx, kubeNamespace(), "skyforge-snmp-trap"); ipErr == nil && found {
					trapHost = strings.TrimSpace(ip)
				}
				trapPort := 162
				patched, patchErr := patchNetlabBundleB64(bundleB64, func(b []byte) ([]byte, error) {
					return patchNetlabTopologyYAMLForSnmp(b, community, trapHost, trapPort)
				})
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
