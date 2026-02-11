package taskengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"encore.app/internal/taskdispatch"
	"encore.app/internal/taskstore"
	"gopkg.in/yaml.v3"
)

type netlabC9sTaskSpec struct {
	Action          string            `json:"action,omitempty"` // deploy|destroy
	Server          string            `json:"server,omitempty"`
	Deployment      string            `json:"deployment,omitempty"`
	DeploymentID    string            `json:"deploymentId,omitempty"`
	WorkspaceRoot   string            `json:"workspaceRoot,omitempty"`
	TemplateSource  string            `json:"templateSource,omitempty"`
	TemplateRepo    string            `json:"templateRepo,omitempty"`
	TemplatesDir    string            `json:"templatesDir,omitempty"`
	Template        string            `json:"template,omitempty"`
	WorkspaceDir    string            `json:"workspaceDir,omitempty"`
	MultilabNumeric int               `json:"multilabNumeric,omitempty"`
	TopologyPath    string            `json:"topologyPath,omitempty"`
	ClabTarball     string            `json:"clabTarball,omitempty"`
	K8sNamespace    string            `json:"k8sNamespace,omitempty"`
	LabName         string            `json:"labName,omitempty"`
	TopologyName    string            `json:"topologyName,omitempty"`
	Environment     map[string]string `json:"environment,omitempty"`
	SetOverrides    []string          `json:"setOverrides,omitempty"`
}

type netlabC9sRunSpec struct {
	TaskID          int
	WorkspaceCtx    *workspaceContext
	WorkspaceSlug   string
	Username        string
	Environment     map[string]string
	SetOverrides    []string
	Action          string
	Deployment      string
	DeploymentID    string
	WorkspaceRoot   string
	TemplateSource  string
	TemplateRepo    string
	TemplatesDir    string
	Template        string
	WorkspaceDir    string
	MultilabNumeric int
	StateRoot       string
	Server          NetlabServerConfig
	TopologyPath    string
	ClabTarball     string
	K8sNamespace    string
	LabName         string
	TopologyName    string
}

func tarballNameFromSpec(spec netlabC9sRunSpec) string {
	tarballName := strings.TrimSpace(spec.ClabTarball)
	if tarballName == "" {
		tarballName = fmt.Sprintf("containerlab-%s.tar.gz", strings.TrimSpace(spec.Deployment))
	}
	return tarballName
}

func clabernetesWorkspaceNamespace(workspaceSlug string) string {
	workspaceSlug = strings.TrimSpace(workspaceSlug)
	if workspaceSlug == "" {
		return "ws"
	}
	return sanitizeKubeNameFallback("ws-"+workspaceSlug, "ws")
}

func clabernetesTopologyName(labName string) string {
	labName = strings.TrimSpace(labName)
	if labName == "" {
		return "topology"
	}
	return sanitizeKubeNameFallback(labName, "topology")
}

func (e *Engine) dispatchNetlabC9sTask(ctx context.Context, task *taskstore.TaskRecord, log Logger) error {
	if task == nil {
		return nil
	}
	var specIn netlabC9sTaskSpec
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
	// NOTE: netlab-c9s is cluster-native and must not depend on BYOS netlab servers.

	if strings.TrimSpace(specIn.TemplateSource) == "" {
		specIn.TemplateSource = "blueprints"
	}

	runSpec := netlabC9sRunSpec{
		TaskID:          task.ID,
		WorkspaceCtx:    pc,
		WorkspaceSlug:   strings.TrimSpace(pc.workspace.Slug),
		Username:        username,
		Environment:     specIn.Environment,
		SetOverrides:    specIn.SetOverrides,
		Action:          strings.TrimSpace(specIn.Action),
		Deployment:      strings.TrimSpace(specIn.Deployment),
		DeploymentID:    strings.TrimSpace(specIn.DeploymentID),
		WorkspaceRoot:   strings.TrimSpace(specIn.WorkspaceRoot),
		TemplateSource:  strings.TrimSpace(specIn.TemplateSource),
		TemplateRepo:    strings.TrimSpace(specIn.TemplateRepo),
		TemplatesDir:    strings.TrimSpace(specIn.TemplatesDir),
		Template:        strings.TrimSpace(specIn.Template),
		WorkspaceDir:    strings.TrimSpace(specIn.WorkspaceDir),
		MultilabNumeric: specIn.MultilabNumeric,
		StateRoot:       "",
		Server:          NetlabServerConfig{},
		TopologyPath:    strings.TrimSpace(specIn.TopologyPath),
		ClabTarball:     strings.TrimSpace(specIn.ClabTarball),
		K8sNamespace:    strings.TrimSpace(specIn.K8sNamespace),
		LabName:         strings.TrimSpace(specIn.LabName),
		TopologyName:    strings.TrimSpace(specIn.TopologyName),
	}
	action := strings.ToLower(strings.TrimSpace(runSpec.Action))
	if action == "" {
		action = "run"
	}
	return taskdispatch.WithTaskStep(ctx, e.db, task.ID, "netlab.c9s."+action, func() error {
		return e.runNetlabC9sTask(ctx, runSpec, log)
	})
}

func (e *Engine) runNetlabC9sTask(ctx context.Context, spec netlabC9sRunSpec, log Logger) error {
	if log == nil {
		log = noopLogger{}
	}
	if spec.TaskID > 0 {
		canceled, _ := e.taskCanceled(ctx, spec.TaskID)
		if canceled {
			return fmt.Errorf("netlab c9s job canceled")
		}
	}
	if spec.WorkspaceCtx == nil {
		return fmt.Errorf("workspace context unavailable")
	}

	action := strings.ToLower(strings.TrimSpace(spec.Action))
	switch action {
	case "", "deploy", "create", "start", "up":
		action = "deploy"
	case "destroy", "delete", "down", "stop":
		action = "destroy"
	default:
		return fmt.Errorf("invalid netlab c9s action (use deploy or destroy)")
	}

	ns := strings.TrimSpace(spec.K8sNamespace)
	if ns == "" {
		ns = clabernetesWorkspaceNamespace(spec.WorkspaceCtx.workspace.Slug)
	}
	labName := strings.TrimSpace(spec.LabName)
	if labName == "" {
		labName = containerlabLabName(spec.WorkspaceCtx.workspace.Slug, spec.Deployment)
	}
	topologyName := strings.TrimSpace(spec.TopologyName)
	if topologyName == "" {
		topologyName = clabernetesTopologyName(labName)
	}

	if action == "destroy" {
		clabSpec := clabernetesRunSpec{
			TaskID:       spec.TaskID,
			Action:       "destroy",
			Namespace:    ns,
			TopologyName: topologyName,
			LabName:      labName,
		}
		if err := e.runClabernetesTask(ctx, clabSpec, log); err != nil {
			return err
		}
		log.Infof("Cleaning orphaned c9s resources (topologyOwner=%s)", topologyName)
		if err := kubeDeleteOrphanedClabernetesResources(ctx, ns, topologyName); err != nil {
			return err
		}
		log.Infof("Orphaned c9s resources cleanup requested")
		deleted, err := kubeDeleteConfigMapsByLabel(ctx, ns, map[string]string{
			"skyforge-c9s-topology": topologyName,
		})
		if err != nil {
			return err
		}
		if deleted > 0 {
			log.Infof("C9s configmaps deleted: %d", deleted)
		}
		return nil
	}

	if strings.TrimSpace(spec.Template) == "" {
		return fmt.Errorf("netlab template is required")
	}
	if err := kubeEnsureNamespace(ctx, ns); err != nil {
		return err
	}

	topologyPath := strings.TrimSpace(spec.TopologyPath)
	if topologyPath == "" {
		// When we pass a bundle, the netlab API server writes topology.yml in the workdir.
		topologyPath = "topology.yml"
	}

	// Apply platform defaults for netlab `--set` before we run the generator.
	// This is intentionally done before `netlab create` so generated startup-config
	// snippets match what will run in-cluster.
	if len(e.cfg.NetlabC9sDefaultSetOverrides) > 0 {
		spec.SetOverrides = mergeNetlabSetOverrides(spec.SetOverrides, e.cfg.NetlabC9sDefaultSetOverrides)
	}

	var clabYAML []byte
	var nodeMounts map[string][]c9sFileFromConfigMap
	var generatorManifest *netlabC9sManifest
	if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.k8s-generate", func() error {
		var err error
		clabYAML, nodeMounts, generatorManifest, err = e.runNetlabC9sTaskK8sGenerator(ctx, spec, topologyPath, tarballNameFromSpec(spec), log)
		return err
	}); err != nil {
		return err
	}
	if envBool(spec.Environment, "SKYFORGE_NETLAB_C9S_ENABLE_NETLAB_INITIAL", true) {
		if generatorManifest == nil || generatorManifest.NetlabOutput == nil || len(generatorManifest.NetlabOutput.Chunks) == 0 {
			return fmt.Errorf("netlab initial enabled but generator output missing netlabOutput artifacts")
		}
	}

	topologyBytes, nodeMounts, nodeNameMapping, err := prepareC9sTopologyForDeploy(spec.TaskID, topologyName, labName, clabYAML, nodeMounts, e, log)
	if err != nil {
		return err
	}

	// Derive netlab `set` overrides to align netlab initial credentials with the NOS images
	// running in-cluster. Without this, netlab initial can fail its SSH readiness check with
	// "SSH server not ready after 100s" even when SSH banners are present (auth mismatch).
	derivedOverrides := deriveNetlabC9sSetOverridesFromClabYAML(topologyBytes)
	setOverrides := mergeNetlabSetOverrides(spec.SetOverrides, derivedOverrides)

	// Persist the node name mapping (original ↔ sanitized) so post-deploy steps
	// (netlab initial applier, debug tooling) can consistently address Kubernetes
	// services while keeping netlab artifacts in original node names.
	if err := kubeUpsertC9sNameMapConfigMap(ctx, ns, topologyName, nodeNameMapping); err != nil {
		return err
	}

	// Prefer startup-config injection (instead of post-start exec hacks).
	// This keeps netlab as the source-of-truth but lets Skyforge adapt the generated output
	// for clabernetes-native execution (files are mounted into the launcher, not the NOS container).
	//
	// Default enabled: without this, many netlab + clabernetes-native labs appear "ready"
	// before NOS is actually reachable/configured, and post-up config application becomes flaky.
	enableStartupConfigInjection := envBool(spec.Environment, "SKYFORGE_NETLAB_C9S_ENABLE_STARTUP_CONFIG_INJECTION", true)
	if enableStartupConfigInjection {
		if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.startup-config", func() error {
			var err error
			topologyBytes, nodeMounts, err = injectNetlabC9sStartupConfig(ctx, ns, topologyName, topologyBytes, nodeMounts, log)
			return err
		}); err != nil {
			return err
		}
	}

	clabSpec := clabernetesRunSpec{
		TaskID:             spec.TaskID,
		WorkspaceID:        strings.TrimSpace(spec.WorkspaceCtx.workspace.ID),
		Action:             "deploy",
		Namespace:          ns,
		TopologyName:       topologyName,
		LabName:            labName,
		TopologyYAML:       string(topologyBytes),
		Environment:        map[string]string{},
		FilesFromConfigMap: nodeMounts,
	}
	// Copy environment to avoid mutating the task spec and allow us to add internal hints.
	for k, v := range spec.Environment {
		if strings.TrimSpace(k) == "" {
			continue
		}
		clabSpec.Environment[k] = v
	}

	// Default to spreading NOS pods across Kubernetes nodes for performance.
	// Co-locating with the collector can be helpful for latency, but in practice it tends to
	// concentrate all nodes of a lab onto a single worker and can cause severe CPU contention
	// (slow SSH, slow Forward collection, etc.) unless resources and node sizing are perfect.
	preferColocate := envBool(spec.Environment, "SKYFORGE_C9S_PREFER_COLOCATE_WITH_COLLECTOR", false)
	preferredNode := ""
	if preferColocate && spec.WorkspaceCtx != nil {
		if nodeName, err := kubeCollectorNodeForUser(ctx, spec.WorkspaceCtx.claims.Username); err == nil {
			preferredNode = strings.TrimSpace(nodeName)
		}
	}

	deployOnce := func() error {
		return taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "c9s.deploy", func() error {
			return e.runClabernetesTask(ctx, clabSpec, log)
		})
	}

	if preferredNode != "" {
		// Prefer (but do not require) scheduling onto the same node as the user's collector.
		// This improves performance (local traffic, fewer cross-node hops) while still allowing
		// the scheduler to spread labs across the cluster if the preferred node is full.
		clabSpec.Environment["SKYFORGE_CLABERNETES_PREFERRED_NODE_HOSTNAME"] = preferredNode
	}
	// Default to tolerating control-plane taints so lab workloads can use all available KVM nodes.
	if _, ok := clabSpec.Environment["SKYFORGE_CLABERNETES_TOLERATE_CONTROL_PLANE"]; !ok {
		clabSpec.Environment["SKYFORGE_CLABERNETES_TOLERATE_CONTROL_PLANE"] = "true"
	}

	// Decide an effective scheduling mode before handing off to clabernetes task execution.
	// Supported operator values:
	// - pack/spread: respected as explicit choices.
	// - adaptive (or unset): select pack for small labs, spread for larger labs.
	mode, reason, nodeCount := resolveClabernetesSchedulingMode(clabSpec.Environment, string(topologyBytes))
	clabSpec.Environment["SKYFORGE_CLABERNETES_SCHEDULING_MODE"] = mode
	if log != nil {
		log.Infof("Clabernetes scheduling: mode=%s reason=%s nodes=%d", mode, reason, nodeCount)
	}

	if err := deployOnce(); err != nil {
		return err
	}

	// Run netlab-generated Linux configuration scripts (initial + routing) directly
	// inside the Linux pods. This mirrors netlab's "faster without Ansible" workflow.
	if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.linux-scripts", func() error {
		// Enable SSH on linux hosts by default so they can be used as Forward CLI endpoints.
		// Can be disabled per-run via env.
		enableLinuxSSH := envBool(spec.Environment, "SKYFORGE_NETLAB_C9S_LINUX_ENABLE_SSH", true)
		return runNetlabC9sLinuxScripts(ctx, ns, topologyName, topologyBytes, nodeMounts, enableLinuxSSH, log)
	}); err != nil {
		return err
	}

	// Capture a lightweight topology graph after deploy so the UI can render
	// resolved management IPs without querying netlab output.
	var graph *TopologyGraph
	var dep *WorkspaceDeployment

	captureErr := error(nil)
	graph, captureErr = e.captureC9sTopologyArtifact(ctx, spec, ns, topologyName, labName, topologyBytes, nodeNameMapping, log)
	if captureErr != nil {
		// Don't fail the run if topology capture fails; it is a best-effort UX enhancement.
		if log != nil {
			log.Infof("c9s topology capture failed: %v", captureErr)
		}
	}

	if graph != nil {
		depLoaded, depErr := e.loadDeployment(ctx, spec.WorkspaceCtx.workspace.ID, strings.TrimSpace(spec.DeploymentID))
		if depErr != nil {
			if log != nil {
				log.Infof("forward sync skipped: failed to load deployment: %v", depErr)
			}
		} else if depLoaded == nil {
			if log != nil {
				log.Infof("forward sync skipped: deployment not found")
			}
		} else {
			dep = depLoaded
		}
	}

	// Forward device import (best-effort) should happen as soon as management IPs are available
	// so Forward can start its own reachability checks early.
	if dep != nil && graph != nil {
		earlyConnectivityEnabled := envBool(spec.Environment, "SKYFORGE_FORWARD_CONNECTIVITY_EARLY", true)
		earlyConnectivitySeconds := envInt(spec.Environment, "SKYFORGE_FORWARD_CONNECTIVITY_EARLY_SECONDS", 300)
		earlyConnectivityConcurrency := envInt(spec.Environment, "SKYFORGE_FORWARD_CONNECTIVITY_EARLY_CONCURRENCY", 12)
		earlyConnectivityBatchSize := envInt(spec.Environment, "SKYFORGE_FORWARD_CONNECTIVITY_EARLY_BATCH", 10)

		// 1) Import devices/endpoints into Forward as soon as management IPs are available.
		// We intentionally do this before applying post-up config so Forward can start its
		// own reachability checks early.
		if _, err := e.syncForwardTopologyGraphDevices(ctx, spec.TaskID, spec.WorkspaceCtx, dep, graph, forwardSyncOptions{
			StartConnectivity: false,
			StartCollection:   false,
		}); err != nil {
			if log != nil {
				log.Infof("forward sync skipped: %v", err)
			}
		} else if log != nil {
			log.Infof("forward sync: devices uploaded (collection deferred)")
		}

		// 2) Start Forward connectivity tests as soon as each node becomes SSH-ready (SSH banner).
		// This runs concurrently with post-up config to reduce time-to-signal.
		if earlyConnectivityEnabled && earlyConnectivitySeconds > 0 {
			ctxEarly, cancel := context.WithTimeout(ctx, time.Duration(earlyConnectivitySeconds)*time.Second)
			defer cancel()
			go func() {
				_ = startForwardConnectivityAsNodesSSHReady(ctxEarly, spec.TaskID, e, spec.WorkspaceCtx, dep, graph, spec.Environment, earlyConnectivityConcurrency, earlyConnectivityBatchSize, log)
			}()
		}

	}

	// Apply netlab-generated device configuration using netlab's own `netlab initial`
	// workflow (Ansible playbooks + device-specific tasks). This avoids Skyforge-specific
	// config concatenation logic and keeps netlab as the source of truth.
	//
	// We run it after early Forward topology upload so Forward can start reachability
	// checks while configuration is being applied, but before starting Forward collection.
	enableNetlabInitial := envBool(spec.Environment, "SKYFORGE_NETLAB_C9S_ENABLE_NETLAB_INITIAL", true)
	if enableNetlabInitial {
		// Gate netlab initial on SSH readiness. Netlab initial relies on SSH/NETCONF access
		// to push config. Many vrnetlab-based nodes become "Running" long before they accept
		// SSH logins, and starting netlab initial too early results in authentication errors
		// (devices not fully booted yet).
		if graph != nil {
			sshReadySeconds := envInt(spec.Environment, "SKYFORGE_NETLAB_INITIAL_SSH_READY_SECONDS", envInt(spec.Environment, "SKYFORGE_FORWARD_SSH_READY_SECONDS", defaultForwardSSHReadySeconds))
			if sshReadySeconds > 0 {
				if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.ssh.ready", func() error {
					return waitForForwardSSHReady(ctx, spec.TaskID, e, graph, spec.Environment, time.Duration(sshReadySeconds)*time.Second, log)
				}); err != nil {
					return err
				}
			}
		}
		if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.apply", func() error {
			return e.runNetlabC9sApplierJob(ctx, ns, topologyName, setOverrides, spec.Environment, log)
		}); err != nil {
			return err
		}
	}

	// 4) Apply post-up config for supported NOS kinds (cfglets, SSH enable, etc).
	// This must happen before Forward collection starts, but should not be blocked by
	// Forward sync failures (lab should still be configured even if Forward is down).
	enableNOSPostUp := envBool(spec.Environment, "SKYFORGE_NETLAB_C9S_ENABLE_NOS_POSTUP", false)
	if enableNOSPostUp {
		if err := taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.nos-postup", func() error {
			return runNetlabC9sNOSPostUp(ctx, ns, topologyName, topologyBytes, nodeMounts, log)
		}); err != nil && log != nil {
			// Best-effort: lab is still usable even if cfglets fail.
			log.Infof("c9s post-up config failed (ignored): %v", err)
		}
	}

	// Optional: start connectivity tests in a single batch after post-up config.
	// Default is to start them earlier (per-node as SSH becomes ready).
	postupConnectivity := envBool(spec.Environment, "SKYFORGE_FORWARD_CONNECTIVITY_POSTUP", false)
	if dep != nil && graph != nil && postupConnectivity {
		_ = taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "forward.connectivity.start", func() error {
			delaySeconds := envInt(spec.Environment, "SKYFORGE_FORWARD_CONNECTIVITY_DELAY_SECONDS", 0)
			if delaySeconds > 0 {
				time.Sleep(time.Duration(delaySeconds) * time.Second)
			}
			if err := e.startForwardConnectivityTestsForDeployment(ctx, spec.TaskID, spec.WorkspaceCtx, dep, graph); err != nil {
				if log != nil {
					log.Infof("forward sync skipped: %v", err)
				}
				return err
			}
			if log != nil {
				log.Infof("forward sync: connectivity test started (post-up)")
			}
			return nil
		})
	}

	// 5) Start collection after post-up config has been applied (best-effort).
	// NOTE: "Topology ready" in Kubernetes is not the same thing as "SSH ready" for the NOS.
	// Many vrnetlab/QEMU-based NOS images accept pod readiness quickly but refuse port 22 for
	// minutes while still booting. Starting Forward collection too early results in noisy
	// "device unreachable" signals and wastes time. We therefore gate collection on an SSH
	// banner check (configurable timeout).
	if dep != nil {
		sshReadySeconds := envInt(spec.Environment, "SKYFORGE_FORWARD_SSH_READY_SECONDS", defaultForwardSSHReadySeconds)
		if sshReadySeconds > 0 && graph != nil {
			_ = taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "forward.ssh.ready", func() error {
				if err := waitForForwardSSHReady(ctx, spec.TaskID, e, graph, spec.Environment, time.Duration(sshReadySeconds)*time.Second, log); err != nil {
					// Keep the lab up even if collection is blocked; surface a clear error in the run.
					if log != nil {
						log.Infof("forward sync wait timed out: %v", err)
					}
					return err
				}
				return nil
			})
		}

		_ = taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "forward.collection.start", func() error {
			if err := e.startForwardCollectionForDeployment(ctx, spec.TaskID, spec.WorkspaceCtx, dep); err != nil {
				if log != nil {
					log.Infof("forward sync skipped: %v", err)
				}
				return err
			}
			if log != nil {
				log.Infof("forward sync: collection started")
			}
			return nil
		})
	}

	// Store a bundle of generated artifacts in object storage for browsing and debugging.
	// This is best-effort and should never fail the deployment run.
	_ = taskdispatch.WithTaskStep(ctx, e.db, spec.TaskID, "netlab.c9s.artifacts", func() error {
		err := storeNetlabC9sArtifacts(ctx, e.cfg, netlabC9sArtifactsSpec{
			TaskID:        spec.TaskID,
			WorkspaceID:   strings.TrimSpace(spec.WorkspaceCtx.workspace.ID),
			TopologyName:  topologyName,
			LabName:       labName,
			Namespace:     ns,
			ClabYAMLRaw:   clabYAML,
			TopologyYAML:  topologyBytes,
			TopologyGraph: graph,
			NodeMounts:    nodeMounts,
		}, log)
		if err != nil && log != nil {
			log.Infof("netlab-c9s artifact upload failed: %v", err)
		}
		return nil
	})

	return nil
}

func mergeNetlabSetOverrides(userOverrides, derivedOverrides []string) []string {
	keyOf := func(line string) string {
		line = strings.TrimSpace(line)
		if line == "" {
			return ""
		}
		if i := strings.Index(line, "="); i >= 0 {
			return strings.TrimSpace(line[:i])
		}
		return ""
	}

	seen := map[string]bool{}
	out := make([]string, 0, len(userOverrides)+len(derivedOverrides))
	for _, raw := range userOverrides {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		out = append(out, line)
		if k := keyOf(line); k != "" {
			seen[k] = true
		}
	}
	for _, raw := range derivedOverrides {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		k := keyOf(line)
		if k != "" && seen[k] {
			continue
		}
		out = append(out, line)
		if k != "" {
			seen[k] = true
		}
	}
	return out
}

func deriveNetlabC9sSetOverridesFromClabYAML(clabYAML []byte) []string {
	if len(clabYAML) == 0 {
		return nil
	}
	var topo map[string]any
	if err := yaml.Unmarshal(clabYAML, &topo); err != nil {
		return nil
	}
	topology, _ := topo["topology"].(map[string]any)
	nodesAny, _ := topology["nodes"].(map[string]any)
	if len(nodesAny) == 0 {
		return nil
	}

	type deviceInfo struct {
		deviceKey string
		image     string
	}
	byKey := map[string]deviceInfo{}
	for _, nodeAny := range nodesAny {
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		image := strings.TrimSpace(fmt.Sprintf("%v", cfg["image"]))
		deviceKey := netlabDeviceKeyForClabNode(kind, image)
		if deviceKey == "" {
			continue
		}
		if existing, ok := byKey[deviceKey]; ok && existing.image != "" {
			continue
		}
		byKey[deviceKey] = deviceInfo{deviceKey: deviceKey, image: image}
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(keys)*2)
	for _, deviceKey := range keys {
		info := byKey[deviceKey]
		cred, ok := netlabCredentialForDevice(info.deviceKey, info.image)
		if !ok {
			continue
		}
		lines = append(lines, fmt.Sprintf("devices.%s.group_vars.ansible_user=%s", info.deviceKey, cred.Username))
		lines = append(lines, fmt.Sprintf("devices.%s.group_vars.ansible_ssh_pass=%s", info.deviceKey, cred.Password))
	}
	return lines
}

// netlabDeviceKeyForClabNode attempts to map a containerlab node kind/image to the
// netlab device key used by `--set devices.<device>.group_vars.*`.
//
// Example: containerlab kind "ceos" should map to netlab device "eos".
func netlabDeviceKeyForClabNode(kind, image string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	image = strings.ToLower(strings.TrimSpace(image))
	image = strings.TrimPrefix(image, "ghcr.io/forwardnetworks/")

	// Prefer a direct match against known netlab device keys.
	if kind != "" {
		for _, set := range netlabDefaults.Sets {
			if set.Device != "" && strings.EqualFold(strings.TrimSpace(set.Device), kind) {
				return strings.ToLower(strings.TrimSpace(set.Device))
			}
		}
	}

	// Otherwise, derive device key from the image prefix catalog.
	if image != "" {
		for _, set := range netlabDefaults.Sets {
			if set.Device == "" || set.ImagePrefix == "" {
				continue
			}
			if strings.HasPrefix(image, strings.ToLower(strings.TrimSpace(set.ImagePrefix))) {
				return strings.ToLower(strings.TrimSpace(set.Device))
			}
		}
	}

	// Known containerlab kind -> netlab device aliases.
	switch kind {
	case "ceos":
		return "eos"
	}

	return kind
}

func envInt(env map[string]string, key string, def int) int {
	raw := strings.TrimSpace(envString(env, key))
	if raw == "" {
		return def
	}
	var n int
	_, err := fmt.Sscanf(raw, "%d", &n)
	if err != nil {
		return def
	}
	return n
}

const (
	// Keep the default SSH readiness gate bounded to 15m so failed boots do not
	// monopolize workers for 30m by default.
	defaultForwardSSHReadySeconds     = 900
	defaultForwardSSHDialTimeoutMS    = 4000
	defaultForwardSSHReadTimeoutMS    = 4000
	defaultForwardSSHProbeConsecutive = 1
)

func resolveClabernetesSchedulingMode(env map[string]string, topologyYAML string) (mode string, reason string, nodeCount int) {
	rawMode := strings.ToLower(strings.TrimSpace(envString(env, "SKYFORGE_CLABERNETES_SCHEDULING_MODE")))
	switch rawMode {
	case "pack":
		return "pack", "explicit", containerlabNodeCount(topologyYAML)
	case "spread":
		return "spread", "explicit", containerlabNodeCount(topologyYAML)
	}

	nodeCount = containerlabNodeCount(topologyYAML)
	if envBool(env, "SKYFORGE_CLABERNETES_HEAVY_NOS_SPREAD_OVERRIDE", true) && topologyHasHeavyNOS(topologyYAML) {
		switch rawMode {
		case "":
			reason = "default-adaptive-heavy-nos"
		case "adaptive":
			reason = "adaptive-heavy-nos"
		default:
			reason = "invalid-adaptive-heavy-nos"
		}
		return "spread", reason, nodeCount
	}

	packMaxNodes := envInt(env, "SKYFORGE_CLABERNETES_ADAPTIVE_PACK_MAX_NODES", 4)
	if packMaxNodes <= 0 {
		packMaxNodes = 4
	}
	if nodeCount > 0 && nodeCount <= packMaxNodes {
		mode = "pack"
	} else if nodeCount == 0 {
		mode = "pack"
	} else {
		mode = "spread"
	}

	switch rawMode {
	case "":
		reason = "default-adaptive"
	case "adaptive":
		reason = "adaptive"
	default:
		reason = "invalid-adaptive"
	}
	return mode, reason, nodeCount
}

func topologyHasHeavyNOS(containerlabYAML string) bool {
	specs, err := containerlabNodeSpecs(containerlabYAML)
	if err != nil || len(specs) == 0 {
		return false
	}
	for _, spec := range specs {
		if isHeavyNOSNode(spec.Kind, spec.Image) {
			return true
		}
	}
	return false
}

func isHeavyNOSNode(kind, image string) bool {
	kind = strings.ToLower(strings.TrimSpace(kind))
	image = strings.ToLower(strings.TrimSpace(image))
	image = strings.TrimPrefix(image, "ghcr.io/forwardnetworks/")

	switch kind {
	case "nxos", "vr-n9kv", "n9kv", "vmx", "vr-vmx", "vqfx", "vr-vqfx", "vptx", "vr-vptx", "cat8000v", "vr-cat8000v":
		return true
	}

	heavyHints := []string{
		"n9kv",
		"nxos",
		"vmx",
		"vqfx",
		"vptx",
		"cat8000v",
	}
	for _, hint := range heavyHints {
		if strings.Contains(image, hint) {
			return true
		}
	}
	return false
}

func containerlabNodeCount(containerlabYAML string) int {
	containerlabYAML = strings.TrimSpace(containerlabYAML)
	if containerlabYAML == "" {
		return 0
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(containerlabYAML), &doc); err != nil {
		return 0
	}
	topology, ok := doc["topology"].(map[string]any)
	if !ok || topology == nil {
		return 0
	}
	nodes, ok := topology["nodes"].(map[string]any)
	if !ok || nodes == nil {
		return 0
	}
	return len(nodes)
}

type forwardSSHProbeConfig struct {
	DialTimeout time.Duration
	ReadTimeout time.Duration
	Consecutive int
}

func forwardSSHProbeConfigFromEnv(env map[string]string) forwardSSHProbeConfig {
	cfg := forwardSSHProbeConfig{
		DialTimeout: time.Duration(defaultForwardSSHDialTimeoutMS) * time.Millisecond,
		ReadTimeout: time.Duration(defaultForwardSSHReadTimeoutMS) * time.Millisecond,
		Consecutive: defaultForwardSSHProbeConsecutive,
	}
	if ms := envInt(env, "SKYFORGE_FORWARD_SSH_PROBE_DIAL_TIMEOUT_MS", defaultForwardSSHDialTimeoutMS); ms > 0 {
		cfg.DialTimeout = time.Duration(ms) * time.Millisecond
	}
	if ms := envInt(env, "SKYFORGE_FORWARD_SSH_PROBE_READ_TIMEOUT_MS", defaultForwardSSHReadTimeoutMS); ms > 0 {
		cfg.ReadTimeout = time.Duration(ms) * time.Millisecond
	}
	if n := envInt(env, "SKYFORGE_FORWARD_SSH_PROBE_CONSECUTIVE", defaultForwardSSHProbeConsecutive); n > 0 {
		cfg.Consecutive = n
	}

	if cfg.DialTimeout < 500*time.Millisecond {
		cfg.DialTimeout = 500 * time.Millisecond
	}
	if cfg.DialTimeout > 30*time.Second {
		cfg.DialTimeout = 30 * time.Second
	}
	if cfg.ReadTimeout < 500*time.Millisecond {
		cfg.ReadTimeout = 500 * time.Millisecond
	}
	if cfg.ReadTimeout > 30*time.Second {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.Consecutive < 1 {
		cfg.Consecutive = 1
	}
	if cfg.Consecutive > 5 {
		cfg.Consecutive = 5
	}
	return cfg
}

type forwardSSHReadyTarget struct {
	Name string
	Host string
	Type string // "classic" or "endpoint"
}

func startForwardConnectivityAsNodesSSHReady(
	ctx context.Context,
	taskID int,
	e *Engine,
	pc *workspaceContext,
	dep *WorkspaceDeployment,
	graph *TopologyGraph,
	environment map[string]string,
	concurrency int,
	batchSize int,
	log Logger,
) error {
	if e == nil || pc == nil || dep == nil || graph == nil {
		return nil
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	if batchSize <= 0 {
		batchSize = 10
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

	getString := func(key string) string {
		raw, ok := cfgAny[key]
		if !ok {
			return ""
		}
		if s, ok := raw.(string); ok {
			return strings.TrimSpace(s)
		}
		return strings.TrimSpace(fmt.Sprintf("%v", raw))
	}

	collectorConfigID := getString(forwardCollectorIDKey)
	forwardCfg, err := e.forwardConfigForUserCollector(ctx, pc.claims.Username, collectorConfigID)
	if err != nil || forwardCfg == nil {
		return err
	}
	client, err := newForwardClient(*forwardCfg)
	if err != nil {
		return err
	}

	targets := make([]forwardSSHReadyTarget, 0, len(graph.Nodes))
	for _, n := range graph.Nodes {
		name := strings.TrimSpace(n.Label)
		if name == "" {
			name = strings.TrimSpace(n.ID)
		}
		if name == "" {
			continue
		}
		host := strings.TrimSpace(n.MgmtHost)
		if host == "" {
			host = strings.TrimSpace(n.MgmtIP)
		}
		if host == "" {
			continue
		}
		t := "classic"
		if strings.EqualFold(strings.TrimSpace(n.Kind), "linux") {
			t = "endpoint"
		}
		targets = append(targets, forwardSSHReadyTarget{Name: name, Host: host, Type: t})
	}
	if len(targets) == 0 {
		return nil
	}
	probeCfg := forwardSSHProbeConfigFromEnv(environment)

	if log != nil {
		log.Infof(
			"forward sync: early connectivity armed (targets=%d concurrency=%d sshProbeDial=%s sshProbeRead=%s sshProbeConsecutive=%d)",
			len(targets),
			concurrency,
			probeCfg.DialTimeout,
			probeCfg.ReadTimeout,
			probeCfg.Consecutive,
		)
	}

	readyCh := make(chan forwardSSHReadyTarget, 64)
	sem := make(chan struct{}, concurrency)

	var wg sync.WaitGroup
	for _, tgt := range targets {
		tgt := tgt
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			backoff := 1 * time.Second
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if forwardSSHBannerReadyWithConfig(ctx, tgt.Host, probeCfg) {
					select {
					case readyCh <- tgt:
					case <-ctx.Done():
					}
					return
				}

				timer := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				if backoff < 60*time.Second {
					backoff *= 2
					if backoff > 60*time.Second {
						backoff = 60 * time.Second
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(readyCh)
	}()

	flush := func(classic []string, endpoints []string) {
		if len(classic) > 0 {
			if err := forwardBulkStartConnectivityTests(ctx, client, networkID, classic); err != nil && log != nil {
				log.Infof("forward sync: early connectivity start failed (devices=%d): %v", len(classic), err)
			} else if log != nil {
				log.Infof("forward sync: early connectivity started (devices=%d)", len(classic))
			}
		}
		if len(endpoints) > 0 {
			if err := forwardBulkStartConnectivityTestsTyped(ctx, client, networkID, endpoints, "endpoint"); err != nil && log != nil {
				log.Infof("forward sync: early endpoint connectivity start failed (endpoints=%d): %v", len(endpoints), err)
			} else if log != nil {
				log.Infof("forward sync: early endpoint connectivity started (endpoints=%d)", len(endpoints))
			}
		}
	}

	classicBatch := []string{}
	endpointBatch := []string{}
	ticker := time.NewTicker(750 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case tgt, ok := <-readyCh:
			if !ok {
				flush(classicBatch, endpointBatch)
				return nil
			}
			if tgt.Type == "endpoint" {
				endpointBatch = append(endpointBatch, tgt.Name)
			} else {
				classicBatch = append(classicBatch, tgt.Name)
			}
			if len(classicBatch)+len(endpointBatch) >= batchSize {
				flush(classicBatch, endpointBatch)
				classicBatch = []string{}
				endpointBatch = []string{}
			}
		case <-ticker.C:
			if len(classicBatch) > 0 || len(endpointBatch) > 0 {
				flush(classicBatch, endpointBatch)
				classicBatch = []string{}
				endpointBatch = []string{}
			}
		}
	}
}

func waitForForwardSSHReady(ctx context.Context, taskID int, e *Engine, graph *TopologyGraph, environment map[string]string, timeout time.Duration, log Logger) error {
	if graph == nil {
		return nil
	}
	if timeout <= 0 {
		return nil
	}

	// Only gate on NOS nodes we intend to sync into Forward. Linux hosts are handled
	// separately (as endpoints) and should not block network creation.
	targets := make([]TopologyNode, 0, len(graph.Nodes))
	for _, n := range graph.Nodes {
		kind := strings.ToLower(strings.TrimSpace(n.Kind))
		if kind == "" {
			// If kind is missing, assume it is a NOS node.
			kind = "unknown"
		}
		if kind == "linux" {
			continue
		}
		if strings.TrimSpace(n.MgmtHost) == "" && strings.TrimSpace(n.MgmtIP) == "" {
			continue
		}
		targets = append(targets, n)
	}
	if len(targets) == 0 {
		return nil
	}
	probeCfg := forwardSSHProbeConfigFromEnv(environment)

	start := time.Now()
	deadline := start.Add(timeout)
	if log != nil {
		log.Infof(
			"forward ssh readiness: waiting for ssh on nodes=%d timeout=%s sshProbeDial=%s sshProbeRead=%s sshProbeConsecutive=%d",
			len(targets),
			timeout,
			probeCfg.DialTimeout,
			probeCfg.ReadTimeout,
			probeCfg.Consecutive,
		)
	}
	type readyEvent struct {
		index   int
		elapsed time.Duration
	}

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	readyCh := make(chan readyEvent, len(targets))
	var wg sync.WaitGroup
	for idx, node := range targets {
		idx := idx
		node := node
		host := strings.TrimSpace(node.MgmtHost)
		if host == "" {
			host = strings.TrimSpace(node.MgmtIP)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			nodeStart := time.Now()
			for {
				select {
				case <-waitCtx.Done():
					return
				default:
				}
				// Prefer a real SSH banner read instead of a bare TCP connect. Some NOS images
				// accept TCP connections early but drop/reset them before SSH is usable.
				if forwardSSHBannerReadyWithConfig(waitCtx, host, probeCfg) {
					select {
					case readyCh <- readyEvent{index: idx, elapsed: time.Since(nodeStart)}:
					case <-waitCtx.Done():
					}
					return
				}
				timer := time.NewTimer(2 * time.Second)
				select {
				case <-waitCtx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	}
	defer wg.Wait()

	ready := map[int]time.Duration{}
	progressTicker := time.NewTicker(10 * time.Second)
	cancelPollTicker := time.NewTicker(2 * time.Second)
	defer progressTicker.Stop()
	defer cancelPollTicker.Stop()

	unresolvedList := func() []string {
		out := make([]string, 0, len(targets))
		for i, node := range targets {
			if _, ok := ready[i]; ok {
				continue
			}
			host := strings.TrimSpace(node.MgmtHost)
			if host == "" {
				host = strings.TrimSpace(node.MgmtIP)
			}
			label := strings.TrimSpace(node.Label)
			if label == "" {
				label = strings.TrimSpace(node.ID)
			}
			if label == "" {
				label = host
			}
			out = append(out, fmt.Sprintf("%s(%s)", label, host))
		}
		sort.Strings(out)
		return out
	}

	for len(ready) < len(targets) {
		select {
		case evt := <-readyCh:
			if _, ok := ready[evt.index]; ok {
				continue
			}
			ready[evt.index] = evt.elapsed
			node := targets[evt.index]
			host := strings.TrimSpace(node.MgmtHost)
			if host == "" {
				host = strings.TrimSpace(node.MgmtIP)
			}
			label := strings.TrimSpace(node.Label)
			if label == "" {
				label = strings.TrimSpace(node.ID)
			}
			if log != nil {
				log.Infof(
					"forward ssh readiness: ok (%d/%d) label=%s host=%s elapsed=%s",
					len(ready),
					len(targets),
					label,
					host,
					evt.elapsed.Truncate(time.Second),
				)
			}
		case <-progressTicker.C:
			if log != nil {
				remaining := time.Until(deadline).Truncate(time.Second)
				if remaining < 0 {
					remaining = 0
				}
				unresolved := unresolvedList()
				if len(unresolved) > 6 {
					unresolved = unresolved[:6]
				}
				log.Infof(
					"forward ssh readiness: waiting ready=%d/%d unresolved=%s overallElapsed=%s remaining=%s",
					len(ready),
					len(targets),
					strings.Join(unresolved, ", "),
					time.Since(start).Truncate(time.Second),
					remaining,
				)
			}
		case <-cancelPollTicker.C:
			if taskID > 0 && e != nil {
				canceled, _ := e.taskCanceled(ctx, taskID)
				if canceled {
					return fmt.Errorf("forward sync wait canceled")
				}
			}
		case <-waitCtx.Done():
			if taskID > 0 && e != nil {
				canceled, _ := e.taskCanceled(ctx, taskID)
				if canceled {
					return fmt.Errorf("forward sync wait canceled")
				}
			}
			unresolved := unresolvedList()
			if len(unresolved) == 0 {
				return fmt.Errorf("forward sync wait canceled")
			}
			return fmt.Errorf(
				"forward sync wait timed out waiting for ssh (ready %d/%d): %s",
				len(ready),
				len(targets),
				strings.Join(unresolved, ", "),
			)
		}
	}

	if log != nil {
		log.Infof("forward ssh readiness ok: nodes=%d elapsed=%s", len(targets), time.Since(start).Truncate(time.Second))
	}
	return nil
}

func forwardSSHBannerReady(ctx context.Context, host string) bool {
	return forwardSSHBannerReadyWithConfig(ctx, host, forwardSSHProbeConfig{})
}

func forwardSSHBannerReadyWithConfig(ctx context.Context, host string, cfg forwardSSHProbeConfig) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if cfg.DialTimeout <= 0 {
		cfg = forwardSSHProbeConfigFromEnv(nil)
	}

	// Some NOS images briefly emit an SSH banner and then reset connections while
	// still booting. Make the required consecutive banners configurable.
	for i := 0; i < cfg.Consecutive; i++ {
		if !forwardSSHBannerReadyOnce(ctx, host, cfg.DialTimeout, cfg.ReadTimeout) {
			return false
		}
		// Small jitter between attempts to avoid hitting the same transient window.
		if i+1 < cfg.Consecutive {
			time.Sleep(250 * time.Millisecond)
		}
	}
	return true
}

func forwardSSHBannerReadyOnce(ctx context.Context, host string, dialTimeout time.Duration, readTimeout time.Duration) bool {
	ctxDial, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := (&net.Dialer{}).DialContext(ctxDial, "tcp", net.JoinHostPort(host, "22"))
	cancel()
	if err != nil || conn == nil {
		return false
	}
	defer conn.Close()

	// Some vrnetlab devices (notably QEMU usernet hostfwd -> guest ssh) can accept the TCP
	// connection quickly but take >750ms before emitting the SSH banner. Use a slightly
	// longer read deadline to avoid false negatives while still keeping probes fast.
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	return bytes.Equal(buf, []byte("SSH-"))
}

func (e *Engine) captureC9sTopologyArtifact(ctx context.Context, spec netlabC9sRunSpec, ns, topologyName, labName string, topologyYAML []byte, nodeNameMapping map[string]string, log Logger) (*TopologyGraph, error) {
	if e == nil || e.db == nil || spec.TaskID <= 0 || spec.WorkspaceCtx == nil || strings.TrimSpace(spec.WorkspaceCtx.workspace.ID) == "" {
		return nil, fmt.Errorf("invalid task context")
	}
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" {
		return nil, fmt.Errorf("namespace and topology name are required")
	}

	pods, err := kubeListPods(ctx, ns, map[string]string{
		"clabernetes/topologyOwner": topologyName,
	})
	if err != nil {
		return nil, err
	}
	podInfo := map[string]TopologyNode{}
	for _, pod := range pods {
		node := strings.TrimSpace(pod.Metadata.Labels["clabernetes/topologyNode"])
		if node == "" {
			continue
		}
		mgmtIP := strings.TrimSpace(pod.Status.PodIP)
		svcName := fmt.Sprintf("%s-%s", topologyName, node)
		podInfo[node] = TopologyNode{
			ID:       node,
			Label:    node,
			MgmtIP:   mgmtIP,
			MgmtHost: kubeServiceFQDN(svcName, ns),
			PingIP:   mgmtIP,
			Status:   strings.TrimSpace(pod.Status.Phase),
		}
	}

	graph, err := containerlabYAMLBytesToTopologyGraph(topologyYAML, podInfo)
	if err != nil {
		return nil, err
	}
	if len(nodeNameMapping) > 0 {
		for i := range graph.Nodes {
			id := strings.TrimSpace(graph.Nodes[i].ID)
			if id == "" {
				continue
			}
			if orig := strings.TrimSpace(nodeNameMapping[id]); orig != "" {
				graph.Nodes[i].Label = orig
			}
		}
	}
	graph.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	graphBytes, err := json.Marshal(graph)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(labName) == "" {
		labName = topologyName
	}
	key := fmt.Sprintf("topology/netlab-c9s/%s.json", sanitizeArtifactKeySegment(labName))
	ctxPut, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	putKey, err := putWorkspaceArtifact(ctxPut, e.cfg, spec.WorkspaceCtx.workspace.ID, key, graphBytes, "application/json")
	if err != nil {
		if isObjectStoreNotConfigured(err) {
			if log != nil {
				log.Infof("c9s topology capture skipped: %v", err)
			}
			return graph, nil
		}
		return nil, err
	}
	e.setTaskMetadataKey(spec.TaskID, "topologyKey", putKey)
	if log != nil {
		log.Infof("c9s topology artifact stored: %s", putKey)
	}
	return graph, nil
}

func prepareC9sTopologyForDeploy(taskID int, topologyName, labName string, clabYAML []byte, nodeMounts map[string][]c9sFileFromConfigMap, e *Engine, log Logger) ([]byte, map[string][]c9sFileFromConfigMap, map[string]string, error) {
	if log == nil {
		log = noopLogger{}
	}
	labName = strings.TrimSpace(labName)
	topologyName = strings.TrimSpace(topologyName)
	if len(clabYAML) == 0 {
		return nil, nil, nil, fmt.Errorf("clab.yml is empty")
	}

	// Sanitize node names to DNS-1035 labels so clabernetes can derive K8s resource names.
	sanitizedYAML, mapping, err := sanitizeContainerlabYAMLForClabernetes(string(clabYAML))
	if err != nil {
		return nil, nil, nil, err
	}
	if sanitizedYAML != "" {
		clabYAML = []byte(sanitizedYAML)
	}
	reverseMapping := map[string]string{}
	for orig, sanitized := range mapping {
		orig = strings.TrimSpace(orig)
		sanitized = strings.TrimSpace(sanitized)
		if orig == "" || sanitized == "" {
			continue
		}
		reverseMapping[sanitized] = orig
	}
	if len(mapping) > 0 && len(nodeMounts) > 0 {
		out := map[string][]c9sFileFromConfigMap{}
		for node, mounts := range nodeMounts {
			newNode := strings.TrimSpace(node)
			if mapped, ok := mapping[newNode]; ok {
				newNode = mapped
			}
			if newNode == "" {
				continue
			}
			for i := range mounts {
				for old, newName := range mapping {
					mounts[i].FilePath = strings.ReplaceAll(mounts[i].FilePath, "/node_files/"+old+"/", "/node_files/"+newName+"/")
				}
			}
			out[newNode] = mounts
		}
		nodeMounts = out
	}

	var topo map[string]any
	if err := yaml.Unmarshal(clabYAML, &topo); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse clab.yml: %w", err)
	}
	if topo == nil {
		topo = map[string]any{}
	}
	if labName != "" {
		topo["name"] = labName
	}

	// Ensure we always have a node name mapping ConfigMap (even when no sanitization was needed).
	//
	// The netlab applier job expects a mapping from Kubernetes-safe node names (as used by clabernetes)
	// back to the original netlab node names. When sanitizeContainerlabYAMLForClabernetes makes no
	// changes, `mapping` is empty and `reverseMapping` would otherwise remain empty which prevents
	// the ConfigMap from being created and makes the applier fail.
	//
	// For the common case where node names are already DNS-safe, this becomes an identity mapping.
	if topology, ok := topo["topology"].(map[string]any); ok {
		if nodes, ok := topology["nodes"].(map[string]any); ok {
			for node := range nodes {
				nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
				if nodeName == "" {
					continue
				}
				if _, ok := reverseMapping[nodeName]; !ok {
					reverseMapping[nodeName] = nodeName
				}
			}
		}
	}

	// Rewrite vrnetlab image references into our GHCR mirror so clabernetes can pull them.
	//
	// Netlab templates often reference upstream tags like "vrnetlab/vr-vmx:18.2R1.9" which are
	// not reliably available via DockerHub. We mirror vrnetlab images under:
	//   ghcr.io/forwardnetworks/vrnetlab/<name>:<tag>
	//
	// This is an adaptation layer; netlab remains the source-of-truth for config generation.
	rewrittenVrnetlabNodes := 0
	if topology, ok := topo["topology"].(map[string]any); ok {
		if nodes, ok := topology["nodes"].(map[string]any); ok {
			for node, nodeAny := range nodes {
				cfg, ok := nodeAny.(map[string]any)
				if !ok || cfg == nil {
					continue
				}
				image := strings.TrimSpace(fmt.Sprintf("%v", cfg["image"]))
				if image == "" {
					continue
				}
				if rewritten, ok := rewriteVrnetlabImageForCluster(image); ok && strings.TrimSpace(rewritten) != "" && rewritten != image {
					cfg["image"] = rewritten
					nodes[node] = cfg
					rewrittenVrnetlabNodes++
				}

				// Some vrnetlab images rely on runtime args that containerlab normally injects.
				// In clabernetes we run images "as-is", so provide minimal kind-specific cmd
				// overrides needed for native mode.
				//
				// CSR 1000v: without `--connection-mode tc`, vrnetlab does not create tap netdevs
				// (`-netdev ... id=p01`) and QEMU crashes with "can't find value 'p01'".
				imgLower := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["image"])))
				kindLower := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
				if (kindLower == "csr" || strings.Contains(imgLower, "/vrnetlab/vr-csr")) && cfg["cmd"] == nil {
					cfg["cmd"] = "--connection-mode tc"
					nodes[node] = cfg
				}
				// NX-OSv 9Kv: the vrnetlab launcher defaults to `--connection-mode vrxcon`, which
				// does not create tap netdevs for the container interfaces in our clabernetes
				// native-mode model. Force tc datapath mode to match containerlab semantics.
				if (kindLower == "nxos" || kindLower == "n9kv" || kindLower == "cisco_n9kv" || strings.Contains(imgLower, "/vrnetlab/vr-n9kv")) && cfg["cmd"] == nil {
					cfg["cmd"] = "--connection-mode tc"
					nodes[node] = cfg
				}
			}
			topology["nodes"] = nodes
		}
		topo["topology"] = topology
	}
	if rewrittenVrnetlabNodes > 0 {
		log.Infof("c9s: rewritten vrnetlab image(s): nodes=%d", rewrittenVrnetlabNodes)
	}

	// ASAv (vrnetlab/cisco_asav) expects container interface names like eth1, eth2, ...
	// (it relies on vrnetlab's "grep eth" style interface discovery at boot).
	//
	// Netlab's device definition for ASAv uses interface names like GigabitEthernet0/0.
	// That is fine for the *guest* naming, but the *container* Linux ifnames must be
	// eth* to allow vrnetlab to detect the provisioned dataplane interfaces and boot.
	//
	// Netlab can be configured to generate eth* names (clab.interface.name), but to
	// avoid depending on generator image contents, patch the generated clab.yml here.
	if topology, ok := topo["topology"].(map[string]any); ok {
		nodes, _ := topology["nodes"].(map[string]any)
		linksAny, _ := topology["links"].([]any)
		if len(nodes) > 0 && len(linksAny) > 0 {
			asavNodes := map[string]struct{}{}
			for node, nodeAny := range nodes {
				cfg, ok := nodeAny.(map[string]any)
				if !ok || cfg == nil {
					continue
				}
				kindLower := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
				imgLower := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["image"])))
				if kindLower == "cisco_asav" || strings.Contains(imgLower, "/vrnetlab/cisco_asav") {
					asavNodes[strings.TrimSpace(fmt.Sprintf("%v", node))] = struct{}{}
				}
			}
			if len(asavNodes) > 0 {
				nextIdx := map[string]int{}
				for n := range asavNodes {
					nextIdx[n] = 1 // eth0 is mgmt, dataplane starts at eth1
				}
				changed := 0
				for li, linkAny := range linksAny {
					lm, ok := linkAny.(map[string]any)
					if !ok || lm == nil {
						continue
					}
					epsAny, ok := lm["endpoints"].([]any)
					if !ok || len(epsAny) == 0 {
						continue
					}
					outEps := make([]any, 0, len(epsAny))
					for _, epAny := range epsAny {
						ep := strings.TrimSpace(fmt.Sprintf("%v", epAny))
						if ep == "" {
							outEps = append(outEps, epAny)
							continue
						}
						parts := strings.SplitN(ep, ":", 2)
						if len(parts) != 2 {
							outEps = append(outEps, epAny)
							continue
						}
						n := strings.TrimSpace(parts[0])
						if _, ok := asavNodes[n]; !ok {
							outEps = append(outEps, epAny)
							continue
						}
						idx := nextIdx[n]
						nextIdx[n] = idx + 1
						outEps = append(outEps, fmt.Sprintf("%s:eth%d", n, idx))
						changed++
					}
					lm["endpoints"] = outEps
					linksAny[li] = lm
				}
				if changed > 0 {
					topology["links"] = linksAny
					topo["topology"] = topology
					log.Infof("c9s: asav: rewritten dataplane endpoints to eth*: endpoints=%d", changed)
				}
			}
		}
	}

	// Rewrite bind sources to the mounted file paths (only for node_files paths).
	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	if topology, ok := topo["topology"].(map[string]any); ok {
		if nodes, ok := topology["nodes"].(map[string]any); ok {
			for node, nodeAny := range nodes {
				nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
				cfg, ok := nodeAny.(map[string]any)
				if !ok || cfg == nil {
					continue
				}
				kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
				// Some netlab-generated binds (notably /etc/hosts) point at a directory that is
				// populated via filesFromConfigMap, where the actual file lives under
				// `<mountRoot>/node_files/<rel>/<configMapPath>`.
				filePathForMountDir := map[string]string{}
				if nodeMounts != nil {
					if mounts, ok := nodeMounts[nodeName]; ok {
						for _, m := range mounts {
							if strings.TrimSpace(m.FilePath) == "" || strings.TrimSpace(m.ConfigMapPath) == "" {
								continue
							}
							// nodeMounts can contain either relative ("node_files/...") or absolute
							// ("/tmp/skyforge-c9s/...") file paths. Normalize to the absolute mount
							// root so we can rewrite netlab binds reliably.
							fp := strings.TrimSpace(m.FilePath)
							if !strings.HasPrefix(fp, "/") {
								fp = strings.TrimPrefix(fp, "./")
								if strings.HasPrefix(fp, "node_files/") || strings.HasPrefix(fp, "config/") {
									fp = path.Join(mountRoot, fp)
								}
							}
							filePathForMountDir[fp] = path.Join(fp, strings.TrimSpace(m.ConfigMapPath))
						}
					}
				}

				// Rewrite startup-config if present.
				if sc, ok := cfg["startup-config"].(string); ok {
					sc = strings.TrimSpace(sc)
					if strings.HasPrefix(sc, "config/") || strings.HasPrefix(sc, "node_files/") {
						cfg["startup-config"] = path.Join(mountRoot, sc)
					}
				}

				bindsAny, ok := cfg["binds"]
				if !ok {
					// Even if no binds, we might have updated nodeMounts with startup-config
					nodes[node] = cfg
					continue
				}
				rawBinds, ok := bindsAny.([]any)
				if !ok || len(rawBinds) == 0 {
					nodes[node] = cfg
					continue
				}
				out := make([]any, 0, len(rawBinds))
				for _, bindAny := range rawBinds {
					bind := strings.TrimSpace(fmt.Sprintf("%v", bindAny))
					if bind == "" {
						continue
					}
					parts := strings.SplitN(bind, ":", 2)
					if len(parts) != 2 {
						out = append(out, bind)
						continue
					}
					hostPath := strings.TrimSpace(parts[0])
					rest := parts[1]

					// Kubernetes container runtimes mount volumes with recursive bind flags
					// (`MS_BIND|MS_REC`). When attempting to mount a single file onto `/etc/hosts`,
					// some runtimes treat this as an invalid recursive bind (ENOTDIR). The
					// /etc/hosts bind is nice-to-have for name resolution but not required for the
					// topology to boot, so drop it for linux containers.
					if kind == "linux" && strings.HasPrefix(strings.TrimSpace(rest), "/etc/hosts") {
						if e != nil {
							e.appendTaskWarning(taskID, fmt.Sprintf("c9s: skipped /etc/hosts bind for linux node %s (not supported by runtime)", nodeName))
						}
						continue
					}

					hostPath = strings.TrimPrefix(hostPath, "./")
					if strings.HasPrefix(hostPath, "node_files/") {
						newHost := path.Join(mountRoot, hostPath)
						// If the bind target is /etc/hosts or /etc/network/interfaces, netlab expects
						// the source to be a file, but filesFromConfigMap materializes it under a
						// directory named by the bind source. Rewrite to the materialized file
						// path when possible.
						if strings.HasPrefix(rest, "/etc/hosts") || strings.HasPrefix(rest, "/etc/network/interfaces") {
							if fp, ok := filePathForMountDir[newHost]; ok && fp != "" {
								newHost = fp
							}
						}
						out = append(out, newHost+":"+rest)
						continue
					}
					if strings.HasPrefix(hostPath, "config/") {
						newHost := path.Join(mountRoot, hostPath)
						out = append(out, newHost+":"+rest)
						continue
					}
					if !strings.HasPrefix(hostPath, "/") && hostPath != "" {
						if e != nil {
							e.appendTaskWarning(taskID, fmt.Sprintf("c9s: bind path %q for node %s is relative and not under node_files or config", hostPath, nodeName))
						}
					}
					out = append(out, bind)
				}
				cfg["binds"] = out
				nodes[node] = cfg
			}
			topology["nodes"] = nodes
		}
		topo["topology"] = topology
	}

	topologyBytes, err := yaml.Marshal(topo)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode clab.yml: %w", err)
	}
	return topologyBytes, nodeMounts, reverseMapping, nil
}

func ensureNetlabC9sEOSStartupSSH(ctx context.Context, ns, topologyName string, clabYAML []byte, nodeMounts map[string][]c9sFileFromConfigMap, log Logger) (map[string][]c9sFileFromConfigMap, error) {
	if log == nil {
		log = noopLogger{}
	}
	ns = strings.TrimSpace(ns)
	topologyName = strings.TrimSpace(topologyName)
	if ns == "" || topologyName == "" || len(clabYAML) == 0 || nodeMounts == nil {
		return nodeMounts, nil
	}

	var topo map[string]any
	if err := yaml.Unmarshal(clabYAML, &topo); err != nil {
		return nil, fmt.Errorf("failed to parse clab.yml: %w", err)
	}
	topology, ok := topo["topology"].(map[string]any)
	if !ok {
		return nodeMounts, nil
	}
	nodes, ok := topology["nodes"].(map[string]any)
	if !ok || len(nodes) == 0 {
		return nodeMounts, nil
	}

	mountRoot := path.Join("/tmp/skyforge-c9s", topologyName)
	overrideCM := sanitizeKubeNameFallback(fmt.Sprintf("c9s-%s-startup-overrides", topologyName), "c9s-startup-overrides")
	overrideData := map[string]string{}
	labels := map[string]string{
		"skyforge-c9s-topology": topologyName,
	}

	changedAny := false
	for node, nodeAny := range nodes {
		nodeName := strings.TrimSpace(fmt.Sprintf("%v", node))
		cfg, ok := nodeAny.(map[string]any)
		if !ok || cfg == nil || nodeName == "" {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", cfg["kind"])))
		if kind != "ceos" && kind != "eos" {
			continue
		}
		sc, _ := cfg["startup-config"].(string)
		sc = strings.TrimSpace(sc)
		if !strings.HasPrefix(sc, "config/") {
			continue
		}

		startupPath := path.Join(mountRoot, sc)
		mounts := nodeMounts[nodeName]
		if len(mounts) == 0 {
			continue
		}

		var originalCM, originalKey string
		for _, m := range mounts {
			if strings.TrimSpace(m.FilePath) == startupPath && strings.TrimSpace(m.ConfigMapName) != "" && strings.TrimSpace(m.ConfigMapPath) != "" {
				originalCM = strings.TrimSpace(m.ConfigMapName)
				originalKey = strings.TrimSpace(m.ConfigMapPath)
				break
			}
		}
		if originalCM == "" || originalKey == "" {
			log.Infof("c9s: eos startup-config mount not found for %s (%s)", nodeName, sc)
			continue
		}

		cmData, ok, err := kubeGetConfigMap(ctx, ns, originalCM)
		if err != nil {
			return nil, err
		}
		if !ok {
			log.Infof("c9s: eos startup-config configmap missing: %s", originalCM)
			continue
		}
		contents, ok := cmData[originalKey]
		if !ok {
			log.Infof("c9s: eos startup-config key missing: %s/%s", originalCM, originalKey)
			continue
		}

		out, changed := injectEOSManagementSSH(contents)
		if !changed {
			continue
		}

		overrideKey := sanitizeArtifactKeySegment(fmt.Sprintf("%s-%s", nodeName, path.Base(sc)))
		if overrideKey == "" || overrideKey == "unknown" {
			overrideKey = sanitizeArtifactKeySegment(fmt.Sprintf("%s-startup", nodeName))
		}
		overrideData[overrideKey] = out

		for i := range mounts {
			if strings.TrimSpace(mounts[i].FilePath) == startupPath && strings.TrimSpace(mounts[i].ConfigMapName) == originalCM && strings.TrimSpace(mounts[i].ConfigMapPath) == originalKey {
				mounts[i].ConfigMapName = overrideCM
				mounts[i].ConfigMapPath = overrideKey
				changedAny = true
				break
			}
		}
		nodeMounts[nodeName] = mounts
	}

	if len(overrideData) == 0 || !changedAny {
		return nodeMounts, nil
	}
	if err := kubeUpsertConfigMap(ctx, ns, overrideCM, overrideData, labels); err != nil {
		return nil, err
	}
	log.Infof("c9s: injected management ssh into eos startup-config (%d file(s))", len(overrideData))
	return nodeMounts, nil
}

func injectEOSManagementSSH(cfg string) (out string, changed bool) {
	cfg = strings.ReplaceAll(cfg, "\r\n", "\n")
	lower := strings.ToLower(cfg)
	if strings.Contains(lower, "management ssh") {
		return cfg, false
	}

	lines := strings.Split(cfg, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(strings.ToLower(lines[i])) == "end" {
			outLines := make([]string, 0, len(lines)+1)
			outLines = append(outLines, lines[:i]...)
			outLines = append(outLines, "management ssh")
			outLines = append(outLines, lines[i:]...)
			out = strings.Join(outLines, "\n")
			if !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
			return out, true
		}
	}
	if !strings.HasSuffix(cfg, "\n") {
		cfg += "\n"
	}
	return cfg + "management ssh\n", true
}

func injectEOSDefaultSSHUser(cfg string) (out string, changed bool) {
	cfg = strings.ReplaceAll(cfg, "\r\n", "\n")
	lower := strings.ToLower(cfg)
	needUser := !(strings.Contains(lower, "\nusername ") || strings.HasPrefix(strings.TrimSpace(lower), "username "))
	needEnableSecret := !strings.Contains(lower, "\nenable secret")
	needAAALogin := !strings.Contains(lower, "\naaa authentication login")
	needAAAExec := !strings.Contains(lower, "\naaa authorization exec")

	if !needUser && !needEnableSecret && !needAAALogin && !needAAAExec {
		return cfg, false
	}

	linesToInsert := make([]string, 0, 4)
	// Default, predictable access for in-cluster labs. If a template supplies any of
	// these, we leave it alone.
	if needUser {
		linesToInsert = append(linesToInsert, "username admin privilege 15 secret admin")
	}
	if needEnableSecret {
		linesToInsert = append(linesToInsert, "enable secret admin")
	}
	if needAAALogin {
		linesToInsert = append(linesToInsert, "aaa authentication login default local")
	}
	if needAAAExec {
		linesToInsert = append(linesToInsert, "aaa authorization exec default local")
	}
	if len(linesToInsert) == 0 {
		return cfg, false
	}

	lines := strings.Split(cfg, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(strings.ToLower(lines[i])) == "end" {
			outLines := make([]string, 0, len(lines)+len(linesToInsert))
			outLines = append(outLines, lines[:i]...)
			outLines = append(outLines, linesToInsert...)
			outLines = append(outLines, lines[i:]...)
			out = strings.Join(outLines, "\n")
			if !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
			return out, true
		}
	}

	if !strings.HasSuffix(cfg, "\n") {
		cfg += "\n"
	}
	return cfg + strings.Join(linesToInsert, "\n") + "\n", true
}
