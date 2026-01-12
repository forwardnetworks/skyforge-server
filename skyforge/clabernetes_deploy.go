package skyforge

import (
	"context"
	"fmt"
	"log"
	"path"
	"strings"
	"time"

	"encore.dev/beta/errs"
	"gopkg.in/yaml.v3"
)

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

func (s *Service) runClabernetesDeploymentAction(
	ctx context.Context,
	pc *workspaceContext,
	dep *WorkspaceDeployment,
	envJSON JSONMap,
	action string,
	templateSource string,
	templateRepo string,
	templatesDir string,
	template string,
	labName string,
	k8sNamespace string,
) (*WorkspaceRunResponse, error) {
	if pc == nil || dep == nil {
		return nil, errs.B().Code(errs.InvalidArgument).Msg("deployment context unavailable").Err()
	}
	if s.db == nil {
		return nil, errs.B().Code(errs.Unavailable).Msg("database unavailable").Err()
	}

	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "", "deploy", "create", "start", "up":
		action = "deploy"
	case "destroy", "delete", "down", "stop":
		action = "destroy"
	default:
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid clabernetes action (use deploy or destroy)").Err()
	}

	labName = strings.TrimSpace(labName)
	if labName == "" {
		labName = containerlabLabName(pc.workspace.Slug, dep.Name)
	}
	k8sNamespace = strings.TrimSpace(k8sNamespace)
	if k8sNamespace == "" {
		k8sNamespace = clabernetesWorkspaceNamespace(pc.workspace.Slug)
	}
	topologyName := clabernetesTopologyName(labName)

	topologyYAML := ""
	if action == "deploy" {
		template = strings.TrimSpace(template)
		if template == "" {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg("clabernetes template is required").Err()
		}
		templatesDir = strings.Trim(strings.TrimSpace(templatesDir), "/")
		if templatesDir == "" {
			templatesDir = "blueprints/containerlab"
		}
		if !isSafeRelativePath(templatesDir) {
			return nil, errs.B().Code(errs.InvalidArgument).Msg("templatesDir must be a safe repo-relative path").Err()
		}
		ref, err := resolveTemplateRepoForProject(s.cfg, pc, templateSource, templateRepo)
		if err != nil {
			return nil, errs.B().Code(errs.InvalidArgument).Msg(err.Error()).Err()
		}
		filePath := path.Join(templatesDir, template)
		body, err := readGiteaFileBytes(s.cfg, ref.Owner, ref.Repo, filePath, ref.Branch)
		if err != nil {
			log.Printf("clabernetes template read: %v", err)
			return nil, errs.B().Code(errs.Unavailable).Msg("failed to read clabernetes template").Err()
		}
		var topo map[string]any
		if err := yaml.Unmarshal(body, &topo); err != nil {
			log.Printf("clabernetes template parse: %v", err)
			return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid containerlab topology").Err()
		}
		if topo == nil {
			topo = map[string]any{}
		}
		topo["name"] = labName
		topologyBytes, err := yaml.Marshal(topo)
		if err != nil {
			log.Printf("clabernetes template encode: %v", err)
			return nil, errs.B().Code(errs.Internal).Msg("failed to encode topology").Err()
		}
		topologyYAML = string(topologyBytes)
	}

	message := strings.TrimSpace(fmt.Sprintf("Skyforge clabernetes run (%s)", pc.claims.Username))
	{
		auditCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		defer cancel()
		actor, actorIsAdmin, impersonated := auditActor(s.cfg, pc.claims)
		writeAuditEvent(
			auditCtx,
			s.db,
			actor,
			actorIsAdmin,
			impersonated,
			"workspace.run.clabernetes",
			pc.workspace.ID,
			fmt.Sprintf("action=%s namespace=%s topology=%s", action, k8sNamespace, topologyName),
		)
	}

	meta, err := toJSONMap(map[string]any{
		"action":       action,
		"deployment":   dep.Name,
		"deploymentID": dep.ID,
		"template":     template,
		"labName":      labName,
		"namespace":    k8sNamespace,
		"topologyName": topologyName,
	})
	if err != nil {
		log.Printf("clabernetes meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}

	allowActive := action == "destroy"
	var task *TaskRecord
	if allowActive {
		task, err = createTaskAllowActive(ctx, s.db, pc.workspace.ID, &dep.ID, "clabernetes-run", message, pc.claims.Username, meta)
	} else {
		task, err = createTask(ctx, s.db, pc.workspace.ID, &dep.ID, "clabernetes-run", message, pc.claims.Username, meta)
	}
	if err != nil {
		return nil, err
	}

	envAny, _ := fromJSONMap(envJSON)
	envMap := parseEnvMap(envAny)

	spec := clabernetesRunSpec{
		TaskID:      task.ID,
		Action:      action,
		Namespace:   k8sNamespace,
		TopologyName: topologyName,
		LabName:     labName,
		Template:    template,
		TopologyYAML: topologyYAML,
		Environment: envMap,
	}
	s.queueTask(task, func(ctx context.Context, log *taskLogger) error {
		return s.runClabernetesTask(ctx, spec, log)
	})

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("clabernetes task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &WorkspaceRunResponse{
		WorkspaceID: pc.workspace.ID,
		Task:        taskJSON,
		User:        pc.claims.Username,
	}, nil
}
