package skyforge

import (
	"context"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"log"
	"strings"
	"time"

	"crypto/rand"

	"encore.dev/beta/errs"
)

func netlabMultilabNumericID(multilabID string) int {
	multilabID = strings.TrimSpace(multilabID)
	if multilabID == "" {
		return 1
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(multilabID))
	// Range 1..199 (multilab rejects 0 and values >= 200).
	return int(h.Sum32()%199) + 1
}

func (s *Service) runNetlabC9sDeploymentAction(
	ctx context.Context,
	pc *workspaceContext,
	dep *WorkspaceDeployment,
	envJSON JSONMap,
	action string,
	netlabServer string,
	templateSource string,
	templateRepo string,
	templatesDir string,
	template string,
	labName string,
	k8sNamespace string,
	setOverrides []string,
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
		return nil, errs.B().Code(errs.InvalidArgument).Msg("invalid netlab c9s action (use deploy or destroy)").Err()
	}

	serverName := "k8s"
	mode := strings.ToLower(strings.TrimSpace(s.cfg.NetlabC9sGeneratorMode))
	if mode == "" {
		mode = "k8s"
	}
	// Skyforge is moving away from BYOS netlab runners for netlab-c9s; treat "remote" as legacy
	// and default to the in-cluster generator.
	if mode == "remote" {
		mode = "k8s"
	}
	if mode == "remote" {
		netlabServer = strings.TrimSpace(netlabServer)
		if netlabServer == "" {
			netlabServer = strings.TrimSpace(pc.workspace.NetlabServer)
		}
		server, err := s.resolveWorkspaceNetlabServerConfig(ctx, pc.workspace.ID, netlabServer)
		if err != nil {
			return nil, errs.B().Code(errs.FailedPrecondition).Msg(err.Error()).Err()
		}
		serverName = server.Name
	} else {
		// Cluster-native generator mode: do not require BYOS netlab servers.
		if strings.TrimSpace(netlabServer) != "" {
			serverName = strings.TrimSpace(netlabServer)
		}
	}

	template = strings.TrimSpace(template)
	if template == "" && action != "destroy" {
		return nil, errs.B().Code(errs.FailedPrecondition).Msg("netlab template is required").Err()
	}

	templateSource = strings.TrimSpace(templateSource)
	if templateSource == "" {
		templateSource = "blueprints"
	}

	multilabID := strings.TrimSpace(dep.ID)
	if multilabID == "" {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err == nil {
			multilabID = hex.EncodeToString(buf)
		} else {
			multilabID = fmt.Sprintf("%d", time.Now().UnixNano())
		}
	}
	multilabNumeric := netlabMultilabNumericID(multilabID)

	deploymentName := strings.TrimSpace(dep.Name)
	if deploymentName == "" {
		deploymentName = multilabID
	}
	workspaceRoot := fmt.Sprintf("/home/%s/netlab", strings.TrimSpace(pc.claims.Username))
	workspaceDir := fmt.Sprintf("%s/%s/%s", workspaceRoot, strings.TrimSpace(pc.workspace.Slug), deploymentName)
	clabTarball := fmt.Sprintf("containerlab-%s.tar.gz", deploymentName)

	labName = strings.TrimSpace(labName)
	if labName == "" {
		labName = containerlabLabName(pc.workspace.Slug, deploymentName)
	}
	k8sNamespace = strings.TrimSpace(k8sNamespace)
	if k8sNamespace == "" {
		k8sNamespace = clabernetesWorkspaceNamespace(pc.workspace.Slug)
	}
	topologyName := clabernetesTopologyName(labName)

	envAny, _ := fromJSONMap(envJSON)
	envMap := parseEnvMap(envAny)
	filteredOverrides := []string{}
	for _, raw := range setOverrides {
		if v := strings.TrimSpace(raw); v != "" {
			filteredOverrides = append(filteredOverrides, v)
		}
	}
	message := strings.TrimSpace(fmt.Sprintf("Skyforge netlab c9s run (%s)", pc.claims.Username))
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
			"workspace.run.netlab.c9s",
			pc.workspace.ID,
			fmt.Sprintf("action=%s server=%s namespace=%s topology=%s", action, serverName, k8sNamespace, topologyName),
		)
	}

	meta, err := toJSONMap(map[string]any{
		"action":       action,
		"server":       serverName,
		"deployment":   dep.Name,
		"deploymentID": dep.ID,
		"namespace":    k8sNamespace,
		"topologyName": topologyName,
		"labName":      labName,
		"dedupeKey":    fmt.Sprintf("netlab-c9s:%s:%s:%s", pc.workspace.ID, action, dep.ID),
		"spec": netlabC9sTaskSpec{
			Action:          action,
			Server:          serverName,
			Deployment:      deploymentName,
			DeploymentID:    dep.ID,
			WorkspaceRoot:   workspaceRoot,
			TemplateSource:  templateSource,
			TemplateRepo:    strings.TrimSpace(templateRepo),
			TemplatesDir:    strings.TrimSpace(templatesDir),
			Template:        template,
			WorkspaceDir:    workspaceDir,
			MultilabNumeric: multilabNumeric,
			TopologyPath:    "",
			ClabTarball:     clabTarball,
			K8sNamespace:    k8sNamespace,
			LabName:         labName,
			TopologyName:    topologyName,
			Environment:     envMap,
			SetOverrides:    filteredOverrides,
		},
	})
	if err != nil {
		log.Printf("netlab c9s meta encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode metadata").Err()
	}

	allowActive := action == "destroy"
	var task *TaskRecord
	if allowActive {
		task, err = createTaskAllowActive(ctx, s.db, pc.workspace.ID, &dep.ID, "netlab-c9s-run", message, pc.claims.Username, meta)
	} else {
		task, err = createTask(ctx, s.db, pc.workspace.ID, &dep.ID, "netlab-c9s-run", message, pc.claims.Username, meta)
	}
	if err != nil {
		return nil, err
	}

	s.queueTask(task)

	taskJSON, err := toJSONMap(taskToRunInfo(*task))
	if err != nil {
		log.Printf("netlab c9s task encode: %v", err)
		return nil, errs.B().Code(errs.Internal).Msg("failed to encode run").Err()
	}
	return &WorkspaceRunResponse{
		WorkspaceID: pc.workspace.ID,
		Task:        taskJSON,
		User:        pc.claims.Username,
	}, nil
}
